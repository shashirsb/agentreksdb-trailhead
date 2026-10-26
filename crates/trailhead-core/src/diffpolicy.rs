//! Diff-policy gate (stage 7): the only layer aimed at malice. It reads every byte of the
//! generated diff (build scripts, CI, lockfiles, binary fixtures, not just `src/`) and hard-stops
//! to a human on anything outside the intent's lane: new egress, secret reads, dependencies,
//! crypto/auth paths, `unsafe`, encoded blobs, Trojan-Source characters.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// The manifest the gate workflow builds from `git diff base..head`.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Manifest {
    pub base: String,
    pub head: String,
    pub files: Vec<FileChange>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct FileChange {
    pub path: String,
    /// added | modified | deleted | renamed
    pub status: String,
    pub binary: bool,
    pub added_lines: Vec<String>,
    /// Lines the diff removes. Sabotage by deletion — dropping an `fsync`, an authorization
    /// check or a quorum guard — adds nothing, so a gate that only reads `added_lines` is
    /// blind to the most realistic attack. Defaults empty so older manifests still parse.
    pub removed_lines: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Block,
    Warn,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// pattern matches the changed file's path
    Path,
    /// pattern matches any added line
    AddedLine,
    /// pattern matches any removed line (sabotage by deletion)
    RemovedLine,
    /// pattern matches a removed line AND no surviving added line in the same file matches it:
    /// the guard was taken out rather than moved or reworded. This is the low-noise form of
    /// [`Kind::RemovedLine`] and the one most rules should use.
    DroppedGuard,
    /// pattern matches the path of a changed lockfile (e.g. `Cargo\.lock$`)
    Lockfile,
    /// file is binary and its path matches pattern
    Binary,
    /// the whole file was deleted and its path matches pattern. A diff that removes an entire
    /// file carries no removed lines in the manifest, so `removed_line` and `dropped_guard`
    /// are blind to it: deleting `wal.rs` wholesale would otherwise be quieter than deleting
    /// one line inside it.
    DeletedFile,
}

#[derive(Deserialize)]
struct RuleDef {
    id: String,
    level: Level,
    kind: Kind,
    pattern: String,
    #[serde(default)]
    exempt_paths: Vec<String>,
    /// Whether `exempt_paths` also excuses files this diff *creates*. Default false, because
    /// an exemption like `(^|/)net/` is otherwise an instruction for how to bypass the rule:
    /// the generated diff simply adds `engine/src/net/backdoor.rs`. An exemption is meant to
    /// spare code that a human already reviewed, so by default it applies only to files that
    /// existed in the base commit.
    #[serde(default)]
    exempt_applies_to_new_files: bool,
    message: String,
}

#[derive(Deserialize)]
struct PolicyFile {
    rule: Vec<RuleDef>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub level: Level,
    pub kind: Kind,
    pub pattern: Regex,
    pub exempt: Vec<Regex>,
    pub exempt_applies_to_new_files: bool,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub rules: Vec<Rule>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    pub rule: String,
    pub path: String,
    pub line: Option<String>,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    Warn,
    Block,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Verdict {
    pub verdict: Outcome,
    pub base: String,
    pub head: String,
    pub rules_evaluated: usize,
    pub blocked_by: Vec<Finding>,
    pub warned: Vec<Finding>,
}

impl Policy {
    pub fn parse(src: &str) -> anyhow::Result<Policy> {
        let file: PolicyFile = toml::from_str(src)?;
        let mut rules = Vec::new();
        for r in file.rule {
            let pattern = RegexBuilder::new(&r.pattern)
                .build()
                .map_err(|e| anyhow::anyhow!("rule {}: bad pattern: {e}", r.id))?;
            let exempt = r
                .exempt_paths
                .iter()
                .map(|p| {
                    Regex::new(p)
                        .map_err(|e| anyhow::anyhow!("rule {}: bad exempt path: {e}", r.id))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            rules.push(Rule {
                id: r.id,
                level: r.level,
                kind: r.kind,
                pattern,
                exempt,
                exempt_applies_to_new_files: r.exempt_applies_to_new_files,
                message: r.message,
            });
        }
        Ok(Policy { rules })
    }

    pub fn check(&self, m: &Manifest) -> Verdict {
        let mut blocked_by = Vec::new();
        let mut warned = Vec::new();
        for rule in &self.rules {
            for f in &m.files {
                // A file this diff creates cannot rely on a path exemption unless the rule
                // opts in, otherwise the exemption list doubles as a bypass recipe.
                let newly_added = f.status == "added";
                let exempt_here = (rule.exempt_applies_to_new_files || !newly_added)
                    && rule.exempt.iter().any(|e| e.is_match(&f.path));
                if exempt_here {
                    continue;
                }
                let found: Option<Option<String>> = match rule.kind {
                    Kind::Path | Kind::Lockfile => rule.pattern.is_match(&f.path).then_some(None),
                    Kind::Binary => (f.binary && rule.pattern.is_match(&f.path)).then_some(None),
                    Kind::DeletedFile => {
                        (f.status == "deleted" && rule.pattern.is_match(&f.path)).then_some(None)
                    }
                    Kind::AddedLine => f
                        .added_lines
                        .iter()
                        .find(|l| rule.pattern.is_match(l))
                        .map(|l| Some(truncate(l, 160))),
                    Kind::RemovedLine => f
                        .removed_lines
                        .iter()
                        .find(|l| rule.pattern.is_match(l))
                        .map(|l| Some(truncate(l, 160))),
                    // Removed somewhere and not re-added anywhere in the same file: the guard
                    // is gone, not merely moved or reformatted.
                    Kind::DroppedGuard => {
                        let still_present = f.added_lines.iter().any(|l| rule.pattern.is_match(l));
                        if still_present {
                            None
                        } else {
                            f.removed_lines
                                .iter()
                                .find(|l| rule.pattern.is_match(l))
                                .map(|l| Some(truncate(l, 160)))
                        }
                    }
                };
                if let Some(line) = found {
                    let finding = Finding {
                        rule: rule.id.clone(),
                        path: f.path.clone(),
                        line,
                        message: rule.message.clone(),
                    };
                    match rule.level {
                        Level::Block => blocked_by.push(finding),
                        Level::Warn => warned.push(finding),
                    }
                }
            }
        }
        let verdict = if !blocked_by.is_empty() {
            Outcome::Block
        } else if !warned.is_empty() {
            Outcome::Warn
        } else {
            Outcome::Pass
        };
        Verdict {
            verdict,
            base: m.base.clone(),
            head: m.head.clone(),
            rules_evaluated: self.rules.len(),
            blocked_by,
            warned,
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
[[rule]]
id = "deps.lockfile"
level = "block"
kind = "lockfile"
pattern = 'Cargo\.lock$'
message = "dependency change"

[[rule]]
id = "net.egress"
level = "block"
kind = "added_line"
pattern = '(TcpStream|UdpSocket|reqwest::|hyper::Client)'
exempt_paths = ['(^|/)net/']
message = "new egress outside net/"

[[rule]]
id = "unicode.bidi"
level = "block"
kind = "added_line"
pattern = '[\x{202A}-\x{202E}\x{2066}-\x{2069}]'
message = "Trojan Source"

[[rule]]
id = "blob"
level = "block"
kind = "binary"
pattern = '.*'
message = "binary file"

[[rule]]
id = "unwrap"
level = "warn"
kind = "added_line"
pattern = '\.unwrap\(\)'
message = "unwrap in server path"
"#;

    fn file(path: &str, lines: &[&str]) -> FileChange {
        FileChange {
            path: path.into(),
            status: "modified".into(),
            binary: false,
            added_lines: lines.iter().map(|s| s.to_string()).collect(),
            removed_lines: Vec::new(),
        }
    }

    fn removing(path: &str, added: &[&str], removed: &[&str]) -> FileChange {
        FileChange {
            path: path.into(),
            status: "modified".into(),
            binary: false,
            added_lines: added.iter().map(|s| s.to_string()).collect(),
            removed_lines: removed.iter().map(|s| s.to_string()).collect(),
        }
    }

    const DELETION_POLICY: &str = r#"
[[rule]]
id = "dropped-durability"
level = "block"
kind = "dropped_guard"
pattern = '\b(sync_all|fsync)\b'
message = "durability barrier deleted"

[[rule]]
id = "removed-forbid"
level = "block"
kind = "removed_line"
pattern = 'forbid\(unsafe_code\)'
message = "unsafe ban removed"
"#;

    #[test]
    fn deleting_a_whole_source_file_blocks() {
        let p = Policy::parse(
            r#"
[[rule]]
id = "source-file-deleted"
level = "block"
kind = "deleted_file"
pattern = '\.rs$'
message = "a source file was deleted"
"#,
        )
        .unwrap();
        let mut gone = file("engine/src/wal.rs", &[]);
        gone.status = "deleted".into();
        let v = p.check(&Manifest {
            files: vec![gone],
            ..Default::default()
        });
        assert_eq!(v.verdict, Outcome::Block);
        // A merely modified file does not trip it.
        let v2 = p.check(&Manifest {
            files: vec![file("engine/src/wal.rs", &["let x = 1;"])],
            ..Default::default()
        });
        assert_eq!(v2.verdict, Outcome::Pass);
    }

    #[test]
    fn deleting_an_fsync_blocks() {
        let p = Policy::parse(DELETION_POLICY).unwrap();
        let v = p.check(&Manifest {
            files: vec![removing(
                "engine/src/wal.rs",
                &["self.file.write_all(&buf)?;"],
                &["self.file.write_all(&buf)?;", "self.file.sync_all()?;"],
            )],
            ..Default::default()
        });
        assert_eq!(v.verdict, Outcome::Block);
        assert_eq!(v.blocked_by[0].rule, "dropped-durability");
    }

    #[test]
    fn moving_a_guard_is_quiet_but_deleting_it_is_not() {
        let p = Policy::parse(DELETION_POLICY).unwrap();
        // Reindented and moved, but still present: no finding.
        let moved = p.check(&Manifest {
            files: vec![removing(
                "engine/src/wal.rs",
                &["        self.file.sync_all()?;"],
                &["    self.file.sync_all()?;"],
            )],
            ..Default::default()
        });
        assert_eq!(moved.verdict, Outcome::Pass, "{:?}", moved.blocked_by);

        let deleted = p.check(&Manifest {
            files: vec![removing(
                "engine/src/wal.rs",
                &[],
                &["self.file.sync_all()?;"],
            )],
            ..Default::default()
        });
        assert_eq!(deleted.verdict, Outcome::Block);
    }

    #[test]
    fn removed_line_rule_fires_even_when_re_added() {
        // `removed_line` is the blunt form: it does not care whether the text came back.
        let p = Policy::parse(DELETION_POLICY).unwrap();
        let v = p.check(&Manifest {
            files: vec![removing(
                "core/src/lib.rs",
                &["#![forbid(unsafe_code)]"],
                &["#![forbid(unsafe_code)]"],
            )],
            ..Default::default()
        });
        assert_eq!(v.verdict, Outcome::Block);
        assert_eq!(v.blocked_by[0].rule, "removed-forbid");
    }

    #[test]
    fn an_exempt_path_cannot_be_manufactured_by_the_diff() {
        let p = Policy::parse(POLICY).unwrap();
        // `net.egress` exempts `(^|/)net/`. A diff that CREATES such a file must not get the
        // exemption, or the exemption list is just a bypass recipe.
        let mut created = file(
            "engine/src/net/helper.rs",
            &["let s = TcpStream::connect(a)?;"],
        );
        created.status = "added".into();
        let v = p.check(&Manifest {
            files: vec![created],
            ..Default::default()
        });
        assert_eq!(v.verdict, Outcome::Block, "new file claimed an exemption");

        // A file that already existed in the base keeps its exemption.
        let v2 = p.check(&Manifest {
            files: vec![file(
                "engine/src/net/helper.rs",
                &["let s = TcpStream::connect(a)?;"],
            )],
            ..Default::default()
        });
        assert_eq!(v2.verdict, Outcome::Pass);
    }

    #[test]
    fn shipped_policy_covers_deletion_sabotage() {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../gates/diff-policy.toml"
        ))
        .expect("shipped policy");
        let p = Policy::parse(&src).unwrap();
        assert!(
            p.rules
                .iter()
                .any(|r| matches!(r.kind, Kind::DroppedGuard | Kind::RemovedLine)),
            "the shipped policy must read removed lines"
        );
        // The real policy must block a real deletion attack.
        let v = p.check(&Manifest {
            files: vec![removing(
                "server/src/handler.rs",
                &["    let user = session.user();"],
                &[
                    "    let user = session.user();",
                    "    authorize(&user, Action::Write)?;",
                ],
            )],
            ..Default::default()
        });
        assert_eq!(v.verdict, Outcome::Block, "{v:?}");
    }

    #[test]
    fn clean_diff_passes() {
        let p = Policy::parse(POLICY).unwrap();
        let v = p.check(&Manifest {
            files: vec![file("engine/src/scan.rs", &["let x = 1;"])],
            ..Default::default()
        });
        assert_eq!(v.verdict, Outcome::Pass);
    }

    #[test]
    fn egress_outside_net_blocks_but_net_is_exempt() {
        let p = Policy::parse(POLICY).unwrap();
        let bad = p.check(&Manifest {
            files: vec![file(
                "engine/src/health.rs",
                &["let s = TcpStream::connect(addr)?;"],
            )],
            ..Default::default()
        });
        assert_eq!(bad.verdict, Outcome::Block);
        assert_eq!(bad.blocked_by[0].rule, "net.egress");
        let ok = p.check(&Manifest {
            files: vec![file(
                "server/src/net/peer.rs",
                &["let s = TcpStream::connect(addr)?;"],
            )],
            ..Default::default()
        });
        assert_eq!(ok.verdict, Outcome::Pass);
    }

    #[test]
    fn lockfile_binary_and_bidi_block() {
        let p = Policy::parse(POLICY).unwrap();
        let mut bin = file("tests/fixtures/data.xz", &[]);
        bin.binary = true;
        let v = p.check(&Manifest {
            files: vec![
                file("Cargo.lock", &[]),
                bin,
                file("src/a.rs", &["let admin = \"user\u{202E}\";"]),
            ],
            ..Default::default()
        });
        let rules: Vec<_> = v.blocked_by.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.contains(&"deps.lockfile"));
        assert!(rules.contains(&"blob"));
        assert!(rules.contains(&"unicode.bidi"));
    }

    #[test]
    fn warn_only() {
        let p = Policy::parse(POLICY).unwrap();
        let v = p.check(&Manifest {
            files: vec![file("src/a.rs", &["x.unwrap()"])],
            ..Default::default()
        });
        assert_eq!(v.verdict, Outcome::Warn);
    }
}

#[cfg(test)]
mod shipped_policy {
    #[test]
    fn gates_diff_policy_toml_parses() {
        let src = include_str!("../../../gates/diff-policy.toml");
        let p = super::Policy::parse(src).expect("gates/diff-policy.toml must parse");
        assert!(p.rules.len() >= 20);
    }
}
