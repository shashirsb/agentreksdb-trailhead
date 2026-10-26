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
    /// pattern matches the path of a changed lockfile (e.g. `Cargo\.lock$`)
    Lockfile,
    /// file is binary and its path matches pattern
    Binary,
}

#[derive(Deserialize)]
struct RuleDef {
    id: String,
    level: Level,
    kind: Kind,
    pattern: String,
    #[serde(default)]
    exempt_paths: Vec<String>,
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
                if rule.exempt.iter().any(|e| e.is_match(&f.path)) {
                    continue;
                }
                let found: Option<Option<String>> = match rule.kind {
                    Kind::Path | Kind::Lockfile => rule.pattern.is_match(&f.path).then_some(None),
                    Kind::Binary => (f.binary && rule.pattern.is_match(&f.path)).then_some(None),
                    Kind::AddedLine => f
                        .added_lines
                        .iter()
                        .find(|l| rule.pattern.is_match(l))
                        .map(|l| Some(truncate(l, 160))),
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
        }
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
