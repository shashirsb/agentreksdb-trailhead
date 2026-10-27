//! Spec conformance: does the diff do only what the spec asked for?
//!
//! Every other gate asks whether the code is *bad*. This one asks whether it is *asked for*,
//! which is a different and often easier question. A backdoor has to live somewhere, and the
//! spec that justified the work almost never mentions that place. The xz-utils payload sat in
//! test fixtures and a build macro; the Linux "hypocrite commits" fixed a real bug in one hunk
//! and weakened something in another. In both cases the malicious hunk was *off-topic* for the
//! change it travelled with, and off-topic is something a machine can check without
//! understanding the code at all.
//!
//! That check is only possible here because contributors never write code. The spec is agreed
//! before a single token is generated, so by the time there is a diff the project already has a
//! written, public statement of what the change was allowed to touch. The model is told to
//! declare which requirement each hunk serves. This module compares the two.
//!
//! Four findings block:
//!
//! 1. **Out of scope** — a file outside every declared area. The spec said "engine"; the diff
//!    edits the auth module.
//! 2. **Forbidden area** — a file whose area the spec explicitly listed as out of scope. Worse
//!    than merely undeclared, because the spec already considered and rejected it.
//! 3. **Undeclared API change** — a public signature moved while `api_or_data_changes` was
//!    empty. The one change class every consumer feels, slipped in unannounced.
//! 4. **Untraced hunk** — a changed file no requirement claims. If nothing asked for it, the
//!    question "why is this here?" has no answer on the record.
//!
//! Two more are advisory, because both have honest explanations often enough that blocking
//! would train governors to wave findings through:
//!
//! - **Unexplained literal branch** — a new comparison against a hard-coded value the spec
//!   never mentions. This is the shape of a magic-value backdoor, and also the shape of an
//!   ordinary bounds check.
//! - **Scope creep** — the diff touches far more areas than the spec declared.
//!
//! The area map is deliberately coarse and lives in the spec's own vocabulary, so a governor
//! reading a finding sees the same words the contributor agreed to.

use crate::diffpolicy::Manifest;
use crate::spec::Spec;
use serde::{Deserialize, Serialize};

/// Why a file counts as belonging to an area. Paths are matched by segment, never by substring,
/// so `engine/` matches `src/engine/x.rs` but a file called `my_engine_notes.rs` does not: a
/// generated patch that only has to *contain* a blessed word could otherwise name itself into
/// any area it liked.
#[derive(Clone, Debug)]
struct AreaRule {
    area: &'static str,
    /// Path segments that put a file in this area.
    segments: &'static [&'static str],
}

/// The areas a spec may declare, and the paths each one covers. These are AgentreksDB's own
/// subsystem names (the same list the interviewer offers), plus the cross-cutting areas every
/// repository has. An area nobody can name in a spec is an area no generated diff can enter.
const AREAS: &[AreaRule] = &[
    AreaRule {
        area: "engine",
        segments: &["engine", "storage", "wal", "index"],
    },
    AreaRule {
        area: "search",
        segments: &["search", "vector", "rerank", "hnsw"],
    },
    AreaRule {
        area: "graph",
        segments: &["graph", "traversal"],
    },
    AreaRule {
        area: "memory",
        segments: &["memory", "agent_memory"],
    },
    AreaRule {
        area: "events",
        segments: &["events", "replication", "consensus", "crdt", "hlc"],
    },
    AreaRule {
        area: "console",
        segments: &["console", "web", "ui"],
    },
    AreaRule {
        area: "deploy",
        segments: &["deploy", "docker", "helm", "terraform"],
    },
    AreaRule {
        area: "api",
        segments: &["api", "server", "http", "protocol", "wire"],
    },
    AreaRule {
        area: "auth",
        segments: &["auth", "authz", "crypto", "identity", "token"],
    },
    AreaRule {
        area: "tests",
        segments: &["tests", "test", "benches", "fuzz", "testdata"],
    },
    AreaRule {
        area: "docs",
        segments: &["docs", "doc"],
    },
    AreaRule {
        area: "ci",
        segments: &[".github", "gates", "scripts", "xtask"],
    },
];

/// The area a path belongs to, or `None` when no rule claims it. A path can sit in several
/// areas (`src/api/auth.rs`); all of them are returned, and the file is in scope if *any* was
/// declared. Being generous here is deliberate: a false "out of scope" on an honest change
/// costs a governor's attention, which is the scarcest thing in the pipeline.
pub fn areas_of(path: &str) -> Vec<&'static str> {
    let segs: Vec<&str> = path
        .split('/')
        .flat_map(|s| s.split('.'))
        .filter(|s| !s.is_empty())
        .collect();
    let mut out: Vec<&'static str> = AREAS
        .iter()
        .filter(|r| {
            r.segments
                .iter()
                .any(|w| segs.iter().any(|s| s.eq_ignore_ascii_case(w)))
        })
        .map(|r| r.area)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Normalise a spec's free-text area to one of [`AREAS`]. Specs are written by a model from a
/// human's words, so "the storage engine" and "Engine" must land on `engine`.
fn canonical_area(declared: &str) -> Option<&'static str> {
    let d = declared.trim().to_ascii_lowercase();
    if let Some(r) = AREAS.iter().find(|r| d == r.area) {
        return Some(r.area);
    }
    // Fall back to any area whose own name or segments appear as a word in the phrase.
    let words: Vec<&str> = d
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .collect();
    AREAS
        .iter()
        .find(|r| words.contains(&r.area) || r.segments.iter().any(|s| words.contains(s)))
        .map(|r| r.area)
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Block,
    Warn,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine name, e.g. `out_of_scope`.
    pub rule: String,
    pub path: String,
    /// What a governor needs to decide, in the spec's own words.
    pub detail: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Areas the spec declared, canonicalised.
    pub declared: Vec<String>,
    /// Areas the diff actually touched.
    pub touched: Vec<String>,
}

impl Report {
    pub fn blocked(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Block)
    }
}

/// A hunk-to-requirement map the generator emits: `path` → requirement ids it serves. A path
/// absent from the map is untraced. An empty map means the generator did not produce one, and
/// tracing is skipped rather than failing every file, so this gate can be rolled out before the
/// generator is taught to emit it.
pub type TraceMap = std::collections::BTreeMap<String, Vec<String>>;

/// Files that change in essentially every diff and that no spec would think to declare.
/// Lockfiles are deliberately NOT here: a dependency change is exactly the kind of thing that
/// should be declared, and `diffpolicy` has its own lockfile rules.
fn is_incidental(path: &str) -> bool {
    let p = path.rsplit('/').next().unwrap_or(path);
    matches!(
        p,
        "CHANGELOG.md" | "README.md" | ".gitignore" | "Cargo.toml"
    )
}

/// True when an added line changes a public signature.
fn is_public_api_line(line: &str) -> bool {
    let t = line.trim_start();
    (t.starts_with("pub fn ")
        || t.starts_with("pub async fn ")
        || t.starts_with("pub struct ")
        || t.starts_with("pub enum ")
        || t.starts_with("pub trait ")
        || t.starts_with("pub const ")
        || t.starts_with("pub type "))
        && !t.contains("#[cfg(test)]")
}

/// A new branch comparing against a hard-coded value: `if x == 0xdeadbeef`, `if user == "root"`.
/// This is the shape of a magic-value backdoor. Returns the literal when one is found.
fn literal_branch(line: &str) -> Option<String> {
    let t = line.trim();
    if !(t.starts_with("if ") || t.starts_with("} else if ") || t.starts_with("else if ")) {
        return None;
    }
    let op = t.find("==").or_else(|| t.find("!="))?;
    let rhs = t[op + 2..].trim();
    // A string literal, or a numeric literal that is not a small bound like 0, 1 or 2.
    if let Some(stripped) = rhs.strip_prefix('"') {
        let lit = stripped.split('"').next().unwrap_or("");
        if lit.len() >= 3 {
            return Some(format!("\"{lit}\""));
        }
        return None;
    }
    let tok: String = rhs
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == 'x' || *c == '_')
        .collect();
    let digits = tok.replace('_', "");
    if digits.len() >= 4 && (digits.starts_with("0x") || digits.chars().all(|c| c.is_ascii_digit()))
    {
        return Some(digits);
    }
    None
}

/// Check a diff against the spec that justified it.
pub fn check(spec: &Spec, manifest: &Manifest, trace: &TraceMap) -> Report {
    let declared: Vec<&'static str> = {
        let mut v: Vec<&'static str> = spec
            .affected_areas
            .iter()
            .filter_map(|a| canonical_area(a))
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    // Out-of-scope lines are prose ("secondary indexes"), so only those naming a real area can
    // be enforced. The rest stay a matter for the governor to read.
    let forbidden: Vec<&'static str> = {
        let mut v: Vec<&'static str> = spec
            .out_of_scope
            .iter()
            .filter_map(|a| canonical_area(a))
            .filter(|a| !declared.contains(a))
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };

    let declares_api_change = spec
        .api_or_data_changes
        .as_ref()
        .is_some_and(|c| !c.summary.trim().is_empty());

    let mut findings = Vec::new();
    let mut touched: Vec<&'static str> = Vec::new();

    for f in &manifest.files {
        let areas = areas_of(&f.path);
        for a in &areas {
            if !touched.contains(a) {
                touched.push(a);
            }
        }

        if is_incidental(&f.path) {
            continue;
        }

        if let Some(bad) = areas.iter().find(|a| forbidden.contains(a)) {
            findings.push(Finding {
                severity: Severity::Block,
                rule: "forbidden_area".into(),
                path: f.path.clone(),
                detail: format!(
                    "the spec puts `{bad}` out of scope, and this file is in it. The change \
                     cannot touch an area its own spec ruled out; widen the spec and re-run, \
                     or drop the file."
                ),
            });
        } else if !areas.is_empty()
            && !declared.is_empty()
            && !areas.iter().any(|a| declared.contains(a))
        {
            findings.push(Finding {
                severity: Severity::Block,
                rule: "out_of_scope".into(),
                path: f.path.clone(),
                detail: format!(
                    "in `{}`, but the spec declared only {}. A hunk nobody asked for is where \
                     a backdoor lives, so this stops for a human.",
                    areas.join("`, `"),
                    declared
                        .iter()
                        .map(|d| format!("`{d}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        if !trace.is_empty() && !trace.contains_key(&f.path) && !f.binary {
            findings.push(Finding {
                severity: Severity::Block,
                rule: "untraced".into(),
                path: f.path.clone(),
                detail: "no requirement claims this file. Every hunk must name the requirement \
                         it serves, so that 'why is this here?' has an answer on the record."
                    .into(),
            });
        }

        if !declares_api_change {
            if let Some(line) = f.added_lines.iter().find(|l| is_public_api_line(l)) {
                findings.push(Finding {
                    severity: Severity::Block,
                    rule: "undeclared_api_change".into(),
                    path: f.path.clone(),
                    detail: format!(
                        "adds a public item while the spec declares no API change: `{}`. \
                         Every consumer feels this, so it is declared or it does not ship.",
                        line.trim()
                    ),
                });
            }
        }

        for line in &f.added_lines {
            if let Some(lit) = literal_branch(line) {
                let mentioned = spec_mentions(spec, &lit);
                if !mentioned {
                    findings.push(Finding {
                        severity: Severity::Warn,
                        rule: "unexplained_literal_branch".into(),
                        path: f.path.clone(),
                        detail: format!(
                            "branches on {lit}, which the spec never mentions. Usually a bounds \
                             check; occasionally the trigger of a magic-value backdoor."
                        ),
                    });
                }
            }
        }
    }

    if !declared.is_empty() && touched.len() > declared.len() + 2 {
        findings.push(Finding {
            severity: Severity::Warn,
            rule: "scope_creep".into(),
            path: String::new(),
            detail: format!(
                "the spec declared {} area(s) but the diff touches {}. Either the spec was \
                 written too narrowly or the change grew past it.",
                declared.len(),
                touched.len()
            ),
        });
    }

    touched.sort_unstable();
    Report {
        findings,
        declared: declared.into_iter().map(String::from).collect(),
        touched: touched.into_iter().map(String::from).collect(),
    }
}

/// Whether the spec's prose anywhere mentions a literal, so an explained constant stays quiet.
fn spec_mentions(spec: &Spec, literal: &str) -> bool {
    let needle = literal.trim_matches('"').to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    let mut hay = String::new();
    for r in &spec.requirements {
        hay.push_str(&r.ears);
        hay.push(' ');
        hay.push_str(&r.rationale);
        hay.push(' ');
    }
    for t in &spec.acceptance_tests {
        hay.push_str(&t.given);
        hay.push(' ');
        hay.push_str(&t.when);
        hay.push(' ');
        hay.push_str(&t.then);
        hay.push(' ');
    }
    for c in &spec.constraints {
        hay.push_str(c);
        hay.push(' ');
    }
    for s in &spec.in_scope {
        hay.push_str(s);
        hay.push(' ');
    }
    if let Some(p) = &spec.problem_statement {
        hay.push_str(p);
    }
    hay.to_ascii_lowercase().contains(&needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diffpolicy::FileChange;

    fn file(path: &str, added: &[&str]) -> FileChange {
        FileChange {
            path: path.into(),
            status: "modified".into(),
            binary: false,
            added_lines: added.iter().map(|s| s.to_string()).collect(),
            removed_lines: vec![],
        }
    }

    fn manifest(files: Vec<FileChange>) -> Manifest {
        Manifest {
            base: "a".into(),
            head: "b".into(),
            files,
        }
    }

    fn engine_spec() -> Spec {
        Spec {
            affected_areas: vec!["engine".into()],
            out_of_scope: vec!["auth".into()],
            requirements: vec![crate::spec::Requirement {
                id: "R1".into(),
                ears: "WHEN a range filter is given THE SYSTEM SHALL read only matching records"
                    .into(),
                rationale: "scan cost".into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn a_file_in_the_declared_area_passes() {
        let m = manifest(vec![file("src/engine/scan.rs", &["let n = 1;"])]);
        let r = check(&engine_spec(), &m, &TraceMap::new());
        assert!(!r.blocked(), "{:?}", r.findings);
        assert_eq!(r.touched, vec!["engine"]);
    }

    /// The core case: the spec said engine, the diff edits auth. This is the shape of a
    /// backdoor riding along with an honest change.
    #[test]
    fn a_file_outside_every_declared_area_blocks() {
        let m = manifest(vec![
            file("src/engine/scan.rs", &["let n = 1;"]),
            file("src/auth/token.rs", &["let ok = true;"]),
        ]);
        let r = check(&engine_spec(), &m, &TraceMap::new());
        assert!(r.blocked());
        let f = r.findings.iter().find(|f| f.path.contains("auth")).unwrap();
        // `auth` is listed out of scope here, so the stronger rule should be the one that fires.
        assert_eq!(f.rule, "forbidden_area");
    }

    #[test]
    fn an_undeclared_area_blocks_even_when_not_explicitly_forbidden() {
        let mut s = engine_spec();
        s.out_of_scope = vec!["secondary indexes".into()];
        let m = manifest(vec![file("src/auth/token.rs", &["let ok = true;"])]);
        let r = check(&s, &m, &TraceMap::new());
        assert_eq!(r.findings[0].rule, "out_of_scope");
    }

    /// Matching must be by path segment. A file that merely contains a blessed word in its
    /// name must not be able to talk its way into an area.
    #[test]
    fn area_matching_is_by_segment_not_substring() {
        assert_eq!(areas_of("src/engine/scan.rs"), vec!["engine"]);
        assert!(areas_of("src/my_engine_notes.rs").is_empty());
        assert_eq!(areas_of("src/api/auth.rs"), vec!["api", "auth"]);
    }

    /// A file in several areas is in scope if any one of them was declared.
    #[test]
    fn a_file_in_several_areas_needs_only_one_declared() {
        let mut s = engine_spec();
        s.out_of_scope.clear();
        s.affected_areas = vec!["api".into()];
        let m = manifest(vec![file("src/api/auth.rs", &["let x = 1;"])]);
        let r = check(&s, &m, &TraceMap::new());
        assert!(!r.blocked(), "{:?}", r.findings);
    }

    #[test]
    fn an_undeclared_public_item_blocks() {
        let m = manifest(vec![file(
            "src/engine/scan.rs",
            &["pub fn backdoor(k: &str) -> bool {"],
        )]);
        let r = check(&engine_spec(), &m, &TraceMap::new());
        assert!(r.findings.iter().any(|f| f.rule == "undeclared_api_change"));
    }

    #[test]
    fn a_declared_api_change_is_allowed() {
        let mut s = engine_spec();
        s.api_or_data_changes = Some(crate::spec::ApiChanges {
            summary: "adds scan_range".into(),
            breaking: false,
        });
        let m = manifest(vec![file(
            "src/engine/scan.rs",
            &["pub fn scan_range(a: u64) -> bool {"],
        )]);
        let r = check(&s, &m, &TraceMap::new());
        assert!(!r.blocked(), "{:?}", r.findings);
    }

    #[test]
    fn a_file_no_requirement_claims_blocks_when_a_trace_map_exists() {
        let mut trace = TraceMap::new();
        trace.insert("src/engine/scan.rs".into(), vec!["R1".into()]);
        let m = manifest(vec![
            file("src/engine/scan.rs", &["let n = 1;"]),
            file("src/engine/other.rs", &["let m = 2;"]),
        ]);
        let r = check(&engine_spec(), &m, &trace);
        let f = r.findings.iter().find(|f| f.rule == "untraced").unwrap();
        assert_eq!(f.path, "src/engine/other.rs");
    }

    /// Rolling this gate out must not fail every file before the generator emits a map.
    #[test]
    fn an_empty_trace_map_traces_nothing() {
        let m = manifest(vec![file("src/engine/a.rs", &["let n = 1;"])]);
        let r = check(&engine_spec(), &m, &TraceMap::new());
        assert!(!r.findings.iter().any(|f| f.rule == "untraced"));
    }

    #[test]
    fn a_magic_value_branch_is_flagged_but_does_not_block() {
        let m = manifest(vec![file(
            "src/engine/scan.rs",
            &["    if token == \"s3cr3t-master-key\" {"],
        )]);
        let r = check(&engine_spec(), &m, &TraceMap::new());
        let f = r
            .findings
            .iter()
            .find(|f| f.rule == "unexplained_literal_branch")
            .unwrap();
        assert_eq!(f.severity, Severity::Warn);
    }

    /// A constant the spec actually discusses is ordinary engineering, not a trigger.
    #[test]
    fn a_literal_the_spec_explains_stays_quiet() {
        let mut s = engine_spec();
        s.constraints = vec!["records longer than 65536 bytes are rejected".into()];
        let m = manifest(vec![file("src/engine/scan.rs", &["    if len == 65536 {"])]);
        let r = check(&s, &m, &TraceMap::new());
        assert!(!r
            .findings
            .iter()
            .any(|f| f.rule == "unexplained_literal_branch"));
    }

    #[test]
    fn small_bounds_are_not_treated_as_magic_values() {
        assert!(literal_branch("if n == 0 {").is_none());
        assert!(literal_branch("if n == 1 {").is_none());
        assert!(literal_branch("if s == \"a\" {").is_none());
        assert!(literal_branch("let x = y == 12345;").is_none());
        assert_eq!(
            literal_branch("if k == 0xdeadbeef {").as_deref(),
            Some("0xdeadbeef")
        );
    }

    /// A spec that declares nothing cannot be used to police anything; readiness already
    /// refuses such a spec, and this gate must not invent a verdict from an empty list.
    #[test]
    fn an_empty_declaration_blocks_nothing_here() {
        let s = Spec::default();
        let m = manifest(vec![file("src/auth/token.rs", &["let ok = true;"])]);
        let r = check(&s, &m, &TraceMap::new());
        assert!(!r.findings.iter().any(|f| f.rule == "out_of_scope"));
    }

    #[test]
    fn incidental_files_are_not_policed() {
        let m = manifest(vec![file("CHANGELOG.md", &["- fixed a thing"])]);
        let r = check(&engine_spec(), &m, &TraceMap::new());
        assert!(!r.blocked(), "{:?}", r.findings);
    }

    #[test]
    fn free_text_areas_are_canonicalised() {
        assert_eq!(canonical_area("the storage engine"), Some("engine"));
        assert_eq!(canonical_area("Engine"), Some("engine"));
        assert_eq!(canonical_area("vector search"), Some("search"));
        assert_eq!(canonical_area("nothing recognisable"), None);
    }
}
