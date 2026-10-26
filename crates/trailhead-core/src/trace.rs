//! Requirement → acceptance test → Rust test traceability.
//!
//! When no human writes the code, the tests are the only thing standing between the model and
//! a broken database, and "the suite is green" says nothing about whether the suite tests what
//! was asked for. This module answers two questions a gate can block on:
//!
//! 1. **Is every acceptance criterion backed by a real test?** An acceptance test with no Rust
//!    test behind it is a promise nobody kept.
//! 2. **Does that test actually prove the change?** A test that already passed on the parent
//!    commit demonstrates nothing about the diff. It is reported as *not discriminating*,
//!    which is the per-criterion equivalent of a surviving mutant.
//!
//! Tests declare what they cover with a doc comment the source carries verbatim:
//!
//! ```text
//! /// trailhead: T1, T3
//! #[test]
//! fn range_filter_reads_only_matching_records() { … }
//! ```
//!
//! A naming convention (`at_t1_<slug>`) is accepted too, so the link survives into JUnit output
//! where only the test's name is left.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::spec::Spec;

/// One Rust test as the runner reports it.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct TestCase {
    /// Fully qualified test name, e.g. `trailhead-core::spec tests::readiness_rejects_empty`.
    pub id: String,
    /// Acceptance-test ids declared by a `trailhead:` doc comment.
    pub covers: Vec<String>,
    /// Whether this test is newly added in the diff under review.
    pub added_in_diff: bool,
    /// Result on the parent commit: `fail` (good — it proves the change), `pass` (it passed
    /// before, so it does not discriminate) or `n/a` (not run against the parent).
    pub fail_before: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Gap {
    /// An acceptance criterion with no test behind it.
    Untested,
    /// A test claims an acceptance id the spec never defined.
    UnknownAcceptance,
    /// A requirement with no acceptance criterion at all.
    RequirementUntested,
    /// Covered, but every covering test already passed on the parent commit.
    NotDiscriminating,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Finding {
    pub gap: Gap,
    pub id: String,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Report {
    pub acceptance_total: usize,
    pub acceptance_covered: usize,
    pub requirements_total: usize,
    pub requirements_covered: usize,
    /// Acceptance id -> the tests that cover it.
    pub matrix: BTreeMap<String, Vec<String>>,
    pub findings: Vec<Finding>,
    /// True when nothing blocking was found. `NotDiscriminating` warns rather than blocks,
    /// because a test can legitimately pass before a pure refactor.
    pub ok: bool,
}

/// Pull acceptance ids out of a `trailhead:` doc comment line.
///
/// Accepts `/// trailhead: T1, T3` and `// trailhead: T1`.
pub fn ids_from_comment(line: &str) -> Vec<String> {
    let Some(rest) = line.split("trailhead:").nth(1) else {
        return Vec::new();
    };
    rest.split([',', ';'])
        .map(|s| s.trim().trim_end_matches('*').trim())
        .filter(|s| {
            s.len() >= 2
                && s.len() <= 16
                && s.starts_with(['T', 't'])
                && s[1..].chars().all(|c| c.is_ascii_digit())
        })
        .map(|s| s.to_uppercase())
        .collect()
}

/// Recover an acceptance id from a test name following the `at_t1_…` convention.
pub fn id_from_name(name: &str) -> Option<String> {
    // nextest reports names as `crate::module tests::name`, so split on both separators.
    let tail = name
        .rsplit(|c: char| c == ':' || c.is_whitespace())
        .next()
        .unwrap_or(name);
    let rest = tail.strip_prefix("at_")?;
    let mut chars = rest.chars();
    if !matches!(chars.next(), Some('t') | Some('T')) {
        return None;
    }
    let digits: String = rest[1..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    Some(format!("T{digits}"))
}

/// Build the traceability report for one spec and one set of test results.
pub fn report(spec: &Spec, tests: &[TestCase]) -> Report {
    let defined: BTreeSet<String> = spec
        .acceptance_tests
        .iter()
        .map(|a| a.id.to_uppercase())
        .collect();

    let mut matrix: BTreeMap<String, Vec<String>> =
        defined.iter().map(|id| (id.clone(), Vec::new())).collect();
    let mut findings = Vec::new();

    for t in tests {
        let mut claimed: BTreeSet<String> = t.covers.iter().map(|c| c.to_uppercase()).collect();
        if let Some(from_name) = id_from_name(&t.id) {
            claimed.insert(from_name);
        }
        for id in claimed {
            match matrix.get_mut(&id) {
                Some(v) => v.push(t.id.clone()),
                None => findings.push(Finding {
                    gap: Gap::UnknownAcceptance,
                    id: id.clone(),
                    detail: format!(
                        "test `{}` claims acceptance test {id}, which this spec does not define",
                        t.id
                    ),
                }),
            }
        }
    }

    let by_id: BTreeMap<&str, &TestCase> = tests.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut covered = 0usize;
    for (acc, ts) in &matrix {
        if ts.is_empty() {
            let text = spec
                .acceptance_tests
                .iter()
                .find(|a| a.id.eq_ignore_ascii_case(acc))
                .map(|a| format!("{} / {} / {}", a.given, a.when, a.then))
                .unwrap_or_default();
            findings.push(Finding {
                gap: Gap::Untested,
                id: acc.clone(),
                detail: format!("no test covers {acc}: {text}"),
            });
            continue;
        }
        covered += 1;
        // If every covering test already passed on the parent, none of them proves the change.
        let any_discriminates = ts.iter().any(|name| {
            by_id
                .get(name.as_str())
                .and_then(|t| t.fail_before.as_deref())
                .map(|f| f != "pass")
                .unwrap_or(true)
        });
        if !any_discriminates {
            findings.push(Finding {
                gap: Gap::NotDiscriminating,
                id: acc.clone(),
                detail: format!(
                    "every test covering {acc} already passed on the parent commit, so none of them demonstrates this change"
                ),
            });
        }
    }

    // A requirement is covered when at least one of its acceptance tests is covered.
    let mut req_covered = 0usize;
    for r in &spec.requirements {
        let has = spec.acceptance_tests.iter().any(|a| {
            a.requirement_id.eq_ignore_ascii_case(&r.id)
                && matrix
                    .get(&a.id.to_uppercase())
                    .map(|v| !v.is_empty())
                    .unwrap_or(false)
        });
        if has {
            req_covered += 1;
        } else {
            findings.push(Finding {
                gap: Gap::RequirementUntested,
                id: r.id.clone(),
                detail: format!(
                    "no passing-and-linked test reaches requirement {}: {}",
                    r.id, r.ears
                ),
            });
        }
    }

    let ok = !findings
        .iter()
        .any(|f| !matches!(f.gap, Gap::NotDiscriminating));

    Report {
        acceptance_total: matrix.len(),
        acceptance_covered: covered,
        requirements_total: spec.requirements.len(),
        requirements_covered: req_covered,
        matrix,
        findings,
        ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{AcceptanceTest, Requirement};

    fn spec() -> Spec {
        Spec {
            requirements: vec![
                Requirement {
                    id: "R1".into(),
                    ears:
                        "WHEN a range filter is given THE SYSTEM SHALL read only matching records"
                            .into(),
                    rationale: "perf".into(),
                },
                Requirement {
                    id: "R2".into(),
                    ears: "THE SYSTEM SHALL reject an empty filter".into(),
                    rationale: "safety".into(),
                },
            ],
            acceptance_tests: vec![
                AcceptanceTest {
                    id: "T1".into(),
                    requirement_id: "R1".into(),
                    given: "10k rows".into(),
                    when: "a range filter".into(),
                    then: "only matching read".into(),
                    negative: false,
                },
                AcceptanceTest {
                    id: "T2".into(),
                    requirement_id: "R2".into(),
                    given: "an empty filter".into(),
                    when: "queried".into(),
                    then: "an error".into(),
                    negative: true,
                },
            ],
            ..Default::default()
        }
    }

    fn t(id: &str, covers: &[&str], fail_before: &str) -> TestCase {
        TestCase {
            id: id.into(),
            covers: covers.iter().map(|s| s.to_string()).collect(),
            added_in_diff: true,
            fail_before: Some(fail_before.into()),
        }
    }

    #[test]
    fn a_fully_traced_spec_passes() {
        let r = report(&spec(), &[t("a", &["T1"], "fail"), t("b", &["T2"], "fail")]);
        assert!(r.ok, "{:?}", r.findings);
        assert_eq!(r.acceptance_covered, 2);
        assert_eq!(r.requirements_covered, 2);
    }

    #[test]
    fn an_uncovered_criterion_blocks() {
        let r = report(&spec(), &[t("a", &["T1"], "fail")]);
        assert!(!r.ok);
        assert!(r
            .findings
            .iter()
            .any(|f| f.gap == Gap::Untested && f.id == "T2"));
        // The requirement behind it is reported too, so the gap is visible at both levels.
        assert!(r
            .findings
            .iter()
            .any(|f| f.gap == Gap::RequirementUntested && f.id == "R2"));
    }

    #[test]
    fn a_test_that_passed_before_does_not_prove_the_change() {
        let r = report(&spec(), &[t("a", &["T1"], "pass"), t("b", &["T2"], "fail")]);
        assert!(r
            .findings
            .iter()
            .any(|f| f.gap == Gap::NotDiscriminating && f.id == "T1"));
        // It warns rather than blocks: a pure refactor legitimately keeps its tests green.
        assert!(r.ok);
    }

    #[test]
    fn one_discriminating_test_is_enough() {
        let r = report(
            &spec(),
            &[
                t("a", &["T1"], "pass"),
                t("a2", &["T1"], "fail"),
                t("b", &["T2"], "fail"),
            ],
        );
        assert!(!r.findings.iter().any(|f| f.gap == Gap::NotDiscriminating));
    }

    #[test]
    fn claiming_an_undefined_criterion_blocks() {
        let r = report(
            &spec(),
            &[
                t("a", &["T1"], "fail"),
                t("b", &["T2"], "fail"),
                t("c", &["T9"], "fail"),
            ],
        );
        assert!(!r.ok);
        assert!(r
            .findings
            .iter()
            .any(|f| f.gap == Gap::UnknownAcceptance && f.id == "T9"));
    }

    #[test]
    fn the_naming_convention_also_links() {
        let mut by_name = t("crate::m at_t1_reads_only_matching", &[], "fail");
        by_name.covers.clear();
        let r = report(&spec(), &[by_name, t("b", &["T2"], "fail")]);
        assert_eq!(r.acceptance_covered, 2, "{:?}", r.matrix);
    }

    #[test]
    fn doc_comment_parsing() {
        assert_eq!(ids_from_comment("/// trailhead: T1, T3"), vec!["T1", "T3"]);
        assert_eq!(ids_from_comment("// trailhead:t7"), vec!["T7"]);
        assert!(ids_from_comment("/// nothing here").is_empty());
        // Must not swallow prose or absurd values.
        assert!(ids_from_comment("/// trailhead: the whole thing").is_empty());
        assert!(ids_from_comment("/// trailhead: T").is_empty());
    }

    #[test]
    fn name_parsing() {
        assert_eq!(id_from_name("m::at_t12_slug"), Some("T12".into()));
        assert_eq!(id_from_name("at_t1_x"), Some("T1".into()));
        assert_eq!(id_from_name("not_an_at_test"), None);
        assert_eq!(id_from_name("at_xyz"), None);
    }

    #[test]
    fn an_empty_spec_is_vacuously_fine_but_reports_nothing_covered() {
        let r = report(&Spec::default(), &[]);
        assert!(r.ok);
        assert_eq!(r.acceptance_total, 0);
    }
}
