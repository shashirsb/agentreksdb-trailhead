//! The intent → spec contract. Generation is only allowed once a spec passes [`readiness`]:
//! the "definition of ready". The model drafts the spec during the intent chat; this validator,
//! not the model, decides whether it is complete.

use serde::{Deserialize, Serialize};

pub const CHANGE_TYPES: [&str; 6] = ["bug", "feature", "perf", "refactor", "docs", "protocol"];
pub const RISK_LEVELS: [&str; 3] = ["low", "medium", "high"];

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Spec {
    pub title: Option<String>,
    pub change_type: Option<String>,
    pub problem_statement: Option<String>,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub affected_areas: Vec<String>,
    pub requirements: Vec<Requirement>,
    pub acceptance_tests: Vec<AcceptanceTest>,
    pub api_or_data_changes: Option<ApiChanges>,
    pub constraints: Vec<String>,
    pub constitution_check: Vec<String>,
    pub risk_level: Option<String>,
    pub rollback_plan: Option<String>,
    pub open_questions: Vec<String>,
    pub clarification_log: Vec<Clarification>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Requirement {
    pub id: String,
    /// EARS statement, e.g. "WHEN a range filter is given THE SYSTEM SHALL read only matching records".
    pub ears: String,
    pub rationale: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct AcceptanceTest {
    pub id: String,
    pub requirement_id: String,
    pub given: String,
    pub when: String,
    pub then: String,
    /// A negative or edge case. At least one test must be negative.
    pub negative: bool,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct ApiChanges {
    pub summary: String,
    pub breaking: bool,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Clarification {
    pub q: String,
    pub a: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Readiness {
    pub ready: bool,
    /// Required fields that are empty.
    pub missing: Vec<String>,
    /// Fields that are present but fail a quality rule.
    pub weak: Vec<String>,
    /// At most three next questions for the contributor, derived from `missing` and `weak`.
    pub questions: Vec<String>,
}

fn blank(s: &Option<String>) -> bool {
    s.as_deref().map(str::trim).unwrap_or("").is_empty()
}

fn question_for(field: &str) -> &'static str {
    match field {
        "title" => "What short title describes this change?",
        "change_type" => "Is this a bug fix, feature, perf, refactor, docs or protocol change?",
        "problem_statement" => "Who hits this problem, what happens today, and why does it matter? (a few sentences)",
        "in_scope" => "What exactly is in scope for this change?",
        "out_of_scope" => "What is explicitly out of scope, so the model does not over-build?",
        "affected_areas" => "Which parts of AgentreksDB does it touch (engine, search, graph, memory, events, console, deploy)?",
        "requirements" => "State each requirement as 'WHEN <trigger> THE SYSTEM SHALL <response>'.",
        "requirements.ears" => "Rewrite each requirement in EARS form: 'WHEN <trigger> THE SYSTEM SHALL <response>'.",
        "acceptance_tests" => "How will we know it works? Give Given/When/Then tests, one per requirement.",
        "acceptance_tests.negative" => "Add at least one negative or edge-case test (what must NOT happen).",
        "acceptance_tests.link" => "Each acceptance test must name the requirement it proves.",
        "api_or_data_changes" => "Does this change any API, wire format or stored data? Is it breaking?",
        "constraints" => "Any performance, consistency, security or compatibility constraints?",
        "constitution_check" => "Confirm which project invariants stay untouched (consistency model, storage format, AI-only provenance).",
        "risk_level" => "How risky is this: low, medium or high?",
        "rollback_plan" => "If it goes wrong after merge, how do we roll it back?",
        "problem_statement.short" => "Say more about the problem: who is affected and what it costs them.",
        "change_type.invalid" => "Pick one change type: bug, feature, perf, refactor, docs or protocol.",
        "risk_level.invalid" => "Pick one risk level: low, medium or high.",
        _ => "Please clarify this part of the request.",
    }
}

/// Decide whether a spec is complete enough to start generation.
pub fn readiness(spec: &Spec) -> Readiness {
    let mut missing = Vec::new();
    let mut weak = Vec::new();

    if blank(&spec.title) {
        missing.push("title");
    }
    match spec.change_type.as_deref().map(str::trim) {
        None | Some("") => missing.push("change_type"),
        Some(t) if !CHANGE_TYPES.contains(&t) => weak.push("change_type.invalid"),
        _ => {}
    }
    if blank(&spec.problem_statement) {
        missing.push("problem_statement");
    } else if spec.problem_statement.as_deref().unwrap_or("").trim().len() < 40 {
        weak.push("problem_statement.short");
    }
    if spec.in_scope.is_empty() {
        missing.push("in_scope");
    }
    if spec.out_of_scope.is_empty() {
        missing.push("out_of_scope");
    }
    if spec.affected_areas.is_empty() {
        missing.push("affected_areas");
    }
    if spec.requirements.is_empty() {
        missing.push("requirements");
    } else if spec.requirements.iter().any(|r| !is_ears(&r.ears)) {
        weak.push("requirements.ears");
    }
    if spec.acceptance_tests.is_empty() {
        missing.push("acceptance_tests");
    } else {
        if !spec.acceptance_tests.iter().any(|t| t.negative) {
            weak.push("acceptance_tests.negative");
        }
        let ids: Vec<&str> = spec.requirements.iter().map(|r| r.id.as_str()).collect();
        if spec
            .acceptance_tests
            .iter()
            .any(|t| !ids.contains(&t.requirement_id.as_str()))
        {
            weak.push("acceptance_tests.link");
        }
    }
    if spec.api_or_data_changes.is_none() {
        missing.push("api_or_data_changes");
    }
    if spec.constraints.is_empty() {
        missing.push("constraints");
    }
    if spec.constitution_check.is_empty() {
        missing.push("constitution_check");
    }
    match spec.risk_level.as_deref().map(str::trim) {
        None | Some("") => missing.push("risk_level"),
        Some(r) if !RISK_LEVELS.contains(&r) => weak.push("risk_level.invalid"),
        _ => {}
    }
    if blank(&spec.rollback_plan) {
        missing.push("rollback_plan");
    }

    let mut questions: Vec<String> = spec.open_questions.iter().take(3).cloned().collect();
    for f in missing.iter().chain(weak.iter()) {
        if questions.len() >= 3 {
            break;
        }
        questions.push(question_for(f).to_string());
    }

    let ready = missing.is_empty() && weak.is_empty() && spec.open_questions.is_empty();
    Readiness {
        ready,
        missing: missing.into_iter().map(String::from).collect(),
        weak: weak.into_iter().map(String::from).collect(),
        questions,
    }
}

/// EARS: every requirement must say what the system SHALL do; event-driven, state-driven,
/// optional and unwanted-behaviour forms add WHEN / WHILE / WHERE / IF.
pub fn is_ears(s: &str) -> bool {
    let u = s.to_uppercase();
    u.contains(" SHALL ") || u.starts_with("THE SYSTEM SHALL")
}

/// The question text for one readiness field (used by the offline interviewer).
pub fn question(field: &str) -> &'static str {
    question_for(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn complete() -> Spec {
        Spec {
            title: Some("Ordered primary-key index for range scans".into()),
            change_type: Some("perf".into()),
            problem_statement: Some(
                "Range scans read, merge and sort the whole collection; YCSB-E takes 1.7s at 20k records.".into(),
            ),
            in_scope: vec!["ordered PK index per shard".into()],
            out_of_scope: vec!["secondary indexes".into()],
            affected_areas: vec!["engine".into()],
            requirements: vec![Requirement {
                id: "R1".into(),
                ears: "WHEN a range filter on the primary key is given THE SYSTEM SHALL read only matching records".into(),
                rationale: "speed".into(),
            }],
            acceptance_tests: vec![
                AcceptanceTest {
                    id: "T1".into(),
                    requirement_id: "R1".into(),
                    given: "20k records".into(),
                    when: "a range scan runs".into(),
                    then: "results equal the full scan".into(),
                    negative: false,
                },
                AcceptanceTest {
                    id: "T2".into(),
                    requirement_id: "R1".into(),
                    given: "an empty range".into(),
                    when: "a range scan runs".into(),
                    then: "no records are read".into(),
                    negative: true,
                },
            ],
            api_or_data_changes: Some(ApiChanges { summary: "none".into(), breaking: false }),
            constraints: vec!["results byte-identical to full scan".into()],
            constitution_check: vec!["storage format unchanged".into()],
            risk_level: Some("medium".into()),
            rollback_plan: Some("revert the commit; index is rebuilt on start".into()),
            open_questions: vec![],
            clarification_log: vec![],
        }
    }

    #[test]
    fn empty_spec_is_not_ready_and_asks_three_questions() {
        let r = readiness(&Spec::default());
        assert!(!r.ready);
        assert!(r.missing.contains(&"title".to_string()));
        assert_eq!(r.questions.len(), 3);
    }

    #[test]
    fn complete_spec_is_ready() {
        let r = readiness(&complete());
        assert!(r.ready, "{r:?}");
        assert!(r.questions.is_empty());
    }

    #[test]
    fn non_ears_requirement_is_weak() {
        let mut s = complete();
        s.requirements[0].ears = "make range scans fast".into();
        let r = readiness(&s);
        assert!(!r.ready);
        assert!(r.weak.contains(&"requirements.ears".to_string()));
    }

    #[test]
    fn needs_a_negative_test_and_links() {
        let mut s = complete();
        s.acceptance_tests.retain(|t| !t.negative);
        s.acceptance_tests[0].requirement_id = "R9".into();
        let r = readiness(&s);
        assert!(r.weak.contains(&"acceptance_tests.negative".to_string()));
        assert!(r.weak.contains(&"acceptance_tests.link".to_string()));
    }

    #[test]
    fn open_questions_block_readiness() {
        let mut s = complete();
        s.open_questions.push("Which shards first?".into());
        let r = readiness(&s);
        assert!(!r.ready);
        assert_eq!(r.questions[0], "Which shards first?");
    }
}
