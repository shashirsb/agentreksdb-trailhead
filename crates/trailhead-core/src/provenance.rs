//! Provenance for every generated commit: an in-toto v1 Statement carrying a SLSA v1 provenance
//! predicate, plus human-readable git trailers. The gate workflow signs the commit with gitsign
//! (keyless, workload identity) and uploads this statement to Rekor; `GET /api/verify/:sha`
//! and `trailhead verify` read it back.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const BUILD_TYPE: &str = "https://github.com/shashirsb/agentreksdb-trailhead/codegen/v1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Generation {
    pub intent_id: i64,
    pub model_id: String,
    pub harness: String,
    pub spec_hash: String,
    pub prompt_log_hash: String,
    pub sandbox_run_id: String,
    pub sandbox_image: String,
    pub guardrail_report_hash: String,
    pub parent_commit: String,
    pub pipeline_commit: String,
    pub terms_version: String,
    pub started_at: String,
    pub finished_at: String,
    pub cost_credits: i64,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn statement(commit_sha: &str, tree_sha: &str, g: &Generation) -> Value {
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": format!("git+commit:{commit_sha}"),
            "digest": { "gitCommit": commit_sha, "gitTree": tree_sha }
        }],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "intent_id": g.intent_id,
                    "spec_hash": g.spec_hash,
                },
                "internalParameters": {
                    "model_id": g.model_id,
                    "harness": g.harness,
                    "terms_version": g.terms_version,
                    "guardrail_report_hash": g.guardrail_report_hash,
                },
                "resolvedDependencies": [
                    { "uri": "git+parent", "digest": { "gitCommit": g.parent_commit } },
                    { "uri": "git+https://github.com/shashirsb/agentreksdb-trailhead", "digest": { "gitCommit": g.pipeline_commit } },
                    { "uri": "oci+sandbox", "digest": { "sha256": g.sandbox_image } }
                ]
            },
            "runDetails": {
                "builder": { "id": "https://github.com/shashirsb/agentreksdb-trailhead/worker" },
                "metadata": {
                    "invocationId": g.sandbox_run_id,
                    "startedOn": g.started_at,
                    "finishedOn": g.finished_at
                },
                "byproducts": [
                    { "name": "prompt-log", "digest": { "sha256": g.prompt_log_hash } }
                ]
            }
        }
    })
}

/// Git trailers appended to the generated commit message.
pub fn trailers(g: &Generation, ledger_url: &str) -> String {
    format!(
        "Generated-By: {}\nTrailhead-Intent: {}\nSpec-Hash: sha256:{}\nPrompt-Log: sha256:{}\nSandbox-Run: {}\nLedger: {}/intents/{}\n",
        g.model_id, g.intent_id, g.spec_hash, g.prompt_log_hash, g.sandbox_run_id, ledger_url, g.intent_id
    )
}

/// Parse trailers back out of a commit message (used by `verify`).
pub fn parse_trailers(message: &str) -> Vec<(String, String)> {
    message
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(": ")?;
            let ok = !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
            ok.then(|| (k.to_string(), v.trim().to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g() -> Generation {
        Generation {
            intent_id: 142,
            model_id: "claude-opus-5-5".into(),
            harness: "claude-agent-sdk".into(),
            spec_hash: sha256_hex(b"spec"),
            prompt_log_hash: sha256_hex(b"log"),
            sandbox_run_id: "run-1".into(),
            sandbox_image: sha256_hex(b"img"),
            guardrail_report_hash: sha256_hex(b"g"),
            parent_commit: "abc".into(),
            pipeline_commit: "def".into(),
            terms_version: "anthropic-commercial-2025-06-17".into(),
            started_at: "2026-10-26T00:00:00Z".into(),
            finished_at: "2026-10-26T00:20:00Z".into(),
            cost_credits: 800,
        }
    }

    #[test]
    fn statement_names_the_commit_and_model() {
        let s = statement("a1f90c2", "t1", &g());
        assert_eq!(s["subject"][0]["digest"]["gitCommit"], "a1f90c2");
        assert_eq!(
            s["predicate"]["buildDefinition"]["internalParameters"]["model_id"],
            "claude-opus-5-5"
        );
    }

    #[test]
    fn trailers_round_trip() {
        let t = trailers(&g(), "https://trailhead.agentreks.dev");
        let p = parse_trailers(&format!("feat: x\n\nbody\n\n{t}"));
        assert!(p.contains(&("Generated-By".into(), "claude-opus-5-5".into())));
        assert!(p.contains(&("Trailhead-Intent".into(), "142".into())));
    }
}
