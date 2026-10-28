//! `trailhead doctor` — check every outside dependency and say exactly what is wrong.
//!
//! The pipeline reaches out to four things it does not control: Postgres, the Anthropic API, the
//! GitHub App, and the container runtime that holds the sandbox. When one of them refuses, the
//! failure surfaces wherever a contributor happened to be standing — the first real intent filed
//! against this deployment died on a bare "400 Bad Request" from the interviewer, and finding out
//! why meant reading the server's source.
//!
//! That is backwards. A deployment should be able to answer "is everything I depend on actually
//! working?" before anybody files anything, and it should answer in the words of whoever said no.
//! So every check here reports the upstream error verbatim rather than a tidy summary of it: the
//! useful part of "credit balance is too low" is the sentence, not the status code.
//!
//! What it never does is print a secret. Keys are reported as present or absent and by length,
//! because the common mistakes — an unset variable, a truncated paste, a trailing newline — are
//! all visible in the length, and none of them need the value.
//!
//! Exit code is the number of failed checks, so `trailhead doctor && deploy` works.

use crate::config::Config;
use serde_json::json;
use std::fmt::Write as _;

#[derive(PartialEq, Clone, Copy)]
enum State {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl State {
    fn mark(self) -> &'static str {
        match self {
            State::Ok => "ok  ",
            State::Warn => "warn",
            State::Fail => "FAIL",
            State::Skip => "skip",
        }
    }
}

struct Report {
    rows: Vec<(State, String, String)>,
}

impl Report {
    fn new() -> Self {
        Report { rows: Vec::new() }
    }
    fn push(&mut self, s: State, what: &str, detail: impl Into<String>) {
        self.rows.push((s, what.to_string(), detail.into()));
    }
    fn failures(&self) -> usize {
        self.rows.iter().filter(|r| r.0 == State::Fail).count()
    }
    fn print(&self) {
        let w = self.rows.iter().map(|r| r.1.len()).max().unwrap_or(0);
        for (s, what, detail) in &self.rows {
            println!("{}  {:<w$}  {}", s.mark(), what, detail, w = w);
        }
        let f = self.failures();
        println!();
        if f == 0 {
            println!("Everything this deployment depends on answered.");
        } else {
            println!(
                "{f} check(s) failed. The pipeline cannot complete an intent until these are fixed."
            );
        }
    }
}

/// Describe a secret without revealing it. Length catches the usual mistakes on its own.
fn secret_shape(v: Option<&String>) -> String {
    match v {
        None => "not set".into(),
        Some(s) if s.trim().is_empty() => "set but empty".into(),
        Some(s) => {
            let trimmed = s.trim_end_matches(['\n', '\r']);
            if trimmed.len() != s.len() {
                format!(
                    "set, {} chars, but ends in a newline (usually a bad paste)",
                    s.len()
                )
            } else {
                format!("set, {} chars", s.len())
            }
        }
    }
}

/// Ask the Anthropic API for one token from `model`, and report whatever it says back.
async fn check_model(http: &reqwest::Client, key: &str, model: &str, label: &str, r: &mut Report) {
    let body = json!({
        "model": model,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}],
    });
    let resp = http
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await;
    match resp {
        Err(e) => r.push(
            State::Fail,
            label,
            format!("{model}: could not connect: {e}"),
        ),
        Ok(raw) => {
            let status = raw.status();
            let text = raw.text().await.unwrap_or_default();
            if status.is_success() {
                r.push(State::Ok, label, format!("{model} answered"));
                return;
            }
            let (msg, hint) = explain_api_error(status.as_u16(), &text);
            r.push(
                State::Fail,
                label,
                format!("{model}: HTTP {status}: {msg}{hint}"),
            );
        }
    }
}

/// Turn an Anthropic error response into the sentence the API actually sent, plus a hint when the
/// cause is one of the three that account for nearly every failure.
///
/// Split out from the request so it can be tested without a network: this is the exact path that
/// produced a bare "400 Bad Request" for the first contributor who tried to use this deployment,
/// and the whole value of `doctor` is that it never does that again.
fn explain_api_error(status: u16, body: &str) -> (String, &'static str) {
    let msg = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(String::from))
        .unwrap_or_else(|| body.chars().take(200).collect());
    let lower = msg.to_lowercase();
    let hint = if lower.contains("credit balance") {
        "  -> add credits at console.anthropic.com -> Billing"
    } else if status == 401 {
        "  -> the key is wrong or revoked"
    } else if lower.contains("model") {
        "  -> this account may not have access to that model; see agent.toml"
    } else {
        ""
    };
    (msg, hint)
}

pub async fn run(cfg: &Config) -> anyhow::Result<i32> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let mut r = Report::new();

    // ---- Postgres ----
    match sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&cfg.database_url)
        .await
    {
        Err(e) => r.push(State::Fail, "database", format!("cannot connect: {e}")),
        Ok(pool) => {
            r.push(State::Ok, "database", "connected");
            // A deployment running older migrations than its binary is the quiet failure that
            // looks like a bug in the code, so name the gap rather than the count.
            match sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM _sqlx_migrations WHERE success",
            )
            .fetch_one(&pool)
            .await
            {
                Ok(applied) => {
                    let shipped = std::fs::read_dir(
                        std::env::var("TRAILHEAD_MIGRATIONS").unwrap_or("migrations".into()),
                    )
                    .map(|d| d.filter_map(|e| e.ok()).count() as i64)
                    .unwrap_or(-1);
                    if shipped < 0 {
                        r.push(State::Ok, "migrations", format!("{applied} applied"));
                    } else if applied >= shipped {
                        r.push(
                            State::Ok,
                            "migrations",
                            format!("{applied} applied, up to date"),
                        );
                    } else {
                        r.push(
                            State::Fail,
                            "migrations",
                            format!("{applied} applied but {shipped} shipped: the database is behind this binary"),
                        );
                    }
                }
                Err(e) => r.push(State::Fail, "migrations", format!("cannot read: {e}")),
            }
            // The ledger is the project's central claim; a broken chain is worth knowing early.
            match sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events")
                .fetch_one(&pool)
                .await
            {
                Ok(n) => r.push(State::Ok, "ledger", format!("{n} event(s)")),
                Err(e) => r.push(State::Fail, "ledger", format!("cannot read events: {e}")),
            }
        }
    }

    // ---- Anthropic ----
    r.push(
        if cfg.anthropic_api_key.is_some() {
            State::Ok
        } else {
            State::Fail
        },
        "anthropic key",
        secret_shape(cfg.anthropic_api_key.as_ref()),
    );
    if let Some(key) = &cfg.anthropic_api_key {
        // Both models are checked: the interviewer and the generator can be different models,
        // and an account with access to one may not have access to the other.
        check_model(&http, key, &cfg.agent.chat.model_id, "  chat model", &mut r).await;
        check_model(
            &http,
            key,
            &cfg.agent.generation.model_id,
            "  generation model",
            &mut r,
        )
        .await;
    } else {
        r.push(
            State::Skip,
            "  models",
            "no key, so the interviewer falls back to the offline script",
        );
    }

    // ---- GitHub App ----
    let gh_configured = cfg.github_app_id.is_some() && cfg.github_app_key_pem.is_some();
    if !gh_configured {
        r.push(
            State::Warn,
            "github app",
            "not configured: gates are simulated and no commit is ever signed",
        );
    } else {
        let gh = crate::github::GitHub { cfg, http: &http };
        match gh.repo_check(&cfg.target_repo).await {
            // Reaching the repository is the easy half. The run ends by pushing a signed commit,
            // so without push this fails *after* the inference has been paid for and every gate
            // has run — the most expensive possible moment to discover a permission.
            Ok(perms) if perms.can_commit() => r.push(
                State::Ok,
                "github app",
                format!("can reach and push to {} ({perms})", cfg.target_repo),
            ),
            Ok(perms) => r.push(
                State::Fail,
                "github app",
                format!(
                    "can reach {} but cannot push ({perms}) \
                     -> give the installation Contents: read and write at \
                     github.com/settings/installations, then re-run",
                    cfg.target_repo
                ),
            ),
            Err(e) => r.push(
                State::Fail,
                "github app",
                format!("cannot reach {}: {e}", cfg.target_repo),
            ),
        }
    }

    // ---- the rest of the configuration ----
    r.push(
        if cfg.ledger_key_hex.is_some() {
            State::Ok
        } else {
            State::Warn
        },
        "ledger key",
        match cfg.ledger_key_hex.as_ref() {
            Some(k) => secret_shape(Some(k)),
            None => "not set: a generated key is stored in the database instead".into(),
        },
    );
    r.push(
        if cfg.webhook_secret.is_some() {
            State::Ok
        } else if gh_configured {
            State::Fail
        } else {
            State::Skip
        },
        "webhook secret",
        secret_shape(cfg.webhook_secret.as_ref()),
    );
    r.push(
        State::Ok,
        "target repo",
        format!(
            "{} (workspace {})",
            cfg.target_repo,
            if cfg.workspace_dir == "." {
                "repo root"
            } else {
                &cfg.workspace_dir
            }
        ),
    );
    r.push(
        if cfg.governor_ids.is_empty() && cfg.bootstrap_governors.is_empty() {
            State::Fail
        } else {
            State::Ok
        },
        "governors",
        if cfg.governor_ids.is_empty() && cfg.bootstrap_governors.is_empty() {
            "none set: nothing could ever be merged".to_string()
        } else {
            format!(
                "{} id(s), {} login(s)",
                cfg.governor_ids.len(),
                cfg.bootstrap_governors.len()
            )
        },
    );

    let mut notes = String::new();
    if cfg.dev_login {
        let _ = writeln!(
            notes,
            "note: TRAILHEAD_DEV_LOGIN is on — anyone can sign in as anyone. Never set this in production."
        );
    }
    if !cfg.enforce_window {
        let _ = writeln!(
            notes,
            "note: the weekly train window is not enforced; intents can be submitted at any time."
        );
    }

    r.print();
    if !notes.is_empty() {
        println!();
        print!("{notes}");
    }
    Ok(r.failures() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure that started all of this: a 400 whose body explains itself perfectly well.
    #[test]
    fn a_low_balance_is_reported_in_the_api_s_own_words() {
        let body = r#"{"type":"error","error":{"type":"invalid_request_error",
            "message":"Your credit balance is too low to access the Anthropic API."}}"#;
        let (msg, hint) = explain_api_error(400, body);
        assert!(msg.contains("credit balance is too low"));
        assert!(hint.contains("Billing"));
    }

    #[test]
    fn a_bad_key_says_so() {
        let body = r#"{"error":{"message":"invalid x-api-key"}}"#;
        let (msg, hint) = explain_api_error(401, body);
        assert_eq!(msg, "invalid x-api-key");
        assert!(hint.contains("revoked"));
    }

    #[test]
    fn an_unknown_model_points_at_agent_toml() {
        let body = r#"{"error":{"message":"model: claude-nonexistent-1 not found"}}"#;
        let (_, hint) = explain_api_error(404, body);
        assert!(hint.contains("agent.toml"));
    }

    /// A proxy or gateway can answer with HTML. Showing a prefix of it beats showing nothing.
    #[test]
    fn a_non_json_body_is_still_shown() {
        let (msg, hint) = explain_api_error(502, "<html><body>Bad Gateway</body></html>");
        assert!(msg.contains("Bad Gateway"));
        assert_eq!(hint, "");
    }

    #[test]
    fn a_very_long_body_is_truncated_rather_than_dumped() {
        let (msg, _) = explain_api_error(500, &"x".repeat(5000));
        assert_eq!(msg.chars().count(), 200);
    }

    /// Keys must never be printed, and the mistakes that matter are all visible in the length.
    #[test]
    fn a_secret_is_described_never_revealed() {
        let key = "sk-ant-super-secret-value".to_string();
        let shape = secret_shape(Some(&key));
        assert!(!shape.contains("super-secret"));
        assert!(shape.contains("25 chars"));
        assert_eq!(secret_shape(None), "not set");
        assert_eq!(secret_shape(Some(&"   ".to_string())), "set but empty");
        let pasted = "sk-ant-abc\n".to_string();
        assert!(secret_shape(Some(&pasted)).contains("newline"));
    }
}
