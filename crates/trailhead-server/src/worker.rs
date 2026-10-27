//! The pipeline worker: a Postgres job queue (`FOR UPDATE SKIP LOCKED`) that moves intents
//! through guardrails → generation → signed commit → gates, plus the weekly-train clock and the
//! governor's decisions. Every step writes to the public ledger in the same transaction.

use chrono::Utc;
use serde_json::{json, Value};
use std::time::Duration;
use trailhead_core::credits::EntryKind;
use trailhead_core::diffpolicy::{FileChange, Manifest, Outcome};
use trailhead_core::guardrails::{self, Risk};
use trailhead_core::provenance::{self, sha256_hex};
use trailhead_core::spec::Spec;
use trailhead_core::train;

use crate::api::AppState;
use crate::db::{self, IntentRow};
use crate::github::GitHub;
use crate::sandbox;

pub const DIFF_POLICY: &str = include_str!("../../../gates/diff-policy.toml");
/// Every check that must report green, from GitHub Actions, before the governor sees an intent.
/// Names match the job names in gates/.github/workflows. Perf and AI review are advisory inputs.
pub const EXPECTED_CHECKS: [(&str, &str); 6] = [
    ("tests", "gate-tests / static"),
    ("tests", "gate-tests / nextest"),
    ("tests", "gate-tests / coverage"),
    ("tests", "gate-tests / mutants"),
    ("diff-policy", "gate-diff-policy / policy"),
    ("attestation", "gate-attestation / verify"),
];

pub async fn run(st: AppState) {
    let mut last_tick = std::time::Instant::now() - Duration::from_secs(60);
    loop {
        if last_tick.elapsed() >= Duration::from_secs(30) {
            if let Err(e) = tick(&st).await {
                tracing::error!("train tick failed: {e:#}");
            }
            last_tick = std::time::Instant::now();
        }
        match run_one(&st).await {
            Ok(true) => continue,
            Ok(false) => tokio::time::sleep(Duration::from_millis(500)).await,
            Err(e) => {
                tracing::error!("worker error: {e:#}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// (id, kind, intent_id, attempts, created_at)
type JobRow = (i64, String, Option<i64>, i32, chrono::DateTime<Utc>);

/// Claim and run one job. Returns false when the queue is empty.
pub async fn run_one(st: &AppState) -> anyhow::Result<bool> {
    sqlx::query("UPDATE jobs SET state = 'queued', locked_at = NULL WHERE state = 'running' AND locked_at < now() - interval '1 hour'")
        .execute(&st.pool)
        .await?;
    let job: Option<JobRow> = sqlx::query_as(
        "UPDATE jobs SET state = 'running', locked_at = now(), attempts = attempts + 1
         WHERE id = (SELECT id FROM jobs WHERE state = 'queued' AND run_after <= now()
                     ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
         RETURNING id, kind, intent_id, attempts, created_at",
    )
    .fetch_optional(&st.pool)
    .await?;
    let Some((id, kind, intent_id, attempts, job_created)) = job else {
        return Ok(false);
    };
    let result = match (kind.as_str(), intent_id) {
        ("guardrails", Some(i)) => guardrails_job(st, i).await,
        ("generate", Some(i)) => generate_job(st, i).await,
        ("merge", Some(i)) => merge_job(st, i, job_created).await,
        _ => Err(anyhow::anyhow!("unknown job {kind}")),
    };
    match result {
        Ok(Retry::No) => {
            sqlx::query("UPDATE jobs SET state = 'done' WHERE id = $1")
                .bind(id)
                .execute(&st.pool)
                .await?;
        }
        Ok(Retry::After(secs)) => {
            sqlx::query("UPDATE jobs SET state = 'queued', attempts = attempts - 1, run_after = now() + make_interval(secs => $2) WHERE id = $1")
                .bind(id)
                .bind(secs as f64)
                .execute(&st.pool)
                .await?;
        }
        Err(e) => {
            let msg = format!("{e:#}");
            tracing::warn!("job {id} {kind} failed (attempt {attempts}): {msg}");
            let final_fail = attempts >= 3;
            sqlx::query(
                "UPDATE jobs SET state = $2, last_error = $3, run_after = now() + make_interval(secs => $4) WHERE id = $1",
            )
            .bind(id)
            .bind(if final_fail { "failed" } else { "queued" })
            .bind(&msg)
            .bind(30.0 * attempts as f64)
            .execute(&st.pool)
            .await?;
            if final_fail {
                let mut tx = st.pool.begin().await?;
                db::append_event(
                    &mut tx,
                    "job.failed",
                    intent_id,
                    "worker",
                    json!({"job": kind, "error": msg}),
                )
                .await?;
                if let Some(i) = intent_id {
                    db::transition_from(
                        &mut tx,
                        i,
                        &["guardrails", "generating", "gates"],
                        "flagged",
                        4,
                        "worker",
                        json!({"reason": "pipeline job failed", "job": kind}),
                    )
                    .await?;
                }
                tx.commit().await?;
            }
        }
    }
    Ok(true)
}

pub enum Retry {
    No,
    After(u64),
}

async fn kill_switch_on(st: &AppState) -> anyhow::Result<bool> {
    Ok(db::setting(&st.pool, "kill_switch").await?.as_deref() == Some("on"))
}

/// Credits spent on generation today, across everyone (the global circuit breaker).
pub async fn spent_today(st: &AppState) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(sum((payload->>'cost_credits')::bigint), 0)::bigint FROM events
         WHERE kind = 'generation.result' AND ts > date_trunc('day', now())",
    )
    .fetch_one(&st.pool)
    .await?)
}

async fn guardrails_job(st: &AppState, id: i64) -> anyhow::Result<Retry> {
    let Some(it) = db::intent(&st.pool, id).await? else {
        return Ok(Retry::No);
    };
    if it.status != "guardrails" {
        return Ok(Retry::No);
    }
    let msgs: Vec<(String,)> =
        sqlx::query_as("SELECT body FROM intent_messages WHERE intent_id = $1 AND role = 'user'")
            .bind(id)
            .fetch_all(&st.pool)
            .await?;
    // Judge only what the contributor said: the interviewer's own questions live in the
    // clarification log and would otherwise trip rules like "storage format".
    let mut spec_v = it.spec.clone();
    if let Some(o) = spec_v.as_object_mut() {
        o.remove("clarification_log");
    }
    let mut text = format!("{}\n{}\n{}", it.title, it.intent, spec_v);
    for (b,) in msgs {
        text.push('\n');
        text.push_str(&b);
    }
    let verdict = st.guardrails.evaluate(&text);
    let gate_verdict = match verdict.risk {
        Risk::Green => "pass",
        Risk::Amber => "warn",
        Risk::Red => "block",
    };
    let mut tx = st.pool.begin().await?;
    // Re-check under the row lock: a governor may have rejected or held it meanwhile.
    match db::lock_intent(&mut tx, id).await? {
        Some(cur) if cur.status == "guardrails" => {}
        _ => return Ok(Retry::No),
    }
    sqlx::query("UPDATE intents SET risk = $2 WHERE id = $1")
        .bind(id)
        .bind(verdict.risk.as_str())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO gate_results (intent_id, gate, verdict, detail) VALUES ($1,'guardrails',$2,$3)")
        .bind(id)
        .bind(gate_verdict)
        .bind(summary_hits(&verdict))
        .execute(&mut *tx)
        .await?;
    db::append_event(
        &mut tx,
        "guardrails.verdict",
        Some(id),
        "guardrails",
        serde_json::to_value(&verdict)?,
    )
    .await?;
    match verdict.risk {
        Risk::Red => {
            db::transition(
                &mut tx,
                id,
                "held",
                3,
                "guardrails",
                json!({"reason": "red guardrail: a human must look first"}),
            )
            .await?;
        }
        _ => {
            db::transition(
                &mut tx,
                id,
                "generating",
                4,
                "guardrails",
                json!({"risk": verdict.risk.as_str()}),
            )
            .await?;
            db::enqueue(&mut tx, "generate", Some(id)).await?;
        }
    }
    tx.commit().await?;
    Ok(Retry::No)
}

fn summary_hits(v: &guardrails::Verdict) -> String {
    if v.hits.is_empty() {
        return "no rule matched".into();
    }
    v.hits
        .iter()
        .map(|h| format!("{} ({}): {}", h.rule, h.level.as_str(), h.message))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Turn a unified diff into the manifest the diff-policy gate reads.
pub fn manifest_from_patch(base: &str, patch: &str) -> Manifest {
    let mut files: Vec<FileChange> = Vec::new();
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            let path = rest.split(" b/").nth(1).unwrap_or(rest).to_string();
            files.push(FileChange {
                path,
                status: "modified".into(),
                ..Default::default()
            });
            continue;
        }
        let Some(f) = files.last_mut() else { continue };
        if line.starts_with("new file mode") {
            f.status = "added".into();
        } else if line.starts_with("deleted file mode") {
            f.status = "deleted".into();
        } else if line.starts_with("rename to ") {
            f.status = "renamed".into();
        } else if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            f.binary = true;
        } else if let Some(added) = line.strip_prefix('+') {
            if !line.starts_with("+++") {
                f.added_lines.push(added.to_string());
            }
        } else if let Some(removed) = line.strip_prefix('-') {
            // Removed lines matter as much as added ones: deleting an fsync, an authorization
            // check or a quorum guard is sabotage that adds nothing. See diffpolicy::Kind.
            if !line.starts_with("---") {
                f.removed_lines.push(removed.to_string());
            }
        }
    }
    Manifest {
        base: base.into(),
        head: "bundle".into(),
        files,
    }
}

async fn generate_job(st: &AppState, id: i64) -> anyhow::Result<Retry> {
    let Some(it) = db::intent(&st.pool, id).await? else {
        return Ok(Retry::No);
    };
    if it.status != "generating" {
        return Ok(Retry::No);
    }
    if kill_switch_on(st).await? {
        return Ok(Retry::After(600));
    }
    if spent_today(st).await? >= st.cfg.daily_budget_credits {
        let mut tx = st.pool.begin().await?;
        db::append_event(
            &mut tx,
            "budget.breaker",
            Some(id),
            "worker",
            json!({"daily_budget_credits": st.cfg.daily_budget_credits}),
        )
        .await?;
        tx.commit().await?;
        return Ok(Retry::After(3600));
    }
    let spec: Spec = serde_json::from_value(it.spec.clone())?;
    let spec_bytes = serde_json::to_vec(&trailhead_core::ledger::canonical(&it.spec))?;

    // Log the exact prompt before the model runs, so the record exists even if the run dies.
    {
        let mut tx = st.pool.begin().await?;
        db::append_event(
            &mut tx,
            "generation.prompt",
            Some(id),
            "backend",
            json!({"model_id": st.cfg.agent.generation.model_id, "harness": st.cfg.agent.generation.harness,
                   "prompt": sandbox::generation_prompt(id, &spec, &st.cfg.target_repo, &st.cfg.workspace_dir), "spec_hash": sha256_hex(&spec_bytes)}),
        )
        .await?;
        tx.commit().await?;
    }

    let g = sandbox::generate(&st.cfg, id, &spec).await?;
    let patch_text = String::from_utf8_lossy(&g.patch).to_string();
    let patch_sha = sha256_hex(&g.patch);
    let guard_report: Option<(String,)> =
        sqlx::query_as("SELECT detail FROM gate_results WHERE intent_id = $1 AND gate = 'guardrails' ORDER BY id DESC LIMIT 1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let gen = provenance::Generation {
        intent_id: id,
        model_id: st.cfg.agent.generation.model_id.clone(),
        harness: st.cfg.agent.generation.harness.clone(),
        spec_hash: sha256_hex(&spec_bytes),
        prompt_log_hash: sha256_hex(&g.transcript),
        sandbox_run_id: g.run_id.clone(),
        sandbox_image: g.image.clone(),
        guardrail_report_hash: sha256_hex(guard_report.map(|r| r.0).unwrap_or_default().as_bytes()),
        parent_commit: g.base.clone(),
        pipeline_commit: option_env!("TRAILHEAD_GIT_SHA")
            .unwrap_or("dev")
            .to_string(),
        terms_version: st.cfg.agent.generation.terms_version.clone(),
        started_at: g.started_at.clone(),
        finished_at: g.finished_at.clone(),
        cost_credits: g.cost_credits,
    };
    let title = spec.title.clone().unwrap_or_else(|| it.title.clone());
    let message = format!(
        "{}: {}\n\nTrailhead intent #{id}, generated by the pinned model from a public spec.\n\n{}",
        spec.change_type.clone().unwrap_or_else(|| "feat".into()),
        title,
        provenance::trailers(&gen, &st.cfg.public_url)
    );
    let manifest = manifest_from_patch(&g.base, &patch_text);
    let dp = st.diff_policy.check(&manifest);

    const MAX_INLINE: usize = 256 * 1024;
    let transcript_inline = (g.transcript.len() <= MAX_INLINE)
        .then(|| String::from_utf8_lossy(&g.transcript).to_string());

    let mut tx = st.pool.begin().await?;
    // Re-check under the row lock: if a governor rejected or held the intent while the model ran,
    // the result is recorded but goes nowhere (no bundle, no commit, no charge beyond what ran).
    let still_generating =
        matches!(db::lock_intent(&mut tx, id).await?, Some(cur) if cur.status == "generating");
    let ev = db::append_event(
        &mut tx,
        "generation.result",
        Some(id),
        "backend",
        json!({"run_id": g.run_id, "base": g.base, "patch_sha256": patch_sha, "patch_bytes": g.patch.len(),
               "transcript_sha256": gen.prompt_log_hash, "transcript": transcript_inline,
               "cost_credits": g.cost_credits, "discarded": !still_generating,
               "files": manifest.files.iter().map(|f| &f.path).collect::<Vec<_>>()}),
    )
    .await?;

    // Who pays: the author's own balance first, then the community pool for any shortfall.
    let owed = g.cost_credits.max(0);

    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(it.author_id)
        .execute(&mut *tx)
        .await?;
    let bal = db::balance_tx(&mut tx, it.author_id).await?;
    let from_author = owed.min(bal.max(0));
    db::add_credits(
        &mut tx,
        it.author_id,
        EntryKind::Spend,
        from_author,
        Some(id),
        "generation",
    )
    .await?;
    // The community pool covers any shortfall. It books a real ledger entry rather than only
    // an event, so "money in equals money out" can be checked for the community account too.
    let from_community = (owed - from_author).max(0);
    if from_community > 0 {
        db::add_credits(
            &mut tx,
            it.author_id,
            EntryKind::CommunitySpend,
            from_community,
            Some(id),
            "community pool covered the shortfall",
        )
        .await?;
        db::append_event(
            &mut tx,
            "pool.spend",
            Some(id),
            "backend",
            json!({"credits": from_community, "from_author": from_author}),
        )
        .await?;
    }
    if !still_generating {
        tx.commit().await?;
        return Ok(Retry::No);
    }

    sqlx::query(
        "INSERT INTO bundles (intent_id, base, patch, patch_sha256, message, provenance, ledger_seq)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (intent_id) DO UPDATE SET base = EXCLUDED.base, patch = EXCLUDED.patch,
           patch_sha256 = EXCLUDED.patch_sha256, message = EXCLUDED.message, provenance = EXCLUDED.provenance,
           ledger_seq = EXCLUDED.ledger_seq, created_at = now()",
    )
    .bind(id)
    .bind(&g.base)
    .bind(&g.patch)
    .bind(&patch_sha)
    .bind(&message)
    .bind(serde_json::to_value(&gen)?)
    .bind(ev.seq)
    .execute(&mut *tx)
    .await?;

    sqlx::query("INSERT INTO gate_results (intent_id, gate, verdict, detail) VALUES ($1,'diff-policy (pre-check)',$2,$3)")
        .bind(id)
        .bind(match dp.verdict {
            Outcome::Pass => "pass",
            Outcome::Warn => "warn",
            Outcome::Block => "block",
        })
        .bind(serde_json::to_string(&dp)?)
        .execute(&mut *tx)
        .await?;
    db::append_event(
        &mut tx,
        "gate.diff-policy.precheck",
        Some(id),
        "diff-policy",
        serde_json::to_value(&dp)?,
    )
    .await?;

    if dp.verdict == Outcome::Block {
        db::transition(
            &mut tx,
            id,
            "flagged",
            7,
            "diff-policy",
            json!({"blocked_by": dp.blocked_by}),
        )
        .await?;
        tx.commit().await?;
        return Ok(Retry::No);
    }
    db::transition(
        &mut tx,
        id,
        "gates",
        5,
        "backend",
        json!({"bundle_seq": ev.seq}),
    )
    .await?;
    tx.commit().await?;

    // A dry-run bundle has no real base commit, so it can never be signed into a repo.
    if st.cfg.github_app_configured() && g.base != "dry-run" {
        GitHub {
            cfg: &st.cfg,
            http: &st.http,
        }
        .dispatch_commit(id)
        .await?;
    } else {
        simulate_gates(st, id).await?;
    }
    Ok(Retry::No)
}

/// Without a GitHub App (local runs, tests) the repo-side gates cannot run. Record that honestly
/// as "simulated" and move on, so the rest of the pipeline can be exercised end to end.
async fn simulate_gates(st: &AppState, id: i64) -> anyhow::Result<()> {
    let mut tx = st.pool.begin().await?;
    match db::lock_intent(&mut tx, id).await? {
        Some(cur) if cur.status == "gates" => {}
        _ => return Ok(()),
    }
    sqlx::query("UPDATE intents SET branch = $2, commit_sha = 'simulated' WHERE id = $1")
        .bind(id)
        .bind(format!("trailhead/{id}"))
        .execute(&mut *tx)
        .await?;
    for (gate, check) in EXPECTED_CHECKS {
        sqlx::query(
            "INSERT INTO gate_results (intent_id, gate, check_name, verdict, detail, head_sha) VALUES ($1,$2,$3,'pass',$4,'simulated')",
        )
        .bind(id)
        .bind(gate)
        .bind(check)
        .bind("simulated: no GitHub App configured, repo gates did not run")
        .execute(&mut *tx)
        .await?;
    }
    db::append_event(
        &mut tx,
        "gates.simulated",
        Some(id),
        "worker",
        json!({"checks": EXPECTED_CHECKS.iter().map(|c| c.1).collect::<Vec<_>>()}),
    )
    .await?;
    db::transition(
        &mut tx,
        id,
        "review",
        8,
        "worker",
        json!({"note": "simulated gates"}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Map a GitHub check-run name to a Trailhead gate.
pub fn gate_for_check(name: &str) -> Option<&'static str> {
    EXPECTED_CHECKS
        .iter()
        .find(|(_, c)| *c == name)
        .map(|(g, _)| *g)
        .or_else(|| {
            let n = name.to_lowercase();
            if n.contains("perf") || n.contains("bench") {
                Some("perf")
            } else if n.contains("review") {
                Some("ai-review")
            } else {
                None
            }
        })
}

/// After a gate result arrives, move the intent to review (every expected check green) or flagged.
pub async fn evaluate_gates(st: &AppState, id: i64, head_sha: &str) -> anyhow::Result<()> {
    let mut tx = st.pool.begin().await?;
    let Some(it) = db::lock_intent(&mut tx, id).await? else {
        return Ok(());
    };
    if !matches!(it.status.as_str(), "gates" | "review")
        || it.commit_sha.as_deref() != Some(head_sha)
    {
        return Ok(());
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT ON (check_name) check_name, verdict FROM gate_results
         WHERE intent_id = $1 AND head_sha = $2 AND check_name IS NOT NULL ORDER BY check_name, id DESC",
    )
    .bind(id)
    .bind(head_sha)
    .fetch_all(&mut *tx)
    .await?;
    let verdict = |c: &str| rows.iter().find(|(n, _)| n == c).map(|(_, v)| v.as_str());
    if let Some((gate, check)) = EXPECTED_CHECKS
        .iter()
        .find(|(_, c)| verdict(c) == Some("block"))
    {
        let stage = match *gate {
            "attestation" => 5,
            "tests" => 6,
            _ => 7,
        };
        db::transition(
            &mut tx,
            id,
            "flagged",
            stage,
            "gates",
            json!({"gate": gate, "check": check, "head": head_sha}),
        )
        .await?;
    } else if EXPECTED_CHECKS
        .iter()
        .all(|(_, c)| matches!(verdict(c), Some("pass") | Some("warn")))
    {
        if it.status != "review" {
            db::transition(&mut tx, id, "review", 8, "gates", json!({"head": head_sha})).await?;
        }
    } else {
        let reported = EXPECTED_CHECKS
            .iter()
            .filter(|(_, c)| verdict(c).is_some())
            .count();
        let stage = if reported < 4 { 6 } else { 7 };
        sqlx::query("UPDATE intents SET stage = $2 WHERE id = $1")
            .bind(id)
            .bind(stage)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Weekly train transitions; safe to run any number of times.
pub async fn tick(st: &AppState) -> anyhow::Result<Value> {
    let now = Utc::now();
    let s = train::state(now);
    let mut done = Vec::new();

    // Contributor history is recomputed here and nowhere else, so nobody can trigger a
    // recompute and read the result in a loop. A failure is logged, never fatal: the score
    // degrades to Trailhead-only data rather than the tick stopping.
    let signals_refreshed =
        match crate::signals::refresh_batch(&st.pool, &st.cfg, &st.http, 25).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("signals refresh batch failed: {e}");
                0
            }
        };

    if let Some(r) = &s.review {
        if db::setting(&st.pool, "cutoff_done").await?.as_deref() != Some(r.train.as_str()) {
            let mut tx = st.pool.begin().await?;
            // Intents carried over from an earlier train return to where they were.
            let carried: Vec<IntentRow> = sqlx::query_as(
                "SELECT * FROM intents WHERE train = $1 AND status = 'on_hold' ORDER BY id FOR UPDATE",
            )
            .bind(&r.train)
            .fetch_all(&mut *tx)
            .await?;
            for it in &carried {
                let back = match it.hold_from.as_deref() {
                    Some("review") | Some("flagged") | Some("gates") => {
                        it.hold_from.clone().unwrap_or_default()
                    }
                    _ => "flagged".to_string(),
                };
                db::transition(
                    &mut tx,
                    it.id,
                    &back,
                    it.stage,
                    "clock",
                    json!({"reason": "carried into this train", "train": r.train}),
                )
                .await?;
            }
            let counts: Vec<(String, i64)> = sqlx::query_as(
                "SELECT status, count(*) FROM intents WHERE train = $1 GROUP BY status",
            )
            .bind(&r.train)
            .fetch_all(&mut *tx)
            .await?;
            db::append_event(
                &mut tx,
                "train.cutoff",
                None,
                "clock",
                json!({"train": r.train, "cutoff_pt": train::fmt_pt(r.cutoff), "decision_pt": train::fmt_pt(r.decision),
                       "carried_over": carried.len(),
                       "counts": counts.into_iter().map(|(k, v)| (k, json!(v))).collect::<serde_json::Map<_, _>>()}),
            )
            .await?;
            db::set_setting(&mut tx, "cutoff_done", &r.train).await?;
            tx.commit().await?;
            if st.cfg.github_app_configured() {
                let prs: Vec<(i64,)> = sqlx::query_as(
                    "SELECT pr_number FROM intents WHERE train = $1 AND pr_number IS NOT NULL AND status IN ('gates','review','flagged')",
                )
                .bind(&r.train)
                .fetch_all(&st.pool)
                .await?;
                let gh = GitHub {
                    cfg: &st.cfg,
                    http: &st.http,
                };
                for (pr,) in prs {
                    let _ = gh.add_labels(pr, &[format!("train/{}", r.train)]).await;
                }
            }
            done.push(format!("cutoff {}", r.train));
        }
    }

    let last = train::latest_window(now);
    if now >= last.decision
        && db::setting(&st.pool, "decision_done").await?.as_deref() != Some(last.train.as_str())
    {
        let mut tx = st.pool.begin().await?;
        let open: Vec<IntentRow> = sqlx::query_as(
            "SELECT * FROM intents WHERE train = $1
               AND status IN ('submitted','guardrails','held','generating','gates','review','flagged','on_hold')
             ORDER BY id FOR UPDATE",
        )
        .bind(&last.train)
        .fetch_all(&mut *tx)
        .await?;
        for it in &open {
            // Silence is a hold, never a merge.
            let holds = it.holds + 1;
            if holds >= train::HOLD_EXPIRY_TRAINS as i32 {
                sqlx::query("UPDATE intents SET holds = $2 WHERE id = $1")
                    .bind(it.id)
                    .bind(holds)
                    .execute(&mut *tx)
                    .await?;
                db::transition(&mut tx, it.id, "rejected", it.stage, "clock",
                    json!({"reason": format!("no decision for {holds} trains; closed, stake refunded")})).await?;
                db::add_credits(
                    &mut tx,
                    it.author_id,
                    EntryKind::StakeRefund,
                    it.stake_credits,
                    Some(it.id),
                    "stale hold: refund",
                )
                .await?;
            } else {
                sqlx::query("UPDATE intents SET holds = $2, train = $3 WHERE id = $1")
                    .bind(it.id)
                    .bind(holds)
                    .bind(&s.intake.train)
                    .execute(&mut *tx)
                    .await?;
                if it.status != "on_hold" {
                    db::transition(&mut tx, it.id, "on_hold", it.stage, "clock",
                        json!({"reason": "no decision by Friday 00:00 PT", "next_train": s.intake.train, "holds": holds})).await?;
                }
            }
        }
        db::append_event(
            &mut tx,
            "train.decided",
            None,
            "clock",
            json!({"train": last.train, "auto_held": open.len()}),
        )
        .await?;
        db::set_setting(&mut tx, "decision_done", &last.train).await?;
        tx.commit().await?;
        done.push(format!("decision {}", last.train));
    }
    Ok(
        json!({"done": done, "signals_refreshed": signals_refreshed, "intake": s.intake.train, "review": s.review.map(|r| r.train)}),
    )
}

/// Mark an intent merged: status, stake refund and reputation, in the caller's transaction.
async fn finish_merge(
    tx: &mut db::Tx<'_>,
    it: &IntentRow,
    actor: &str,
    reason: &str,
) -> anyhow::Result<()> {
    db::transition(tx, it.id, "merged", 8, actor, json!({"reason": reason})).await?;
    db::add_credits(
        tx,
        it.author_id,
        EntryKind::StakeRefund,
        it.stake_credits,
        Some(it.id),
        "merged: stake refunded",
    )
    .await?;
    sqlx::query("UPDATE users SET rep_points = rep_points + 10 WHERE id = $1")
        .bind(it.author_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// How long a decided merge may wait for GitHub's checks before it is handed back to the governor.
const MERGE_PATIENCE_MINUTES: i64 = 90;

async fn merge_job(
    st: &AppState,
    id: i64,
    job_created: chrono::DateTime<Utc>,
) -> anyhow::Result<Retry> {
    let Some(it) = db::intent(&st.pool, id).await? else {
        return Ok(Retry::No);
    };
    if it.status != "merging" {
        return Ok(Retry::No); // already merged (e.g. via the PR webhook) or changed
    }
    let pr = it
        .pr_number
        .ok_or_else(|| anyhow::anyhow!("merging intent has no PR"))?;
    let result = GitHub {
        cfg: &st.cfg,
        http: &st.http,
    }
    .merge(pr)
    .await;
    let mut tx = st.pool.begin().await?;
    let Some(cur) = db::lock_intent(&mut tx, id).await? else {
        return Ok(Retry::No);
    };
    if cur.status != "merging" {
        return Ok(Retry::No);
    }
    match result {
        Ok(()) => {
            finish_merge(
                &mut tx,
                &cur,
                "github",
                "merged after all required checks passed",
            )
            .await?;
            tx.commit().await?;
            Ok(Retry::No)
        }
        Err(e) if Utc::now() - job_created < chrono::Duration::minutes(MERGE_PATIENCE_MINUTES) => {
            tracing::info!("intent {id}: PR #{pr} not mergeable yet ({e}); retrying");
            Ok(Retry::After(60))
        }
        Err(e) => {
            db::append_event(
                &mut tx,
                "merge.failed",
                Some(id),
                "worker",
                json!({"pr": pr, "error": format!("{e:#}")}),
            )
            .await?;
            db::transition(&mut tx, id, "review", 8, "worker",
                json!({"reason": format!("GitHub would not merge within {MERGE_PATIENCE_MINUTES} minutes; back to the governor")})).await?;
            tx.commit().await?;
            Ok(Retry::No)
        }
    }
}

/// The PR merged on GitHub (normally by our merge job): settle it if the job has not yet.
pub async fn on_pr_merged(st: &AppState, id: i64) -> anyhow::Result<bool> {
    let mut tx = st.pool.begin().await?;
    let Some(cur) = db::lock_intent(&mut tx, id).await? else {
        return Ok(false);
    };
    if cur.status != "merging" {
        return Ok(false);
    }
    finish_merge(&mut tx, &cur, "github", "PR merged on GitHub").await?;
    tx.commit().await?;
    Ok(true)
}

#[derive(Debug)]
pub enum DecideError {
    Invalid(&'static str, String),
}

fn invalid(
    code: &'static str,
    msg: impl Into<String>,
) -> anyhow::Result<Result<Value, DecideError>> {
    Ok(Err(DecideError::Invalid(code, msg.into())))
}

/// Apply a governor decision. `decision` is merge | hold | reject. Everything is validated again
/// under the intent's row lock, so double clicks, two governors or a racing train tick cannot
/// produce two decisions or two refunds.
pub async fn decide(
    st: &AppState,
    intent_id: i64,
    governor_id: i64,
    governor: &str,
    decision: &str,
    reason: &str,
    spam: bool,
) -> anyhow::Result<Result<Value, DecideError>> {
    let reason = reason.trim();
    if reason.is_empty() {
        return invalid(
            "reason_required",
            "Every decision needs a written reason; it is published.",
        );
    }
    let allowed: &[&str] = match decision {
        "merge" => &["review"],
        "hold" | "reject" => &[
            "submitted",
            "guardrails",
            "held",
            "generating",
            "gates",
            "review",
            "flagged",
            "on_hold",
            "merging",
        ],
        _ => return invalid("bad_decision", "Decision must be merge, hold or reject."),
    };
    let s = train::state(Utc::now());
    let current_train = s.review.as_ref().map(|r| r.train.clone());

    let mut tx = st.pool.begin().await?;
    let Some(it) = db::lock_intent(&mut tx, intent_id).await? else {
        return invalid("not_found", "Intent not found.");
    };
    if it.author_id == governor_id {
        return invalid(
            "recuse",
            "Governors recuse from their own intents; another governor must decide.",
        );
    }
    if st.cfg.enforce_window && it.train.as_deref() != current_train.as_deref() {
        return invalid(
            "not_in_review_window",
            format!(
                "Intent is on train {}; a train is decided between its Sunday cutoff and Friday 00:00 PT (now reviewing: {}).",
                it.train.clone().unwrap_or_else(|| "none".into()),
                current_train.unwrap_or_else(|| "none".into())
            ),
        );
    }
    if !allowed.contains(&it.status.as_str()) {
        return invalid(
            if it.status == "flagged" && decision == "merge" {
                "blocked"
            } else {
                "bad_state"
            },
            if it.status == "flagged" && decision == "merge" {
                "A blocking gate failed. It cannot be merged; hold it for regeneration or reject it.".to_string()
            } else {
                format!("Cannot {decision} an intent that is {}.", it.status)
            },
        );
    }
    let train_label = it.train.clone().unwrap_or_default();
    sqlx::query("INSERT INTO decisions (intent_id, train, decision, reason, governor) VALUES ($1,$2,$3,$4,$5)")
        .bind(it.id)
        .bind(&train_label)
        .bind(decision)
        .bind(reason)
        .bind(governor)
        .execute(&mut *tx)
        .await?;
    db::append_event(
        &mut tx,
        "governor.decision",
        Some(it.id),
        governor,
        json!({"decision": decision, "reason": reason, "train": train_label, "spam": spam}),
    )
    .await?;
    let via_github = st.cfg.github_app_configured() && it.pr_number.is_some();
    match decision {
        "merge" if via_github => {
            // Record the decision now; the merge job merges once GitHub's checks (including
            // train-gate, re-run after the labels below) are green, then refunds the stake.
            db::transition(
                &mut tx,
                it.id,
                "merging",
                8,
                governor,
                json!({"reason": reason}),
            )
            .await?;
            db::enqueue(&mut tx, "merge", Some(it.id)).await?;
        }
        "merge" => finish_merge(&mut tx, &it, governor, reason).await?,
        "hold" => {
            sqlx::query("UPDATE intents SET holds = holds + 1, train = $2 WHERE id = $1")
                .bind(it.id)
                .bind(&s.intake.train)
                .execute(&mut *tx)
                .await?;
            db::transition(
                &mut tx,
                it.id,
                "on_hold",
                it.stage,
                governor,
                json!({"reason": reason, "next_train": s.intake.train}),
            )
            .await?;
        }
        _ => {
            db::transition(
                &mut tx,
                it.id,
                "rejected",
                it.stage,
                governor,
                json!({"reason": reason, "spam": spam}),
            )
            .await?;
            if spam {
                db::add_credits(
                    &mut tx,
                    it.author_id,
                    EntryKind::StakeBurn,
                    it.stake_credits,
                    Some(it.id),
                    "spam: stake burned",
                )
                .await?;
                db::append_event(
                    &mut tx,
                    "pool.fund",
                    Some(it.id),
                    "backend",
                    json!({"credits": it.stake_credits, "source": "burned stake"}),
                )
                .await?;
                let burns: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM credit_entries WHERE user_id = $1 AND kind = 'stake_burn' AND created_at > now() - interval '90 days'",
                )
                .bind(it.author_id)
                .fetch_one(&mut *tx)
                .await?;
                if burns >= 3 {
                    sqlx::query(
                        "UPDATE users SET banned_until = now() + interval '30 days' WHERE id = $1",
                    )
                    .bind(it.author_id)
                    .execute(&mut *tx)
                    .await?;
                    db::append_event(&mut tx, "user.suspended", None, "backend", json!({"user_id": it.author_id, "days": 30, "reason": "three burned stakes"})).await?;
                }
            } else {
                db::add_credits(
                    &mut tx,
                    it.author_id,
                    EntryKind::StakeRefund,
                    it.stake_credits,
                    Some(it.id),
                    "declined in good faith: stake refunded",
                )
                .await?;
            }
        }
    }
    // For a merge, the repo's train-gate check needs both labels. GitHub is called while the row lock
    // is held: if labelling fails, nothing is recorded.
    let gh = GitHub {
        cfg: &st.cfg,
        http: &st.http,
    };
    if st.cfg.github_app_configured() {
        if let Some(pr) = it.pr_number {
            if decision == "merge" {
                gh.add_labels(
                    pr,
                    &[format!("train/{train_label}"), "decision:merge".to_string()],
                )
                .await?;
            }
        }
    }
    tx.commit().await?;
    if st.cfg.github_app_configured() {
        if let Some(pr) = it.pr_number {
            let _ = gh.comment(pr, &format!("Governor decision: **{decision}**: {reason}\n\nRecorded in the public ledger.")).await;
            match decision {
                "reject" => {
                    let _ = gh.close(pr).await;
                }
                "hold" => {
                    let _ = gh.add_labels(pr, &["on-hold:review".to_string()]).await;
                }
                _ => {}
            }
        }
    }
    Ok(Ok(
        json!({"intent_id": it.id, "train": train_label, "decision": decision, "reason": reason, "governor": governor}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_diff_policy_parses() {
        assert!(trailhead_core::diffpolicy::Policy::parse(DIFF_POLICY).is_ok());
    }

    #[test]
    fn patch_to_manifest() {
        let p = "diff --git a/src/a.rs b/src/a.rs\nindex 1..2 100644\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1 +1,2 @@\n fn a() {}\n+let s = TcpStream::connect(x);\ndiff --git a/f.bin b/f.bin\nnew file mode 100644\nBinary files /dev/null and b/f.bin differ\n";
        let m = manifest_from_patch("base", p);
        assert_eq!(m.files.len(), 2);
        assert_eq!(
            m.files[0].added_lines,
            vec!["let s = TcpStream::connect(x);"]
        );
        assert!(m.files[1].binary);
        assert_eq!(m.files[1].status, "added");
    }

    #[test]
    fn patch_to_manifest_captures_removed_lines() {
        // A deletion-only patch: the `---`/`+++` headers must not be mistaken for content.
        let p = "diff --git a/src/wal.rs b/src/wal.rs\nindex 1..2 100644\n--- a/src/wal.rs\n+++ b/src/wal.rs\n@@ -1,3 +1,2 @@\n fn commit() {\n-    file.sync_all()?;\n }\n";
        let m = manifest_from_patch("base", p);
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].removed_lines, vec!["    file.sync_all()?;"]);
        assert!(m.files[0].added_lines.is_empty());
        // And the shipped policy blocks it.
        let v = trailhead_core::diffpolicy::Policy::parse(DIFF_POLICY)
            .unwrap()
            .check(&m);
        assert_eq!(
            v.verdict,
            trailhead_core::diffpolicy::Outcome::Block,
            "{v:?}"
        );
    }

    #[test]
    fn check_names_map_to_gates() {
        assert_eq!(gate_for_check("gate-tests / nextest"), Some("tests"));
        assert_eq!(
            gate_for_check("gate-diff-policy / policy"),
            Some("diff-policy")
        );
        assert_eq!(
            gate_for_check("gate-attestation / verify"),
            Some("attestation")
        );
        assert_eq!(gate_for_check("my-test-attest-thing"), None);
        assert_eq!(gate_for_check("train-gate"), None);
    }
}
