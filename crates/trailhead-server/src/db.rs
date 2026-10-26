//! Database access. Every state change that matters is mirrored into the public ledger
//! through [`append_event`], inside the same transaction as the change itself.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use trailhead_core::credits::EntryKind;
use trailhead_core::ledger;

pub type Tx<'a> = Transaction<'a, Postgres>;

#[derive(FromRow, Serialize, Clone, Debug)]
pub struct UserRow {
    pub id: i64,
    pub github_id: Option<i64>,
    pub login: String,
    pub account_created_at: DateTime<Utc>,
    pub verified_org_domain: Option<String>,
    pub is_governor: bool,
    pub rep_points: i64,
    pub banned_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize, Clone, Debug)]
pub struct IntentRow {
    pub id: i64,
    pub title: String,
    pub area: String,
    pub author_id: i64,
    pub intent: String,
    pub status: String,
    pub stage: i32,
    pub stake_credits: i64,
    pub change_type: Option<String>,
    pub risk: Option<String>,
    pub spec: Value,
    pub train: Option<String>,
    pub holds: i32,
    pub hold_from: Option<String>,
    pub branch: Option<String>,
    pub pr_number: Option<i64>,
    pub commit_sha: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize, Clone, Debug)]
pub struct EventRow {
    pub seq: i64,
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub intent_id: Option<i64>,
    pub actor: String,
    pub payload: Value,
    pub prev_hash: String,
    pub hash: String,
}

impl From<EventRow> for ledger::Event {
    fn from(r: EventRow) -> Self {
        ledger::Event {
            seq: r.seq,
            ts: r.ts,
            kind: r.kind,
            intent_id: r.intent_id,
            actor: r.actor,
            payload: r.payload,
            prev_hash: r.prev_hash,
            hash: r.hash,
        }
    }
}

/// Append one event to the public ledger. A transaction-scoped advisory lock serialises writers so
/// sequence numbers and the hash chain never fork.
pub async fn append_event(
    tx: &mut Tx<'_>,
    kind: &str,
    intent_id: Option<i64>,
    actor: &str,
    payload: Value,
) -> anyhow::Result<EventRow> {
    sqlx::query("SELECT pg_advisory_xact_lock(7461)")
        .execute(&mut **tx)
        .await?;
    let last: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut **tx)
            .await?;
    let (seq, prev) = match last {
        Some((s, h)) => (s + 1, h),
        None => (1, ledger::GENESIS.to_string()),
    };
    let ts = ledger::trunc_micros(Utc::now());
    let hash = ledger::compute_hash(&prev, seq, &ts, kind, intent_id, actor, &payload);
    let row = sqlx::query_as::<_, EventRow>(
        "INSERT INTO events (seq, ts, kind, intent_id, actor, payload, prev_hash, hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
    )
    .bind(seq)
    .bind(ts)
    .bind(kind)
    .bind(intent_id)
    .bind(actor)
    .bind(&payload)
    .bind(&prev)
    .bind(&hash)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row)
}

pub async fn add_credits(
    tx: &mut Tx<'_>,
    user_id: i64,
    kind: EntryKind,
    credits: i64,
    intent_id: Option<i64>,
    memo: &str,
) -> anyhow::Result<()> {
    if credits == 0 && kind != EntryKind::Spend {
        return Ok(());
    }
    sqlx::query("INSERT INTO credit_entries (user_id, kind, credits, intent_id, memo) VALUES ($1,$2,$3,$4,$5)")
        .bind(user_id)
        .bind(kind.as_str())
        .bind(credits)
        .bind(intent_id)
        .bind(memo)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn balance(pool: &PgPool, user_id: i64) -> anyhow::Result<i64> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT kind, credits FROM credit_entries WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    let entries: Vec<(EntryKind, i64)> = rows
        .into_iter()
        .filter_map(|(k, c)| EntryKind::parse(&k).map(|k| (k, c)))
        .collect();
    Ok(trailhead_core::credits::balance(&entries))
}

pub async fn intent(pool: &PgPool, id: i64) -> anyhow::Result<Option<IntentRow>> {
    Ok(
        sqlx::query_as::<_, IntentRow>("SELECT * FROM intents WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn setting(pool: &PgPool, key: &str) -> anyhow::Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT value FROM settings WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn set_setting(tx: &mut Tx<'_>, key: &str, value: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(key)
        .bind(value)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn enqueue(tx: &mut Tx<'_>, kind: &str, intent_id: Option<i64>) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO jobs (kind, intent_id) VALUES ($1,$2)")
        .bind(kind)
        .bind(intent_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Lock an intent row for the rest of the transaction. Always take this BEFORE appending to the ledger
/// (the ledger lock is taken second everywhere, so the two can never deadlock).
pub async fn lock_intent(tx: &mut Tx<'_>, id: i64) -> anyhow::Result<Option<IntentRow>> {
    Ok(
        sqlx::query_as::<_, IntentRow>("SELECT * FROM intents WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?,
    )
}

/// Set status and stage, and log the transition publicly. Unconditional: callers must hold the row
/// lock and have checked the current status (see [`transition_from`]).
pub async fn transition(
    tx: &mut Tx<'_>,
    intent_id: i64,
    status: &str,
    stage: i32,
    actor: &str,
    detail: Value,
) -> anyhow::Result<()> {
    let prev: (String,) = sqlx::query_as("SELECT status FROM intents WHERE id = $1 FOR UPDATE")
        .bind(intent_id)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE intents SET status = $2, stage = $3, updated_at = now(),
                hold_from = CASE WHEN $2 = 'on_hold' THEN status ELSE hold_from END
         WHERE id = $1",
    )
    .bind(intent_id)
    .bind(status)
    .bind(stage)
    .execute(&mut **tx)
    .await?;
    append_event(
        tx,
        "status",
        Some(intent_id),
        actor,
        serde_json::json!({"from": prev.0, "to": status, "stage": stage, "detail": detail}),
    )
    .await?;
    Ok(())
}

/// Transition only if the intent is currently in one of `from`. Returns false (and changes nothing)
/// otherwise, so a job that started before a governor decision cannot undo it.
pub async fn transition_from(
    tx: &mut Tx<'_>,
    intent_id: i64,
    from: &[&str],
    status: &str,
    stage: i32,
    actor: &str,
    detail: Value,
) -> anyhow::Result<bool> {
    let Some(cur) = lock_intent(tx, intent_id).await? else {
        return Ok(false);
    };
    if !from.contains(&cur.status.as_str()) {
        return Ok(false);
    }
    transition(tx, intent_id, status, stage, actor, detail).await?;
    Ok(true)
}

/// Spendable balance inside a transaction (call after locking the user row).
pub async fn balance_tx(tx: &mut Tx<'_>, user_id: i64) -> anyhow::Result<i64> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT kind, credits FROM credit_entries WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await?;
    let entries: Vec<(EntryKind, i64)> = rows
        .into_iter()
        .filter_map(|(k, c)| EntryKind::parse(&k).map(|k| (k, c)))
        .collect();
    Ok(trailhead_core::credits::balance(&entries))
}

/// Grant this month's free credits for the user's tier, once per calendar month.
pub async fn ensure_monthly_grant(pool: &PgPool, user_id: i64, monthly: i64) -> anyhow::Result<()> {
    let period = Utc::now().format("%Y-%m").to_string();
    sqlx::query(
        "INSERT INTO credit_entries (user_id, kind, credits, memo, period)
         VALUES ($1, 'grant', $2, 'monthly free inference', $3)
         ON CONFLICT (user_id, period) WHERE kind = 'grant' DO NOTHING",
    )
    .bind(user_id)
    .bind(monthly)
    .bind(period)
    .execute(pool)
    .await?;
    Ok(())
}
