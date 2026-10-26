//! Sponsor pools: an organisation funds the inference for a feature it needs, and any
//! contributor can then build that feature without paying for it themselves.
//!
//! The one rule that shapes everything here: **a pool decides who pays, never what ships or
//! when**. `priority::Inputs` has no monetary field, nothing in this module writes to the
//! priority tables, and a test asserts that a funded and an unfunded intent score identically.
//!
//! The money rules come from watching comparable systems fail:
//! - **All-or-nothing.** If the goal is not met by the deadline, nobody is charged. A
//!   half-funded feature just strands inference.
//! - **Unclaimed money is never the operator's.** Bountysource changed its terms to keep
//!   unclaimed bounties and went bankrupt owing contributors. Leftovers are refunded, or swept
//!   to the community pool only when the sponsor chose that in advance.
//! - **Only gate-passing runs on the linked intent may draw**, so an agent flood cannot drain
//!   a pool the way it drained open bounty programmes.
//! - **No self-approval.** A sponsor may not review or decide work their own pool funded.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use trailhead_core::credits::{self, EntryKind, PoolStatus};

use crate::db::{self, Tx};

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct PoolRow {
    pub id: i64,
    pub title: String,
    pub scope: String,
    pub intent_id: Option<i64>,
    pub goal_credits: i64,
    pub per_intent_cap: i64,
    pub deadline: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub created_by: i64,
    #[allow(dead_code)] // read by the public pool page via the API's own query
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Serialize, Clone, Debug, Default)]
pub struct Balances {
    pub pledged: i64,
    pub drawn: i64,
    pub refunded: i64,
    pub swept: i64,
    pub held: i64,
}

pub async fn get(pool: &PgPool, id: i64) -> anyhow::Result<Option<PoolRow>> {
    Ok(
        sqlx::query_as::<_, PoolRow>("SELECT * FROM sponsor_pools WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn balances(pool: &PgPool, id: i64) -> anyhow::Result<Balances> {
    Ok(sqlx::query_as::<_, Balances>(
        "SELECT pledged, drawn, refunded, swept, held FROM pool_balances WHERE pool_id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .unwrap_or_default())
}

/// Row-lock a pool so two concurrent generation runs cannot both draw the last credits.
pub async fn lock(tx: &mut Tx<'_>, id: i64) -> anyhow::Result<Option<PoolRow>> {
    Ok(
        sqlx::query_as::<_, PoolRow>("SELECT * FROM sponsor_pools WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?,
    )
}

async fn held_tx(tx: &mut Tx<'_>, id: i64) -> anyhow::Result<i64> {
    let held: Option<i64> = sqlx::query_scalar("SELECT held FROM pool_balances WHERE pool_id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(held.unwrap_or(0))
}

/// The pool linked to this intent that is currently allowed to pay, if any.
pub async fn active_for_intent(tx: &mut Tx<'_>, intent_id: i64) -> anyhow::Result<Option<PoolRow>> {
    let row = sqlx::query_as::<_, PoolRow>(
        "SELECT * FROM sponsor_pools WHERE intent_id = $1 AND status = 'active'
         ORDER BY id LIMIT 1 FOR UPDATE",
    )
    .bind(intent_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.filter(|p| {
        PoolStatus::parse(&p.status)
            .map(|s| s.can_draw())
            .unwrap_or(false)
    }))
}

/// Draw up to `cost` from the pool linked to `intent_id`, bounded by what it still holds and
/// by its per-run cap. Returns what the pool paid; the caller charges the remainder elsewhere.
///
/// Called inside the generation transaction, after the run has produced a patch, so a pool only
/// ever pays for work that actually happened.
pub async fn draw_for_run(
    tx: &mut Tx<'_>,
    intent_id: i64,
    cost: i64,
    memo: &str,
) -> anyhow::Result<i64> {
    let Some(p) = active_for_intent(tx, intent_id).await? else {
        return Ok(0);
    };
    let held = held_tx(tx, p.id).await?;
    let amount = credits::pool_draw(cost, held, p.per_intent_cap);
    if amount <= 0 {
        return Ok(0);
    }
    // A draw is booked against the pool's creator row for referential integrity; its sign is
    // zero, so it moves no user's spendable balance. The pool_id column is what matters.
    sqlx::query(
        "INSERT INTO credit_entries (user_id, kind, credits, intent_id, memo, pool_id)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(p.created_by)
    .bind(EntryKind::PoolDraw.as_str())
    .bind(amount)
    .bind(intent_id)
    .bind(memo)
    .bind(p.id)
    .execute(&mut **tx)
    .await?;
    db::append_event(
        tx,
        "pool.draw",
        Some(intent_id),
        "backend",
        serde_json::json!({"pool_id": p.id, "credits": amount, "held_before": held}),
    )
    .await?;
    Ok(amount)
}

/// Move a pool to a terminal state and return every unspent credit to its sponsors, pro rata.
///
/// Inference already spent is never refunded: it bought public work whose receipts are public.
/// Everything unspent always is. This is the only path by which pool money leaves, and it can
/// only reach the sponsors who put it in.
pub async fn settle(
    tx: &mut Tx<'_>,
    id: i64,
    status: PoolStatus,
    reason: &str,
) -> anyhow::Result<i64> {
    let Some(p) = lock(tx, id).await? else {
        anyhow::bail!("pool {id} not found");
    };
    if !status.refunds_unspent() {
        anyhow::bail!("{} is not a settling status", status.as_str());
    }
    let held = held_tx(tx, id).await?;
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT user_id, SUM(credits)::bigint FROM credit_entries
         WHERE pool_id = $1 AND kind = 'pool_pledge' GROUP BY user_id ORDER BY user_id",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    let amounts: Vec<i64> = rows.iter().map(|(_, c)| *c).collect();
    let shares = credits::refund_shares(held, &amounts);
    let mut refunded = 0i64;
    for ((user_id, _), share) in rows.iter().zip(shares) {
        if share <= 0 {
            continue;
        }
        sqlx::query(
            "INSERT INTO credit_entries (user_id, kind, credits, memo, pool_id)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(user_id)
        .bind(EntryKind::PoolRefund.as_str())
        .bind(share)
        .bind(reason)
        .bind(id)
        .execute(&mut **tx)
        .await?;
        refunded += share;
    }
    sqlx::query("UPDATE sponsor_pools SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status.as_str())
        .execute(&mut **tx)
        .await?;
    db::append_event(
        tx,
        "pool.settled",
        p.intent_id,
        "backend",
        serde_json::json!({"pool_id": id, "status": status.as_str(), "reason": reason,
                           "unspent": held, "refunded": refunded}),
    )
    .await?;
    Ok(refunded)
}

/// All-or-nothing funding check, run by the worker tick. A pool past its deadline either
/// becomes `funded` (goal met) or `failed` and refunds everything.
pub async fn resolve_deadlines(pool: &PgPool) -> anyhow::Result<()> {
    let due: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM sponsor_pools WHERE status = 'open' AND deadline <= now()",
    )
    .fetch_all(pool)
    .await?;
    for id in due {
        let mut tx = pool.begin().await?;
        let Some(p) = lock(&mut tx, id).await? else {
            continue;
        };
        if p.status != "open" {
            tx.rollback().await?;
            continue;
        }
        let held = held_tx(&mut tx, id).await?;
        if held >= p.goal_credits {
            sqlx::query("UPDATE sponsor_pools SET status = 'funded' WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            db::append_event(
                &mut tx,
                "pool.funded",
                p.intent_id,
                "backend",
                serde_json::json!({"pool_id": id, "pledged": held, "goal": p.goal_credits}),
            )
            .await?;
        } else {
            settle(
                &mut tx,
                id,
                PoolStatus::Failed,
                "goal not met by the deadline",
            )
            .await?;
        }
        tx.commit().await?;
    }

    // Expiry: an active pool that was never spent cannot hold money forever.
    let expired: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM sponsor_pools WHERE status IN ('funded','active') AND expires_at <= now()",
    )
    .fetch_all(pool)
    .await?;
    for id in expired {
        let mut tx = pool.begin().await?;
        settle(&mut tx, id, PoolStatus::Expired, "pool expired").await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Whether this user must stand aside from reviewing or deciding an intent, because they or
/// their organisation funded it. Checked before a governor decision is accepted.
pub async fn must_recuse(pool: &PgPool, user_id: i64, intent_id: i64) -> anyhow::Result<bool> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pool_sponsors ps
         JOIN sponsor_pools p ON p.id = ps.pool_id
         WHERE p.intent_id = $1 AND (
               ps.user_id = $2
            OR (ps.verified_org_domain IS NOT NULL
                AND ps.verified_org_domain = (SELECT verified_org_domain FROM users WHERE id = $2)))",
    )
    .bind(intent_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}
