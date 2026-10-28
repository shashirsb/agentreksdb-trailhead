//! Reputation lookups: turn ledger history into a tier.

use chrono::Utc;
use sqlx::PgPool;
use trailhead_core::reputation::{self, Activity, Tier};

use crate::db::UserRow;

pub async fn activity(pool: &PgPool, u: &UserRow) -> anyhow::Result<Activity> {
    let (merged_retained, modules): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE updated_at < now() - interval '30 days'),
                count(DISTINCT area)
         FROM intents WHERE author_id = $1 AND status = 'merged'",
    )
    .bind(u.id)
    .fetch_one(pool)
    .await?;
    let (d90, d100): (i64, i64) = sqlx::query_as(
        "SELECT count(DISTINCT date_trunc('day', ts)) FILTER (WHERE ts > now() - interval '90 days'),
                count(DISTINCT date_trunc('day', ts)) FILTER (WHERE ts > now() - interval '100 days')
         FROM events WHERE actor = $1",
    )
    .bind(&u.login)
    .fetch_one(pool)
    .await?;
    // Triage that paid off: votes cast on intents that later merged.
    let reviews: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM votes v JOIN intents i ON i.id = v.intent_id WHERE v.user_id = $1 AND i.status = 'merged'",
    )
    .bind(u.id)
    .fetch_one(pool)
    .await?;
    let reverts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE kind = 'intent.reverted' AND ts > now() - interval '90 days'
           AND intent_id IN (SELECT id FROM intents WHERE author_id = $1)",
    )
    .bind(u.id)
    .fetch_one(pool)
    .await?;
    Ok(Activity {
        account_age_days: (Utc::now() - u.account_created_at).num_days(),
        verified_org_domain: u.verified_org_domain.is_some(),
        merged_retained,
        active_days_last_90: d90,
        active_days_last_100: d100,
        modules_touched: modules,
        reviews_accepted: reviews,
        reverts_last_90: reverts,
        is_elected_governor: u.is_governor,
    })
}

pub async fn tier_of(pool: &PgPool, u: &UserRow) -> anyhow::Result<Tier> {
    Ok(reputation::tier(&activity(pool, u).await?))
}

/// What an account may do beyond reading and voting, which need nothing.
///
/// Read from the `user_rights` view rather than from columns on `users`, so revoking an invitation
/// takes effect on the next request instead of whenever a cached flag happens to be rewritten.
#[derive(Debug, Clone, Copy, sqlx::FromRow)]
pub struct Rights {
    pub may_request_features: bool,
    pub may_develop: bool,
    pub may_create_org: bool,
}

pub async fn rights_of(pool: &PgPool, user_id: i64) -> anyhow::Result<Rights> {
    let r: Rights = sqlx::query_as(
        "SELECT may_request_features, may_develop, may_create_org FROM user_rights WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(r)
}
