//! HTTP API (see docs/API.md). Every read is public; writes need a GitHub session.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::{Datelike, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};
use trailhead_core::credits::{self, EntryKind, VoteError};
use trailhead_core::reputation::{self, Tier};
use trailhead_core::spec::{self, Spec};
use trailhead_core::{diffpolicy, guardrails, ledger, train};

use crate::config::Config;
use crate::db::{self, EventRow, IntentRow, UserRow};
use crate::{auth, github, interviewer, signals, users, worker};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub guardrails: Arc<guardrails::Policy>,
    pub diff_policy: Arc<diffpolicy::Policy>,
    pub ledger_key: Arc<ed25519_dalek::SigningKey>,
}

// ---------- errors ----------

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub hint: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &str, message: &str, hint: &str) -> Self {
        ApiError {
            status,
            code: code.into(),
            message: message.into(),
            hint: hint.into(),
        }
    }
    pub fn bad(code: &str, message: &str, hint: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message, hint)
    }
    pub fn not_found(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("{what} not found."),
            "",
        )
    }
    pub fn forbidden(code: &str, message: &str, hint: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message, hint)
    }
    pub fn internal<E: std::fmt::Display>(e: E) -> Self {
        tracing::error!("internal error: {e}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Something went wrong on our side.",
            "It has been logged; try again.",
        )
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::internal(format!("{e:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error": {"code": self.code, "message": self.message, "hint": self.hint}})),
        )
            .into_response()
    }
}

type R<T> = Result<Json<T>, ApiError>;
type CreditRow = (String, i64, Option<i64>, String, chrono::DateTime<Utc>);

// ---------- router ----------

pub fn router(st: AppState) -> Router {
    let web = st.cfg.web_dir.clone();
    let api = Router::new()
        .route("/auth/github/login", get(auth::github_login))
        .route("/auth/github/callback", get(auth::github_callback))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/dev-login", post(auth::dev_login))
        .route("/api/me", get(me))
        .route("/api/intents", get(list_intents).post(create_intent))
        .route("/api/intents/{id}", get(get_intent))
        .route("/api/intents/{id}/messages", post(post_message))
        .route("/api/intents/{id}/submit", post(submit))
        .route("/api/intents/{id}/vote", post(vote))
        .route("/api/train", get(train_state))
        .route("/api/train/tick", post(train_tick))
        .route("/api/governor/queue", get(governor_queue))
        .route("/api/governor/{id}/decide", post(governor_decide))
        .route("/api/admin/kill-switch", post(kill_switch))
        .route("/api/ledger", get(ledger_list))
        .route("/api/ledger/verify", get(ledger_verify))
        .route("/api/ledger/checkpoint", get(ledger_checkpoint))
        .route("/api/credits", get(my_credits))
        .route("/api/orgs", get(list_orgs).post(create_org))
        .route("/api/orgs/{id}", get(get_org))
        .route("/api/orgs/{id}/members", post(add_org_member))
        .route("/api/orgs/{id}/credits", post(buy_org_credits))
        .route(
            "/api/orgs/{id}/keys",
            get(list_org_keys).post(create_org_key),
        )
        .route("/api/orgs/{id}/keys/{key_id}", delete(revoke_org_key))
        .route("/api/orgs/join", post(redeem_org_key))
        .route("/api/me/org", get(my_org))
        .route("/api/priority", get(priority_board))
        .route("/api/me/signals", get(my_signals).post(set_signals_opt_out))
        .route(
            "/api/intents/{id}/evidence",
            get(get_evidence).post(post_evidence),
        )
        .route("/api/stats", get(stats))
        .route("/api/releases", get(releases))
        .route("/api/verify/{sha}", get(verify_sha))
        .route("/api/bundles/{id}", get(bundle))
        .route("/api/webhooks/github", post(webhook))
        .route("/healthz", get(|| async { "ok" }))
        // An unknown path under /api is an error, not the single-page app. Without this, a
        // client calling a route that was renamed or removed gets 200 and a page of HTML,
        // which parses as neither success nor failure and hides the mistake from whoever is
        // reading the response. Everything else still falls through to the app, so deep links
        // keep working.
        .route(
            "/api/{*rest}",
            any(|| async { ApiError::not_found("endpoint") }),
        );
    api.fallback_service(ServeDir::new(&web).fallback(ServeFile::new(web.join("index.html"))))
        .with_state(st)
}

// ---------- helpers ----------

async fn intent_json(pool: &PgPool, it: &IntentRow) -> Result<Value, ApiError> {
    let author: String = sqlx::query_scalar("SELECT login FROM users WHERE id = $1")
        .bind(it.author_id)
        .fetch_one(pool)
        .await
        .map_err(ApiError::internal)?;
    let votes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(points),0)::bigint FROM votes WHERE intent_id = $1",
    )
    .bind(it.id)
    .fetch_one(pool)
    .await
    .map_err(ApiError::internal)?;
    let s: Spec = serde_json::from_value(it.spec.clone()).unwrap_or_default();
    Ok(json!({
        "id": it.id, "title": it.title, "area": it.area, "author": author, "intent": it.intent,
        "status": it.status, "stage": it.stage, "stake_credits": it.stake_credits,
        "change_type": it.change_type, "risk": it.risk, "train": it.train, "holds": it.holds,
        "branch": it.branch, "pr_number": it.pr_number, "commit_sha": it.commit_sha, "votes": votes,
        "spec": it.spec, "readiness": spec::readiness(&s),
        "created_at": it.created_at, "updated_at": it.updated_at,
    }))
}

async fn load_intent(st: &AppState, id: i64) -> Result<IntentRow, ApiError> {
    db::intent(&st.pool, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Intent"))
}

async fn user_json(st: &AppState, u: &UserRow) -> Result<Value, ApiError> {
    let tier = users::tier_of(&st.pool, u).await?;
    let balance = db::balance(&st.pool, u.id).await?;
    Ok(json!({
        "id": u.id, "login": u.login, "tier": tier.as_str(), "rep_points": u.rep_points,
        "is_governor": u.is_governor, "credits_balance": balance, "created_at": u.created_at,
    }))
}

async fn require_governor(st: &AppState, h: &HeaderMap) -> Result<UserRow, ApiError> {
    let u = auth::require_user(st, h).await?;
    if !u.is_governor {
        return Err(ApiError::forbidden(
            "governors_only",
            "Only governors can do this.",
            "Governors are elected; see GOVERNANCE.md.",
        ));
    }
    Ok(u)
}

fn quarter() -> String {
    let n = Utc::now();
    format!("{}-Q{}", n.year(), (n.month() - 1) / 3 + 1)
}

// ---------- handlers ----------

async fn me(State(st): State<AppState>, h: HeaderMap) -> R<Value> {
    let u = auth::current_user(&st, &h).await?;
    Ok(Json(
        json!({"user": match u { Some(u) => user_json(&st, &u).await?, None => Value::Null },
                   "dev_login": st.cfg.dev_login, "oauth": st.cfg.github_client_id.is_some()}),
    ))
}

#[derive(Deserialize)]
struct ListQ {
    status: Option<String>,
    limit: Option<i64>,
    before: Option<i64>,
}

async fn list_intents(State(st): State<AppState>, Query(q): Query<ListQ>) -> R<Value> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<IntentRow> = sqlx::query_as(
        "SELECT * FROM intents WHERE ($1::text IS NULL OR status = $1) AND ($2::bigint IS NULL OR id < $2)
         ORDER BY id DESC LIMIT $3",
    )
    .bind(q.status.filter(|s| s != "all"))
    .bind(q.before)
    .bind(limit)
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(intent_json(&st.pool, r).await?);
    }
    Ok(Json(json!({"intents": out})))
}

#[derive(Deserialize)]
struct CreateIntent {
    title: String,
    area: String,
    intent: String,
    stake_credits: Option<i64>,
    change_type: Option<String>,
}

async fn create_intent(
    State(st): State<AppState>,
    h: HeaderMap,
    Json(b): Json<CreateIntent>,
) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    if db::setting(&st.pool, "kill_switch").await?.as_deref() == Some("on") {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "kill_switch",
            "New intents are paused by the kill switch.",
            "See the ledger for the reason.",
        ));
    }
    let title = b.title.trim();
    let text = b.intent.trim();
    if title.contains('\0') || text.contains('\0') || b.area.contains('\0') {
        return Err(ApiError::bad(
            "bad_text",
            "Text may not contain NUL characters.",
            "",
        ));
    }
    if title.len() < 6 || title.len() > 140 {
        return Err(ApiError::bad(
            "bad_title",
            "Give it a clear title (6–140 characters).",
            "",
        ));
    }
    if text.len() < 12 {
        return Err(ApiError::bad(
            "bad_intent",
            "Describe the behaviour you expect.",
            "A few sentences is enough; the interviewer asks for the rest.",
        ));
    }
    let activity = users::activity(&st.pool, &u).await?;
    if !reputation::may_participate(&activity) {
        return Err(ApiError::forbidden(
            "account_too_new",
            "GitHub accounts need to be at least 90 days old to file intents.",
            "Or verify an organisation email domain.",
        ));
    }
    let tier = reputation::tier(&activity);
    // Everything below runs under a lock on the user row, so parallel requests cannot all claim the
    // free first intent or spend the same credits twice.
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(u.id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let (open, prior): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status NOT IN ('merged','rejected')), count(*) FROM intents WHERE author_id = $1",
    )
    .bind(u.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    if open >= tier.open_intent_limit() {
        return Err(ApiError::forbidden(
            "too_many_open",
            &format!(
                "Your tier ({}) allows {} open intents at a time.",
                tier.as_str(),
                tier.open_intent_limit()
            ),
            "Finish or withdraw one first; merged work raises the limit.",
        ));
    }
    let change_type = b
        .change_type
        .clone()
        .filter(|c| spec::CHANGE_TYPES.contains(&c.as_str()));
    let min = credits::min_stake(change_type.as_deref().unwrap_or("bug"));
    let stake = if prior == 0 {
        b.stake_credits.unwrap_or(0).max(0)
    } else {
        b.stake_credits.unwrap_or(min)
    };
    if prior > 0 && stake < min {
        return Err(ApiError::bad(
            "stake_too_low",
            &format!("This change needs a stake of at least {min} credits."),
            "Stakes are refunded on merge or good-faith decline and burned only for spam.",
        ));
    }
    let balance = db::balance_tx(&mut tx, u.id).await?;
    if stake > balance {
        return Err(ApiError::bad(
            "insufficient_credits",
            &format!("You have {balance} credits; the stake is {stake}."),
            "Credits refill monthly by tier, or can be bought; money buys inference, never trust.",
        ));
    }
    let seed = interviewer::seed(title, text, change_type.as_deref());
    let opening = interviewer::opening(&seed);
    let area = if b.area.trim().is_empty() {
        "Engine".to_string()
    } else {
        b.area.trim().to_string()
    };
    let it: IntentRow = sqlx::query_as(
        "INSERT INTO intents (title, area, author_id, intent, status, stage, stake_credits, change_type, spec)
         VALUES ($1,$2,$3,$4,'draft',2,$5,$6,$7) RETURNING *",
    )
    .bind(title)
    .bind(&area)
    .bind(u.id)
    .bind(text)
    .bind(stake)
    .bind(&change_type)
    .bind(serde_json::to_value(&seed).map_err(ApiError::internal)?)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    sqlx::query(
        "INSERT INTO intent_messages (intent_id, role, body) VALUES ($1,'user',$2), ($1,'ai',$3)",
    )
    .bind(it.id)
    .bind(text)
    .bind(&opening)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    db::add_credits(
        &mut tx,
        u.id,
        EntryKind::StakeHold,
        stake,
        Some(it.id),
        if prior == 0 { "first intent" } else { "stake" },
    )
    .await?;
    db::append_event(
        &mut tx,
        "intent.created",
        Some(it.id),
        &u.login,
        json!({"title": title, "area": area, "intent": text, "stake_credits": stake, "first_intent_free": prior == 0}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(json!({"intent": intent_json(&st.pool, &it).await?})))
}

async fn get_intent(State(st): State<AppState>, Path(id): Path<i64>) -> R<Value> {
    let it = load_intent(&st, id).await?;
    let messages: Vec<(String, String, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT role, body, created_at FROM intent_messages WHERE intent_id = $1 ORDER BY id",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let gates: Vec<(String, String, String, chrono::DateTime<Utc>)> =
        sqlx::query_as("SELECT gate, verdict, detail, created_at FROM gate_results WHERE intent_id = $1 ORDER BY id")
            .bind(id)
            .fetch_all(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    let events: Vec<EventRow> =
        sqlx::query_as("SELECT * FROM events WHERE intent_id = $1 ORDER BY seq")
            .bind(id)
            .fetch_all(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    let decision: Option<(i64, String, String, String, String, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT intent_id, train, decision, reason, governor, created_at FROM decisions WHERE intent_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "intent": intent_json(&st.pool, &it).await?,
        "messages": messages.into_iter().map(|(r, b, t)| json!({"role": r, "body": b, "created_at": t})).collect::<Vec<_>>(),
        "gates_simulated": gates.iter().any(|(_, v, _, _)| v == "simulated"),
        "gates": gates.into_iter().map(|(g, v, d, t)| json!({"gate": g, "verdict": v, "detail": d, "created_at": t})).collect::<Vec<_>>(),
        "events": events,
        "decision": decision.map(|(i, tr, d, r, g, t)| json!({"intent_id": i, "train": tr, "decision": d, "reason": r, "governor": g, "created_at": t})),
    })))
}

#[derive(Deserialize)]
struct MessageBody {
    body: String,
}

async fn post_message(
    State(st): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<MessageBody>,
) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    let it = load_intent(&st, id).await?;
    if it.author_id != u.id {
        return Err(ApiError::forbidden(
            "author_only",
            "Only the intent's author can chat with the interviewer.",
            "Vote or comment instead.",
        ));
    }
    if it.status != "draft" {
        return Err(ApiError::bad(
            "not_draft",
            "This intent has been submitted; the spec is frozen.",
            "File a new intent for further changes.",
        ));
    }
    let body = b.body.trim();
    if body.is_empty() || body.len() > 8000 || body.contains('\0') {
        return Err(ApiError::bad(
            "bad_message",
            "Messages must be 1–8000 characters.",
            "",
        ));
    }
    let history: Vec<(String, String)> =
        sqlx::query_as("SELECT role, body FROM intent_messages WHERE intent_id = $1 ORDER BY id")
            .bind(id)
            .fetch_all(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    let spec: Spec = serde_json::from_value(it.spec.clone()).unwrap_or_default();
    let turn = interviewer::turn(&st.cfg, &st.http, &spec, &history, body)
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "interviewer_failed",
                &format!("The interviewer could not answer: {e}"),
                "Try again in a moment.",
            )
        })?;
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    // The model call can take seconds: make sure nobody submitted or changed the spec meanwhile.
    match db::lock_intent(&mut tx, id).await? {
        Some(cur) if cur.status == "draft" && cur.spec == it.spec => {}
        _ => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "spec_changed",
                "The intent changed while the interviewer was answering (submitted, or another message arrived).",
                "Reload the intent and try again.",
            ))
        }
    }
    sqlx::query(
        "INSERT INTO intent_messages (intent_id, role, body) VALUES ($1,'user',$2), ($1,'ai',$3)",
    )
    .bind(id)
    .bind(body)
    .bind(&turn.reply)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    let spec_v = serde_json::to_value(&turn.spec).map_err(ApiError::internal)?;
    sqlx::query("UPDATE intents SET spec = $2, change_type = COALESCE($3, change_type), updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&spec_v)
        .bind(&turn.spec.change_type)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    db::append_event(
        &mut tx,
        "chat.turn",
        Some(id),
        &u.login,
        json!({"interviewer": turn.by, "prompt": turn.prompt_for_log, "reply": turn.reply, "ready": turn.readiness.ready}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"reply": {"role": "ai", "body": turn.reply}, "spec": spec_v, "readiness": turn.readiness}),
    ))
}

async fn submit(State(st): State<AppState>, h: HeaderMap, Path(id): Path<i64>) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    let it = load_intent(&st, id).await?;
    if it.author_id != u.id {
        return Err(ApiError::forbidden(
            "author_only",
            "Only the author can submit.",
            "",
        ));
    }
    if it.status != "draft" {
        return Err(ApiError::bad("not_draft", "Already submitted.", ""));
    }
    let spec: Spec = serde_json::from_value(it.spec.clone()).unwrap_or_default();
    let r = spec::readiness(&spec);
    if !r.ready {
        return Err(ApiError::bad(
            "spec_not_ready",
            &format!(
                "The spec is not ready: {} open.",
                r.missing
                    .iter()
                    .chain(r.weak.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "Answer the interviewer's questions until the validator passes.",
        ));
    }
    let train_label = train::train_for_submission(Utc::now());
    let spec_hash = trailhead_core::provenance::sha256_hex(
        &serde_json::to_vec(&ledger::canonical(&it.spec)).map_err(ApiError::internal)?,
    );
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    match db::lock_intent(&mut tx, id).await? {
        Some(cur) if cur.status == "draft" && cur.spec == it.spec => {}
        _ => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "spec_changed",
                "The intent changed while submitting.",
                "Reload and submit again.",
            ))
        }
    }
    sqlx::query("UPDATE intents SET train = $2 WHERE id = $1")
        .bind(id)
        .bind(&train_label)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    db::append_event(
        &mut tx,
        "intent.submitted",
        Some(id),
        &u.login,
        json!({"train": train_label, "spec": it.spec, "spec_hash": spec_hash}),
    )
    .await?;
    db::transition(
        &mut tx,
        id,
        "guardrails",
        3,
        &u.login,
        json!({"train": train_label}),
    )
    .await?;
    db::enqueue(&mut tx, "guardrails", Some(id)).await?;
    tx.commit().await.map_err(ApiError::internal)?;
    let it = load_intent(&st, id).await?;
    Ok(Json(json!({"intent": intent_json(&st.pool, &it).await?})))
}

#[derive(Deserialize)]
struct VoteBody {
    points: i64,
}

async fn vote(
    State(st): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<VoteBody>,
) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    let it = load_intent(&st, id).await?;
    let tier = users::tier_of(&st.pool, &u).await?;
    if tier == Tier::Visitor {
        return Err(ApiError::forbidden(
            "contributors_only",
            "Voting opens after your first merged intent.",
            "File an intent; your first one needs no stake.",
        ));
    }
    if (Utc::now() - u.account_created_at).num_days() < credits::VOTE_MIN_ACCOUNT_DAYS {
        return Err(ApiError::forbidden(
            "account_too_new",
            "Accounts need 30 days of age to vote.",
            "",
        ));
    }
    if matches!(it.status.as_str(), "merged" | "rejected") {
        return Err(ApiError::bad("closed", "This intent is closed.", ""));
    }
    let q = quarter();
    let spent: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(points*points),0)::bigint FROM votes WHERE user_id = $1 AND quarter = $2 AND intent_id <> $3",
    )
    .bind(u.id)
    .bind(&q)
    .bind(id)
    .fetch_one(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let others: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(points),0)::bigint FROM votes WHERE intent_id = $1 AND user_id <> $2",
    )
    .bind(id)
    .bind(u.id)
    .fetch_one(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let left = credits::check_vote(b.points, spent, others).map_err(|e| match e {
        VoteError::NotPositive => ApiError::bad("bad_points", "Vote with at least 1 point.", ""),
        VoteError::OverBudget { cost: i64::MAX, .. } => ApiError::bad(
            "over_budget",
            &format!("At most {} points per intent.", credits::VOTE_MAX_POINTS),
            "Quadratic voting: n points cost n²; 10 points use the whole quarter.",
        ),
        VoteError::OverBudget { cost, left } => ApiError::bad(
            "over_budget",
            &format!(
                "{} points cost {cost}; you have {left} left this quarter.",
                b.points
            ),
            "Quadratic voting: n points cost n².",
        ),
        VoteError::OverCap => ApiError::bad(
            "over_cap",
            "One account can hold at most 20% of an intent's votes.",
            "",
        ),
    })?;
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query(
        "INSERT INTO votes (user_id, intent_id, quarter, points) VALUES ($1,$2,$3,$4)
         ON CONFLICT (user_id, intent_id, quarter) DO UPDATE SET points = EXCLUDED.points, created_at = now()",
    )
    .bind(u.id)
    .bind(id)
    .bind(&q)
    .bind(b.points)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    db::append_event(
        &mut tx,
        "vote",
        Some(id),
        &u.login,
        json!({"points": b.points, "cost": b.points * b.points, "quarter": q}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"votes": others + b.points, "budget_left": left}),
    ))
}

async fn train_state(State(st): State<AppState>) -> R<Value> {
    let s = train::state(Utc::now());
    let current = s
        .review
        .as_ref()
        .map(|r| r.train.clone())
        .unwrap_or_else(|| s.intake.train.clone());
    let counts: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, count(*) FROM intents WHERE train = $1 GROUP BY status")
            .bind(&current)
            .fetch_all(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    let w = |w: &train::Window| {
        json!({"train": w.train, "cutoff": w.cutoff, "decision": w.decision,
        "cutoff_pt": train::fmt_pt(w.cutoff), "decision_pt": train::fmt_pt(w.decision)})
    };
    Ok(Json(json!({
        "train": current,
        "now_pt": s.now_pt,
        "phase": if s.review.is_some() { "review" } else { "intake" },
        "cutoff_pt": train::fmt_pt(s.intake.cutoff),
        "decision_pt": train::fmt_pt(s.review.as_ref().map(|r| r.decision).unwrap_or(s.intake.decision)),
        "intake": w(&s.intake),
        "review": s.review.as_ref().map(w),
        "counts": counts.into_iter().map(|(k, v)| (k, json!(v))).collect::<serde_json::Map<_, _>>(),
    })))
}

async fn train_tick(State(st): State<AppState>, h: HeaderMap) -> R<Value> {
    let want = st
        .cfg
        .tick_token
        .clone()
        .ok_or_else(|| ApiError::not_found("Endpoint"))?;
    let got = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !constant_eq(got.as_bytes(), want.as_bytes()) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "bad_token",
            "Bad tick token.",
            "",
        ));
    }
    Ok(Json(worker::tick(&st).await?))
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn governor_queue(State(st): State<AppState>, h: HeaderMap) -> R<Value> {
    require_governor(&st, &h).await?;
    let rows: Vec<IntentRow> = sqlx::query_as(
        "SELECT * FROM intents WHERE status IN ('review','flagged','held') ORDER BY (status = 'flagged') DESC, id",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let mut items = Vec::new();
    for it in &rows {
        let gates: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT DISTINCT ON (gate) gate, verdict, detail FROM gate_results WHERE intent_id = $1 ORDER BY gate, id DESC",
        )
        .bind(it.id)
        .fetch_all(&st.pool)
        .await
        .map_err(ApiError::internal)?;
        let ai_review = gates
            .iter()
            .find(|g| g.0 == "ai-review")
            .map(|g| g.2.clone());
        items.push(json!({
            "intent": intent_json(&st.pool, it).await?,
            "gates_simulated": gates.iter().any(|(_, v, _)| v == "simulated"),
            "gates": gates.into_iter().map(|(g, v, d)| json!({"gate": g, "verdict": v, "detail": d})).collect::<Vec<_>>(),
            "ai_review": ai_review,
        }));
    }
    Ok(Json(
        json!({"items": items, "enforce_window": st.cfg.enforce_window}),
    ))
}

#[derive(Deserialize)]
struct DecideBody {
    decision: String,
    reason: String,
    #[serde(default)]
    spam: bool,
}

async fn governor_decide(
    State(st): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<DecideBody>,
) -> R<Value> {
    let g = require_governor(&st, &h).await?;
    match worker::decide(&st, id, g.id, &g.login, &b.decision, &b.reason, b.spam).await? {
        Ok(v) => Ok(Json(json!({"decision": v}))),
        Err(worker::DecideError::Invalid("not_found", _)) => Err(ApiError::not_found("Intent")),
        Err(worker::DecideError::Invalid("recuse", msg)) => {
            Err(ApiError::forbidden("recuse", &msg, ""))
        }
        Err(worker::DecideError::Invalid(code, msg)) => Err(ApiError::bad(code, &msg, "")),
    }
}

#[derive(Deserialize)]
struct KillBody {
    on: bool,
    reason: String,
}

async fn kill_switch(
    State(st): State<AppState>,
    h: HeaderMap,
    Json(b): Json<KillBody>,
) -> R<Value> {
    let g = require_governor(&st, &h).await?;
    if b.reason.trim().is_empty() {
        return Err(ApiError::bad(
            "reason_required",
            "Say why; it is published.",
            "",
        ));
    }
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    db::set_setting(&mut tx, "kill_switch", if b.on { "on" } else { "off" }).await?;
    db::append_event(
        &mut tx,
        "kill_switch",
        None,
        &g.login,
        json!({"on": b.on, "reason": b.reason}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(json!({"kill_switch": b.on})))
}

#[derive(Deserialize)]
struct LedgerQ {
    after: Option<i64>,
    limit: Option<i64>,
}

async fn ledger_list(State(st): State<AppState>, Query(q): Query<LedgerQ>) -> R<Value> {
    let rows: Vec<EventRow> =
        sqlx::query_as("SELECT * FROM events WHERE seq > $1 ORDER BY seq LIMIT $2")
            .bind(q.after.unwrap_or(0))
            .bind(q.limit.unwrap_or(100).clamp(1, 500))
            .fetch_all(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    Ok(Json(json!({"events": rows})))
}

pub async fn verify_chain(pool: &PgPool) -> anyhow::Result<ledger::ChainReport> {
    let mut prev = ledger::GENESIS.to_string();
    let mut after = 0i64;
    let mut checked = 0usize;
    loop {
        let rows: Vec<EventRow> =
            sqlx::query_as("SELECT * FROM events WHERE seq > $1 ORDER BY seq LIMIT 5000")
                .bind(after)
                .fetch_all(pool)
                .await?;
        if rows.is_empty() {
            return Ok(ledger::ChainReport {
                ok: true,
                checked,
                head: prev,
                first_bad_seq: None,
            });
        }
        if rows[0].seq != after + 1 {
            return Ok(ledger::ChainReport {
                ok: false,
                checked,
                head: prev,
                first_bad_seq: Some(after + 1),
            });
        }
        after = rows.last().map(|r| r.seq).unwrap_or(after);
        let events: Vec<ledger::Event> = rows.into_iter().map(Into::into).collect();
        let r = ledger::verify(&prev, &events);
        checked += r.checked;
        if !r.ok {
            return Ok(ledger::ChainReport {
                ok: false,
                checked,
                head: r.head,
                first_bad_seq: r.first_bad_seq,
            });
        }
        prev = r.head;
    }
}

async fn ledger_verify(State(st): State<AppState>) -> R<Value> {
    Ok(Json(
        serde_json::to_value(verify_chain(&st.pool).await?).map_err(ApiError::internal)?,
    ))
}

async fn ledger_checkpoint(State(st): State<AppState>) -> R<Value> {
    let last: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    let (seq, head) = last.unwrap_or((0, ledger::GENESIS.to_string()));
    let sig = ledger::sign_checkpoint(&st.ledger_key, seq, &head);
    let pk = hex::encode(st.ledger_key.verifying_key().to_bytes());
    sqlx::query("INSERT INTO checkpoints (seq, head, signature, public_key) VALUES ($1,$2,$3,$4) ON CONFLICT (seq) DO NOTHING")
        .bind(seq)
        .bind(&head)
        .bind(&sig)
        .bind(&pk)
        .execute(&st.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(
        json!({"seq": seq, "head": head, "signature": sig, "public_key": pk,
                   "message": String::from_utf8_lossy(&ledger::checkpoint_message(seq, &head))}),
    ))
}

async fn my_credits(State(st): State<AppState>, h: HeaderMap) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    let entries: Vec<CreditRow> = sqlx::query_as(
        "SELECT kind, credits, intent_id, memo, created_at FROM credit_entries WHERE user_id = $1 ORDER BY id DESC LIMIT 200",
    )
    .bind(u.id)
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "balance": db::balance(&st.pool, u.id).await?,
        "entries": entries.into_iter().map(|(k, c, i, m, t)| json!({"kind": k, "credits": c, "intent_id": i, "memo": m, "created_at": t})).collect::<Vec<_>>(),
    })))
}

async fn stats(State(st): State<AppState>) -> R<Value> {
    let (open, in_review, merged, staked): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status NOT IN ('merged','rejected')),
                count(*) FILTER (WHERE status = 'review'),
                count(*) FILTER (WHERE status = 'merged'),
                COALESCE(sum(stake_credits) FILTER (WHERE status NOT IN ('merged','rejected')),0)::bigint
         FROM intents",
    )
    .fetch_one(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let spent: i64 = sqlx::query_scalar("SELECT COALESCE(sum((payload->>'cost_credits')::bigint),0)::bigint FROM events WHERE kind = 'generation.result'")
        .fetch_one(&st.pool)
        .await
        .map_err(ApiError::internal)?;
    let s = train::state(Utc::now());
    Ok(Json(json!({
        "open": open, "in_review": in_review, "merged": merged,
        "credits_spent": spent, "credits_staked": staked,
        "spent_today": worker::spent_today(&st).await?, "daily_budget": st.cfg.daily_budget_credits,
        "kill_switch": db::setting(&st.pool, "kill_switch").await?.as_deref() == Some("on"),
        "train": s.review.map(|r| r.train).unwrap_or(s.intake.train),
        "model_id": st.cfg.agent.generation.model_id,
        "target_repo": st.cfg.target_repo,
        "target_repo_url": format!("https://github.com/{}", st.cfg.target_repo),
    })))
}

/// Release notes: one release per weekly train, listing what the governor merged (and how many
/// branches were held or declined), with links into the target repo.
async fn releases(State(st): State<AppState>) -> R<Value> {
    type Row = (
        String,
        i64,
        String,
        String,
        String,
        Option<String>,
        Option<i64>,
        String,
        String,
        chrono::DateTime<Utc>,
    );
    let merged: Vec<Row> = sqlx::query_as(
        "SELECT d.train, i.id, i.title, i.area, u.login, i.commit_sha, i.pr_number, d.reason, d.governor, d.created_at
         FROM decisions d JOIN intents i ON i.id = d.intent_id JOIN users u ON u.id = i.author_id
         WHERE d.decision = 'merge' AND i.status = 'merged' AND d.train <> ''
         ORDER BY d.train DESC, d.created_at",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let others: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT train, decision, count(*) FROM decisions WHERE decision <> 'merge' AND train <> '' GROUP BY train, decision",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let repo = format!("https://github.com/{}", st.cfg.target_repo);
    let mut trains: Vec<String> = merged
        .iter()
        .map(|r| r.0.clone())
        .chain(others.iter().map(|o| o.0.clone()))
        .collect();
    trains.sort();
    trains.dedup();
    trains.reverse();
    let out: Vec<Value> = trains
        .iter()
        .map(|t| {
            let changes: Vec<Value> = merged
                .iter()
                .filter(|r| &r.0 == t)
                .map(|r| {
                    json!({
                        "intent_id": r.1, "title": r.2, "area": r.3, "author": r.4,
                        "commit_sha": r.5, "commit_url": r.5.as_ref().filter(|c| c.len() >= 7 && c.as_str() != "simulated").map(|c| format!("{repo}/commit/{c}")),
                        "pr_number": r.6, "pr_url": r.6.map(|n| format!("{repo}/pull/{n}")),
                        "reason": r.7, "governor": r.8, "merged_at": r.9,
                    })
                })
                .collect();
            let count = |k: &str| others.iter().filter(|o| &o.0 == t && o.1 == k).map(|o| o.2).sum::<i64>();
            json!({"train": t, "version": format!("v0.{}", t.replace("-W", ".w")), "changes": changes,
                   "held": count("hold"), "declined": count("reject")})
        })
        .collect();
    Ok(Json(json!({
        "target_repo": st.cfg.target_repo,
        "repo_url": repo,
        "download_zip": format!("{repo}/archive/refs/heads/main.zip"),
        "clone": format!("git clone {repo}.git"),
        "releases": out,
    })))
}

async fn verify_sha(State(st): State<AppState>, Path(sha): Path<String>) -> R<Value> {
    let sha = sha.to_lowercase();
    if sha.len() < 12 || sha.len() > 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::bad(
            "bad_sha",
            "Give at least 12 hex characters of the commit SHA.",
            "",
        ));
    }
    let it: Option<IntentRow> = sqlx::query_as(
        "SELECT * FROM intents WHERE commit_sha = $1 OR commit_sha LIKE $1 || '%' LIMIT 1",
    )
    .bind(&sha)
    .fetch_optional(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let Some(it) = it else {
        return Ok(Json(json!({"found": false})));
    };
    let prov: Option<(Value, String, i64)> = sqlx::query_as(
        "SELECT provenance, patch_sha256, ledger_seq FROM bundles WHERE intent_id = $1",
    )
    .bind(it.id)
    .fetch_optional(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "found": true, "intent_id": it.id, "commit_sha": it.commit_sha,
        "provenance": prov.as_ref().map(|p| &p.0), "patch_sha256": prov.as_ref().map(|p| &p.1), "ledger_seq": prov.map(|p| p.2),
    })))
}

async fn bundle(State(st): State<AppState>, Path(id): Path<i64>) -> R<Value> {
    // Bundles are public for audit, but the signing workflow only proceeds on `ready_to_sign`:
    // a flagged, rejected or held intent never gets a commit.
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM intents WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.pool)
        .await
        .map_err(ApiError::internal)?;
    let ready_to_sign = status.as_deref() == Some("gates");
    let b: Option<(String, Vec<u8>, String, String, Value, i64)> =
        sqlx::query_as("SELECT base, patch, patch_sha256, message, provenance, ledger_seq FROM bundles WHERE intent_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    let Some((base, patch, sha, message, prov, seq)) = b else {
        return Err(ApiError::not_found("Bundle"));
    };
    let ev_sha: Option<String> =
        sqlx::query_scalar("SELECT payload->>'patch_sha256' FROM events WHERE seq = $1")
            .bind(seq)
            .fetch_optional(&st.pool)
            .await
            .map_err(ApiError::internal)?
            .flatten();
    Ok(Json(json!({
        "intent_id": id, "base": base, "patch_b64": base64::engine::general_purpose::STANDARD.encode(&patch),
        "patch_sha256": sha, "ledger_patch_sha256": ev_sha, "status": status, "ready_to_sign": ready_to_sign, "message": message, "provenance": prov, "ledger_seq": seq,
        "branch": format!("trailhead/{id}"),
    })))
}

async fn webhook(
    State(st): State<AppState>,
    h: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let secret = st
        .cfg
        .webhook_secret
        .clone()
        .ok_or_else(|| ApiError::not_found("Endpoint"))?;
    let sig = h
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !github::verify_webhook(&secret, &body, sig) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "bad_signature",
            "Webhook signature mismatch.",
            "",
        ));
    }
    let event = h
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let v: Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad("bad_json", "Webhook body is not JSON.", ""))?;
    match event.as_str() {
        "pull_request" => on_pull_request(&st, &v).await?,
        "check_run" => on_check_run(&st, &v).await?,
        _ => {}
    }
    Ok(Json(json!({"ok": true})))
}

fn intent_from_body(body: &str) -> Option<i64> {
    body.lines().find_map(|l| {
        l.trim()
            .strip_prefix("Trailhead-Intent:")
            .and_then(|x| x.trim().parse().ok())
    })
}

async fn on_pull_request(st: &AppState, v: &Value) -> Result<(), ApiError> {
    if v["repository"]["full_name"].as_str() != Some(st.cfg.target_repo.as_str()) {
        return Ok(());
    }
    let pr = &v["pull_request"];
    let action = v["action"].as_str().unwrap_or("");
    let author = pr["user"]["login"].as_str().unwrap_or("");
    let Some(id) = intent_from_body(pr["body"].as_str().unwrap_or("")) else {
        return Ok(());
    };
    if author != st.cfg.bot_login {
        // Only the Trailhead App may open intent PRs; anything else is logged as an anomaly.
        let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
        db::append_event(
            &mut tx,
            "anomaly.foreign_pr",
            Some(id),
            "github",
            json!({"author": author, "pr": pr["number"]}),
        )
        .await?;
        tx.commit().await.map_err(ApiError::internal)?;
        return Ok(());
    }
    let Some(it) = db::intent(&st.pool, id).await? else {
        return Ok(());
    };
    let number = pr["number"].as_i64();
    let head = pr["head"]["sha"].as_str().unwrap_or("").to_string();
    let branch = pr["head"]["ref"].as_str().unwrap_or("").to_string();
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    match action {
        "opened" | "reopened" | "synchronize" => {
            sqlx::query("UPDATE intents SET pr_number = $2, commit_sha = $3, branch = $4, updated_at = now() WHERE id = $1")
                .bind(id)
                .bind(number)
                .bind(&head)
                .bind(&branch)
                .execute(&mut *tx)
                .await
                .map_err(ApiError::internal)?;
            db::append_event(
                &mut tx,
                "pr.updated",
                Some(id),
                "github",
                json!({"action": action, "pr": number, "head": head, "branch": branch}),
            )
            .await?;
            if it.status == "gates" && it.stage < 6 {
                sqlx::query("UPDATE intents SET stage = 6 WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(ApiError::internal)?;
            }
        }
        "closed" if pr["merged"].as_bool() == Some(true) && it.status == "merging" => {
            tx.commit().await.map_err(ApiError::internal)?;
            worker::on_pr_merged(st, id).await?;
            return Ok(());
        }
        "closed" if pr["merged"].as_bool() == Some(true) && it.status != "merged" => {
            db::append_event(
                &mut tx,
                "anomaly.merged_without_decision",
                Some(id),
                "github",
                json!({"pr": number}),
            )
            .await?;
        }
        _ => {}
    }
    tx.commit().await.map_err(ApiError::internal)?;
    if let (Some(train), Some(n), true) = (
        it.train.as_ref(),
        number,
        action == "opened" && st.cfg.github_app_configured(),
    ) {
        let _ = github::GitHub {
            cfg: &st.cfg,
            http: &st.http,
        }
        .add_labels(n, &[format!("train/{train}")])
        .await;
    }
    Ok(())
}

async fn on_check_run(st: &AppState, v: &Value) -> Result<(), ApiError> {
    if v["action"].as_str() != Some("completed") {
        return Ok(());
    }
    let cr = &v["check_run"];
    // Only checks run by GitHub Actions in the target repo count; any other app could post a
    // check with a convincing name.
    if cr["app"]["slug"].as_str() != Some("github-actions")
        || v["repository"]["full_name"].as_str() != Some(st.cfg.target_repo.as_str())
    {
        return Ok(());
    }
    let Some(gate) = worker::gate_for_check(cr["name"].as_str().unwrap_or("")) else {
        return Ok(());
    };
    let head = cr["head_sha"].as_str().unwrap_or("").to_string();
    let it: Option<IntentRow> = sqlx::query_as("SELECT * FROM intents WHERE commit_sha = $1")
        .bind(&head)
        .fetch_optional(&st.pool)
        .await
        .map_err(ApiError::internal)?;
    let Some(it) = it else { return Ok(()) };
    let verdict = match cr["conclusion"].as_str().unwrap_or("") {
        "success" => "pass",
        "neutral" | "skipped" => "warn",
        _ => "block",
    };
    let detail = format!(
        "{} · {}",
        cr["name"].as_str().unwrap_or(""),
        cr["html_url"].as_str().unwrap_or("")
    );
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query("INSERT INTO gate_results (intent_id, gate, check_name, verdict, detail, head_sha) VALUES ($1,$2,$6,$3,$4,$5)")
        .bind(it.id)
        .bind(gate)
        .bind(verdict)
        .bind(&detail)
        .bind(&head)
        .bind(cr["name"].as_str().unwrap_or(""))
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    db::append_event(
        &mut tx,
        &format!("gate.{gate}"),
        Some(it.id),
        "github",
        json!({"verdict": verdict, "check": cr["name"], "url": cr["html_url"], "head": head}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    worker::evaluate_gates(st, it.id, &head).await?;
    Ok(())
}

// ---------- priority board ----------

/// The public leaderboard with every term of every score spelled out, so anyone can recompute
/// a ranking from the published inputs and check it. There is no money term to publish.
async fn priority_board(State(st): State<AppState>) -> R<Value> {
    use trailhead_core::priority;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i64,
        String,
        String,
        Option<String>,
        i64,
        i64,
        Option<chrono::DateTime<Utc>>,
    )> = sqlx::query_as(
        // Votes are summed in two parts: points from people with no employer on record, which
        // count as cast, and points from each organisation, which are weighted separately below.
        // Fifty colleagues backing their employer's priority is not fraud and it is not fifty
        // independent opinions either; counting it as the latter would let the largest payroll
        // set the queue, which is the outcome that deleting sponsor pools was meant to prevent.
        "SELECT i.id, i.title, i.status, i.change_type, i.author_id,
                    COALESCE((SELECT SUM(v.points)::bigint FROM votes v
                               LEFT JOIN org_members m ON m.user_id = v.user_id
                              WHERE v.intent_id = i.id AND m.org_id IS NULL), 0),
                    (SELECT MAX(v.created_at) FROM votes v WHERE v.intent_id = i.id)
             FROM intents i
             WHERE i.status NOT IN ('merged','rejected','draft')
             ORDER BY i.id DESC LIMIT 200",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;

    // Add each organisation's bloc back, weighted. `org_vote_weight` counts the first few
    // colleagues in full and the rest at a square-root rate, so a broad coalition inside a large
    // company still outweighs a handful of people while a payroll cannot simply outvote everyone.
    let bloc_rows: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT v.intent_id, m.org_id, SUM(v.points)::bigint
           FROM votes v JOIN org_members m ON m.user_id = v.user_id
          GROUP BY v.intent_id, m.org_id",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let mut org_mass: std::collections::HashMap<i64, f64> = std::collections::HashMap::new();
    for (intent_id, _org, points) in &bloc_rows {
        *org_mass.entry(*intent_id).or_insert(0.0) += trailhead_core::credits::org_vote_weight(
            *points,
            trailhead_core::credits::ORG_VOTE_FREE_POINTS,
        );
    }

    // The saturating prior: the median vote mass across the open board. Using the median
    // rather than the maximum means one brigaded intent cannot rescale everyone else.
    let mut masses: Vec<f64> = rows
        .iter()
        .map(|r| r.5 as f64 + org_mass.get(&r.0).copied().unwrap_or(0.0))
        .collect();
    masses.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = if masses.is_empty() {
        1.0
    } else {
        masses[masses.len() / 2].max(1.0)
    };

    let mut out = Vec::new();
    for (id, title, status, change_type, author_id, points, last_vote) in rows {
        let merged: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM intents WHERE author_id = $1 AND status = 'merged'",
        )
        .bind(author_id)
        .fetch_one(&st.pool)
        .await
        .map_err(ApiError::internal)?;
        // Opted-out users score on Trailhead data alone, with no penalty.
        let sig = signals::get(&st.pool, author_id).await?;
        let idle_days = last_vote.map(|t| (Utc::now() - t).num_days()).unwrap_or(0);
        let inputs = priority::Inputs {
            votes_raw: points as f64 + org_mass.get(&id).copied().unwrap_or(0.0),
            votes_median: median,
            merged_retained: merged.max(0) as u32,
            qualifying_repos: sig.shared_repos.max(0) as u32,
            stake_tier: match change_type.as_deref() {
                Some("protocol") => 1.0,
                Some("feature") | Some("perf") | Some("refactor") => 0.5,
                _ => 0.0,
            },
            idle_days,
            ..Default::default()
        };
        let b = priority::breakdown(inputs);
        out.push(json!({
            "intent_id": id, "title": title, "status": status,
            "score": (b.total * 10.0).round() / 10.0,
            "breakdown": b, "inputs": inputs
        }));
    }
    out.sort_by(|a, b| {
        b["score"]
            .as_f64()
            .partial_cmp(&a["score"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(Json(json!({
        "version": "v2",
        "formula": "S = D x [55V + 9R + 4O + 17Fit + 9K + 6E] x P",
        "money_term": null,
        "note": "Credits buy inference only. No amount of money appears in any term of this score.",
        "weights": {"votes": priority::W_VOTES, "merged": priority::W_MERGED,
                    "repos": priority::W_REPOS, "fit": priority::W_FIT,
                    "stake": priority::W_STAKE, "size": priority::W_SIZE},
        "vote_prior_median": median,
        "intents": out
    })))
}

#[derive(Deserialize)]
struct OptOutBody {
    opted_out: bool,
}

/// A contributor can see exactly what public data was counted, and what was excluded and why.
async fn my_signals(State(st): State<AppState>, h: HeaderMap) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    let s = signals::get(&st.pool, u.id).await?;
    Ok(Json(json!({
        "signals": s,
        "counts_toward": "the two smallest terms of the priority score: merged history (9 of 100) and shared repos (4 of 100)",
        "never_counts": ["raw commit counts", "raw stars", "followers", "private contributions"],
        "opt_out": "You can turn this off. Trailhead-only scoring carries no penalty."
    })))
}

async fn set_signals_opt_out(
    State(st): State<AppState>,
    h: HeaderMap,
    Json(b): Json<OptOutBody>,
) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    signals::set_opt_out(&st.pool, u.id, b.opted_out).await?;
    Ok(Json(json!({"opted_out": b.opted_out})))
}

// ---------- organisations ----------
//
// An organisation buys credits so its own members can pay for inference. Read the handlers
// looking for the call that attaches that money to a feature: there isn't one, and that absence
// is the entire safety property. Sponsor pools (deleted in 0004) had exactly that call, and every
// rule written to keep it honest — no priority, no vote weight, disclosure, recusal — existed to
// contain it. Money that only ever names a person needs none of them.

#[derive(serde::Deserialize)]
struct NewOrg {
    name: String,
    verified_domain: Option<String>,
}

async fn create_org(State(st): State<AppState>, h: HeaderMap, Json(b): Json<NewOrg>) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    let name = b.name.trim();
    if name.len() < 2 || name.len() > 80 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_name",
            "An organisation name is between 2 and 80 characters.",
            "Use the name people would recognise.",
        ));
    }
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    // One employer per person, enforced by a unique index; check first so the error is readable.
    let existing: Option<i64> =
        sqlx::query_scalar("SELECT org_id FROM org_members WHERE user_id = $1")
            .bind(u.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
    if existing.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "already_in_org",
            "You already belong to an organisation.",
            "Leave it before creating another; one employer per account keeps the vote discount honest.",
        ));
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO orgs (name, verified_domain, created_by) VALUES ($1,$2,$3) RETURNING id",
    )
    .bind(name)
    .bind(
        b.verified_domain
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty()),
    )
    .bind(u.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if e.to_string().contains("orgs_name_lower") {
            ApiError::new(
                StatusCode::CONFLICT,
                "name_taken",
                "An organisation with that name already exists.",
                "Ask its admin to add you instead.",
            )
        } else {
            ApiError::internal(e)
        }
    })?;
    sqlx::query(
        "INSERT INTO org_members (org_id, user_id, role, added_by) VALUES ($1,$2,'admin',$2)",
    )
    .bind(id)
    .bind(u.id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    db::append_event(
        &mut tx,
        "org.created",
        None,
        &u.login,
        json!({"org_id": id, "name": name, "domain": b.verified_domain}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(json!({"org_id": id, "name": name, "role": "admin"})))
}

/// Is this user an admin of this organisation?
async fn require_org_admin(st: &AppState, h: &HeaderMap, org: i64) -> Result<UserRow, ApiError> {
    let u = auth::require_user(st, h).await?;
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(u.id)
            .fetch_optional(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    if role.as_deref() != Some("admin") {
        return Err(ApiError::forbidden(
            "org_admin_only",
            "Only an admin of this organisation can do that.",
            "Ask whoever created it.",
        ));
    }
    Ok(u)
}

#[derive(serde::Deserialize)]
struct NewMember {
    login: String,
}

async fn add_org_member(
    State(st): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<NewMember>,
) -> R<Value> {
    let admin = require_org_admin(&st, &h, id).await?;
    let member: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE login = $1")
        .bind(b.login.trim())
        .fetch_optional(&st.pool)
        .await
        .map_err(ApiError::internal)?;
    let Some(member) = member else {
        return Err(ApiError::not_found("That account"));
    };
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    sqlx::query("INSERT INTO org_members (org_id, user_id, added_by) VALUES ($1,$2,$3)")
        .bind(id)
        .bind(member.id)
        .bind(admin.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if e.to_string().contains("org_members_one_org") {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "already_in_org",
                    "That account already belongs to an organisation.",
                    "One employer per account; they must leave the other first.",
                )
            } else {
                ApiError::internal(e)
            }
        })?;
    // Who funds whom is public, because it is what lets anyone check the vote discount is applied.
    db::append_event(
        &mut tx,
        "org.member_added",
        None,
        &admin.login,
        json!({"org_id": id, "member": member.login}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"org_id": id, "member": member.login, "role": "member"}),
    ))
}

#[derive(serde::Deserialize)]
struct BuyCredits {
    credits: i64,
}

async fn buy_org_credits(
    State(st): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<BuyCredits>,
) -> R<Value> {
    let admin = require_org_admin(&st, &h, id).await?;
    if b.credits <= 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_amount",
            "Credits must be a positive number.",
            "",
        ));
    }
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    db::add_org_credits(
        &mut tx,
        id,
        admin.id,
        EntryKind::OrgPurchase,
        b.credits,
        None,
        "organisation credit purchase",
    )
    .await?;
    db::append_event(
        &mut tx,
        "org.purchase",
        None,
        &admin.login,
        json!({"org_id": id, "credits": b.credits}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    let bal = org_balance(&st, id).await?;
    Ok(Json(json!({"org_id": id, "balance": bal})))
}

async fn org_balance(st: &AppState, id: i64) -> Result<i64, ApiError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(balance,0)::bigint FROM org_balances WHERE org_id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(ApiError::internal)
    .map(|v| v.unwrap_or(0))
}

async fn list_orgs(State(st): State<AppState>) -> R<Value> {
    let rows: Vec<(i64, String, Option<String>, i64, i64, i64)> = sqlx::query_as(
        "SELECT org_id, name, verified_domain, purchased, spent, balance
           FROM org_balances ORDER BY name",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "orgs": rows.iter().map(|r| json!({
            "id": r.0, "name": r.1, "domain": r.2,
            "purchased": r.3, "spent": r.4, "balance": r.5,
        })).collect::<Vec<_>>(),
        "priority_effect": "none — the score has no monetary term, and organisation credits \
                            name a member, never an intent",
    })))
}

async fn get_org(State(st): State<AppState>, Path(id): Path<i64>) -> R<Value> {
    let row: Option<(i64, String, Option<String>, i64, i64, i64)> = sqlx::query_as(
        "SELECT org_id, name, verified_domain, purchased, spent, balance
           FROM org_balances WHERE org_id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let Some(r) = row else {
        return Err(ApiError::not_found("Organisation"));
    };
    let members: Vec<(String, String)> = sqlx::query_as(
        "SELECT u.login, m.role FROM org_members m JOIN users u ON u.id = m.user_id
          WHERE m.org_id = $1 ORDER BY m.role, u.login",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "id": r.0, "name": r.1, "domain": r.2,
        "purchased": r.3, "spent": r.4, "balance": r.5,
        "balances_reconcile": r.3 - r.4 == r.5,
        "members": members.iter().map(|m| json!({"login": m.0, "role": m.1})).collect::<Vec<_>>(),
        "vote_weighting": format!(
            "This organisation's combined votes on one intent count in full up to {} points, \
             then at a square-root rate. Colleagues agreeing is not independent support.",
            trailhead_core::credits::ORG_VOTE_FREE_POINTS),
        "priority_effect": "none — these credits pay for a member's inference and name no intent",
    })))
}

/// The signed-in person's own organisation, if they have one. Drives the settings page: a member
/// sees the balance their work draws on, an admin also sees the keys.
async fn my_org(State(st): State<AppState>, h: HeaderMap) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    let row: Option<(i64, String, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT b.org_id, b.name, m.role, b.purchased, b.spent, b.balance
           FROM org_members m JOIN org_balances b ON b.org_id = m.org_id
          WHERE m.user_id = $1",
    )
    .bind(u.id)
    .fetch_optional(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let Some(r) = row else {
        return Ok(Json(json!({"org_id": null})));
    };
    let members: Vec<(String, String)> = sqlx::query_as(
        "SELECT u.login, m.role FROM org_members m JOIN users u ON u.id = m.user_id
          WHERE m.org_id = $1 ORDER BY m.role, u.login",
    )
    .bind(r.0)
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "org_id": r.0, "name": r.1, "role": r.2,
        "purchased": r.3, "spent": r.4, "balance": r.5,
        "members": members.iter().map(|m| json!({"login": m.0, "role": m.1})).collect::<Vec<_>>(),
        "priority_effect": "These credits pay for your inference. They give this organisation no \
                            priority, no vote weight and no say in what merges.",
    })))
}

// ---------- organisation keys ----------
//
// An admin mints a key in settings and gives it to staff; redeeming it bills their inference to
// the employer. Revocation is the control that matters, because a secret shared with a whole team
// will eventually be pasted somewhere public. Only the hash is stored, and the secret is shown
// exactly once, at creation.

#[derive(serde::Deserialize)]
struct NewKey {
    label: Option<String>,
    /// Cap how many people may redeem it. Absent means no cap.
    max_uses: Option<i64>,
    /// Days until it stops working. Absent means it never expires on its own.
    expires_in_days: Option<i64>,
}

async fn create_org_key(
    State(st): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<NewKey>,
) -> R<Value> {
    let admin = require_org_admin(&st, &h, id).await?;
    let label = b
        .label
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .unwrap_or("organisation key")
        .chars()
        .take(80)
        .collect::<String>();
    if b.max_uses.is_some_and(|m| m <= 0) || b.expires_in_days.is_some_and(|d| d <= 0) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_limits",
            "A use limit and an expiry must both be positive.",
            "Leave either out for no limit.",
        ));
    }
    let k = credits::new_org_key();
    let expires = b
        .expires_in_days
        .map(|d| Utc::now() + chrono::Duration::days(d));
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    let key_id: i64 = sqlx::query_scalar(
        "INSERT INTO org_keys (org_id, label, prefix, key_hash, created_by, max_uses, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
    )
    .bind(id)
    .bind(&label)
    .bind(&k.prefix)
    .bind(&k.hash)
    .bind(admin.id)
    .bind(b.max_uses)
    .bind(expires)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    // The event records that a key was minted and by whom. It records no part of the key, not
    // even the display prefix: the ledger is public and permanent, so anything written here is
    // world-readable forever. Six characters of a 256-bit secret are no real help to an attacker,
    // but a public log is the last place to find out that reasoning was wrong. Admins see the
    // prefix on the keys page, which is behind their own authorisation.
    db::append_event(
        &mut tx,
        "org.key_created",
        None,
        &admin.login,
        json!({"org_id": id, "key_id": key_id, "label": label,
               "max_uses": b.max_uses, "expires_at": expires}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(json!({
        "key_id": key_id,
        "label": label,
        // The only time this value ever leaves the server.
        "key": k.secret,
        "prefix": k.prefix,
        "max_uses": b.max_uses,
        "expires_at": expires,
        "warning": "Copy this now: it is stored only as a hash and cannot be shown again. \
                    Anyone holding it can join this organisation and spend its credits, so share \
                    it the way you would a password and revoke it if it leaks.",
    })))
}

async fn list_org_keys(State(st): State<AppState>, h: HeaderMap, Path(id): Path<i64>) -> R<Value> {
    require_org_admin(&st, &h, id).await?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i64,
        String,
        String,
        chrono::DateTime<Utc>,
        Option<chrono::DateTime<Utc>>,
        Option<chrono::DateTime<Utc>>,
        Option<chrono::DateTime<Utc>>,
        i64,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT id, label, prefix, created_at, revoked_at, expires_at, last_used_at, uses, max_uses
           FROM org_keys WHERE org_id = $1 ORDER BY id DESC",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    let now = Utc::now();
    Ok(Json(json!({
        "keys": rows.iter().map(|r| {
            let revoked = r.4.is_some();
            let expired = r.5.is_some_and(|e| e <= now);
            let exhausted = r.8.is_some_and(|m| r.7 >= m);
            json!({
                "id": r.0, "label": r.1, "prefix": r.2, "created_at": r.3,
                "revoked_at": r.4, "expires_at": r.5, "last_used_at": r.6,
                "uses": r.7, "max_uses": r.8,
                "live": !revoked && !expired && !exhausted,
                "state": if revoked { "revoked" } else if expired { "expired" }
                         else if exhausted { "exhausted" } else { "live" },
            })
        }).collect::<Vec<_>>(),
        "note": "Keys are stored as hashes. The secret is shown once, when it is created.",
    })))
}

async fn revoke_org_key(
    State(st): State<AppState>,
    h: HeaderMap,
    Path((id, key_id)): Path<(i64, i64)>,
) -> R<Value> {
    let admin = require_org_admin(&st, &h, id).await?;
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    // Scoped by org_id as well as id, so an admin of one organisation cannot revoke another's key
    // by guessing a number.
    let n = sqlx::query(
        "UPDATE org_keys SET revoked_at = now(), revoked_by = $3
          WHERE id = $2 AND org_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(key_id)
    .bind(admin.id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::internal)?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("That key, or it was already revoked"));
    }
    // Revoking stops future redemptions. People who already joined stay members: their work was
    // genuinely funded, and quietly ejecting them would leave spent credits unexplained. Remove
    // them from the member list if that is what is wanted.
    db::append_event(
        &mut tx,
        "org.key_revoked",
        None,
        &admin.login,
        json!({"org_id": id, "key_id": key_id}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(json!({"key_id": key_id, "revoked": true,
                   "members_kept": "Revoking blocks new redemptions; existing members are unchanged."})))
}

#[derive(serde::Deserialize)]
struct JoinOrg {
    key: String,
}

/// Redeem a key: the caller joins the organisation, and from then on their inference is billed to
/// it. This is the endpoint an employee uses from the intent chat.
async fn redeem_org_key(
    State(st): State<AppState>,
    h: HeaderMap,
    Json(b): Json<JoinOrg>,
) -> R<Value> {
    let u = auth::require_user(&st, &h).await?;
    // Shape first, so a stray paste never reaches the database.
    let hash = credits::parse_org_key(&b.key).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            e.code(),
            e.message(),
            "Organisation keys are created by an admin under the organisation's settings.",
        )
    })?;
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    // FOR UPDATE so two people redeeming the last use of a capped key cannot both succeed.
    #[allow(clippy::type_complexity)]
    let row: Option<(
        i64,
        i64,
        Option<chrono::DateTime<Utc>>,
        Option<chrono::DateTime<Utc>>,
        i64,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT id, org_id, revoked_at, expires_at, uses, max_uses
               FROM org_keys WHERE key_hash = $1 FOR UPDATE",
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::internal)?;
    let Some((key_id, org_id, revoked_at, expires_at, uses, max_uses)) = row else {
        let e = credits::OrgKeyError::Unknown;
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            e.code(),
            e.message(),
            "",
        ));
    };
    let state = credits::OrgKeyState {
        revoked: revoked_at.is_some(),
        expired: expires_at.is_some_and(|e| e <= Utc::now()),
        uses,
        max_uses,
    };
    credits::org_key_usable(state)
        .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, e.code(), e.message(), ""))?;

    // Already a member of this organisation: say so plainly rather than spending a use.
    let current: Option<i64> =
        sqlx::query_scalar("SELECT org_id FROM org_members WHERE user_id = $1")
            .bind(u.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
    if current == Some(org_id) {
        return Ok(Json(json!({"org_id": org_id, "already_a_member": true})));
    }
    if current.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "already_in_org",
            "You already belong to a different organisation.",
            "One employer per account; leave the other first.",
        ));
    }

    sqlx::query("INSERT INTO org_members (org_id, user_id, added_by) VALUES ($1,$2,$2)")
        .bind(org_id)
        .bind(u.id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query("UPDATE org_keys SET uses = uses + 1, last_used_at = now() WHERE id = $1")
        .bind(key_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query("INSERT INTO org_key_redemptions (key_id, user_id) VALUES ($1,$2)")
        .bind(key_id)
        .bind(u.id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    // Who joined through which key is public. It is what lets anyone check that an organisation's
    // votes are being clustered, and that its spending is attached to real named people.
    db::append_event(
        &mut tx,
        "org.key_redeemed",
        None,
        &u.login,
        json!({"org_id": org_id, "key_id": key_id}),
    )
    .await?;
    tx.commit().await.map_err(ApiError::internal)?;
    let name: String = sqlx::query_scalar("SELECT name FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&st.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "org_id": org_id, "org": name, "role": "member",
        "effect": "Your intents' inference is now billed to this organisation. Your votes count \
                   within its bloc, because colleagues are not independent voters.",
    })))
}

// ---------- per-feature evidence ----------
//
// "The suite is green" says nothing about whether the suite tested what was asked for. The
// evidence tables are append-only, so a result cannot be rewritten after the fact, and every
// run records enough to re-run it: toolchain, versions, command, seeds and the hash of each
// raw report.

#[derive(Deserialize)]
struct EvidenceBody {
    head_sha: String,
    parent_sha: Option<String>,
    gate: String,
    check_name: String,
    #[serde(default)]
    run_url: String,
    #[serde(default)]
    env: Value,
    manifest_sha256: String,
    #[serde(default)]
    tests: Vec<EvidenceTest>,
    #[serde(default)]
    mutants: Vec<EvidenceMutant>,
    #[serde(default)]
    links: Vec<EvidenceLink>,
    #[serde(default)]
    blobs: Vec<EvidenceBlob>,
}

#[derive(Deserialize)]
struct EvidenceTest {
    id: String,
    #[serde(default = "unit_kind")]
    kind: String,
    status: String,
    #[serde(default)]
    attempts: Value,
    duration_ms: Option<i64>,
    output_sha256: Option<String>,
    #[serde(default)]
    added_in_diff: bool,
    #[serde(default = "na")]
    fail_before: String,
}
fn unit_kind() -> String {
    "unit".into()
}
fn na() -> String {
    "n/a".into()
}

#[derive(Deserialize)]
struct EvidenceMutant {
    mutant: String,
    file: String,
    line: Option<i32>,
    outcome: String,
    caught_by: Option<String>,
    diff_sha256: Option<String>,
}

#[derive(Deserialize)]
struct EvidenceLink {
    acceptance_id: String,
    requirement_id: String,
    test_id: String,
    #[serde(default = "tag_source")]
    source: String,
}
fn tag_source() -> String {
    "tag".into()
}

#[derive(Deserialize)]
struct EvidenceBlob {
    sha256: String,
    media_type: String,
    size: i64,
    uri: String,
}

/// Ingest one gate run's raw results. Authenticated with the tick token, because this is the
/// CI pipeline talking, not a person.
async fn post_evidence(
    State(st): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(b): Json<EvidenceBody>,
) -> R<Value> {
    let want = st
        .cfg
        .tick_token
        .clone()
        .ok_or_else(|| ApiError::not_found("Endpoint"))?;
    let got = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !constant_eq(got.as_bytes(), want.as_bytes()) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "bad_token",
            "Bad tick token.",
            "",
        ));
    }
    load_intent(&st, id).await?;

    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    let seq = db::append_event(
        &mut tx,
        "evidence.recorded",
        Some(id),
        "ci",
        json!({"gate": b.gate, "check": b.check_name, "head": b.head_sha,
               "manifest_sha256": b.manifest_sha256, "tests": b.tests.len(),
               "mutants": b.mutants.len()}),
    )
    .await?;
    let run_id: i64 = sqlx::query_scalar(
        "INSERT INTO evidence_runs
           (intent_id, head_sha, parent_sha, gate, check_name, run_url, env, manifest_sha256, ledger_seq)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id",
    )
    .bind(id)
    .bind(&b.head_sha)
    .bind(&b.parent_sha)
    .bind(&b.gate)
    .bind(&b.check_name)
    .bind(&b.run_url)
    .bind(&b.env)
    .bind(&b.manifest_sha256)
    .bind(seq.seq)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::internal)?;

    for t in &b.tests {
        sqlx::query(
            "INSERT INTO test_results
               (run_id, test_id, kind, status, attempts, duration_ms, output_sha256, added_in_diff, fail_before)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",
        )
        .bind(run_id)
        .bind(&t.id)
        .bind(&t.kind)
        .bind(&t.status)
        .bind(&t.attempts)
        .bind(t.duration_ms)
        .bind(&t.output_sha256)
        .bind(t.added_in_diff)
        .bind(&t.fail_before)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    }
    for m in &b.mutants {
        sqlx::query(
            "INSERT INTO mutant_results (run_id, mutant, file, line, outcome, caught_by, diff_sha256)
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
        )
        .bind(run_id)
        .bind(&m.mutant)
        .bind(&m.file)
        .bind(m.line)
        .bind(&m.outcome)
        .bind(&m.caught_by)
        .bind(&m.diff_sha256)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    }
    for l in &b.links {
        sqlx::query(
            "INSERT INTO acceptance_links (run_id, acceptance_id, requirement_id, test_id, source)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        )
        .bind(run_id)
        .bind(&l.acceptance_id)
        .bind(&l.requirement_id)
        .bind(&l.test_id)
        .bind(&l.source)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    }
    for bl in &b.blobs {
        sqlx::query(
            "INSERT INTO evidence_blobs (sha256, media_type, size, uri) VALUES ($1,$2,$3,$4)
             ON CONFLICT (sha256) DO NOTHING",
        )
        .bind(&bl.sha256)
        .bind(&bl.media_type)
        .bind(bl.size)
        .bind(&bl.uri)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    }
    tx.commit().await.map_err(ApiError::internal)?;
    Ok(Json(json!({"run_id": run_id, "ledger_seq": seq.seq})))
}

/// The public evidence page for one feature: what was tested, what the results were, and
/// which acceptance criterion each test proves.
async fn get_evidence(State(st): State<AppState>, Path(id): Path<i64>) -> R<Value> {
    let it = load_intent(&st, id).await?;
    type RunRow = (
        i64,
        String,
        Option<String>,
        String,
        String,
        String,
        Value,
        String,
        Option<i64>,
        bool,
        chrono::DateTime<Utc>,
    );
    let runs: Vec<RunRow> = sqlx::query_as(
        "SELECT id, head_sha, parent_sha, gate, check_name, run_url, env, manifest_sha256,
                ledger_seq, simulated, created_at
         FROM evidence_runs WHERE intent_id = $1 ORDER BY id DESC",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await
    .map_err(ApiError::internal)?;

    let mut out = Vec::new();
    for r in &runs {
        let tests: Vec<(String, String, String, Option<i64>, bool, String)> = sqlx::query_as(
            "SELECT test_id, kind, status, duration_ms, added_in_diff, fail_before
             FROM test_results WHERE run_id = $1 ORDER BY test_id",
        )
        .bind(r.0)
        .fetch_all(&st.pool)
        .await
        .map_err(ApiError::internal)?;
        let links: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT acceptance_id, requirement_id, test_id, source FROM acceptance_links
             WHERE run_id = $1 ORDER BY acceptance_id",
        )
        .bind(r.0)
        .fetch_all(&st.pool)
        .await
        .map_err(ApiError::internal)?;
        let mutants: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT mutant, file, outcome, caught_by FROM mutant_results WHERE run_id = $1
             ORDER BY outcome, mutant",
        )
        .bind(r.0)
        .fetch_all(&st.pool)
        .await
        .map_err(ApiError::internal)?;

        let passed = tests.iter().filter(|t| t.2 == "pass").count();
        let failed = tests.iter().filter(|t| t.2 == "fail").count();
        // A test that already passed on the parent commit proves nothing about this change.
        let discriminating = tests.iter().filter(|t| t.5 == "fail").count();
        let caught = mutants.iter().filter(|m| m.2 == "caught").count();
        out.push(json!({
            "run_id": r.0, "head_sha": r.1, "parent_sha": r.2, "gate": r.3,
            "check_name": r.4, "run_url": r.5, "env": r.6,
            "manifest_sha256": r.7, "ledger_seq": r.8,
            // Never show a local dry run as a real pass.
            "simulated": r.9, "created_at": r.10,
            "totals": {"tests": tests.len(), "passed": passed, "failed": failed,
                       "discriminating": discriminating,
                       "mutants": mutants.len(), "mutants_caught": caught},
            "tests": tests.iter().map(|t| json!({"id": t.0, "kind": t.1, "status": t.2,
                "duration_ms": t.3, "added_in_diff": t.4, "fail_before": t.5})).collect::<Vec<_>>(),
            "acceptance_links": links.iter().map(|l| json!({"acceptance_id": l.0,
                "requirement_id": l.1, "test_id": l.2, "source": l.3})).collect::<Vec<_>>(),
            "mutants": mutants.iter().map(|m| json!({"mutant": m.0, "file": m.1,
                "outcome": m.2, "caught_by": m.3})).collect::<Vec<_>>(),
        }));
    }

    let spec: Spec = serde_json::from_value(it.spec.clone()).unwrap_or_default();
    Ok(Json(json!({
        "intent_id": id,
        "requirements": spec.requirements,
        "acceptance_tests": spec.acceptance_tests,
        "runs": out,
        "note": "Evidence rows are append-only: once written, a result cannot be edited or deleted."
    })))
}
