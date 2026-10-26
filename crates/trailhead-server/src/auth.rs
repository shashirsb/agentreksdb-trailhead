//! GitHub sign-in and sessions. The session cookie holds a random token; only its SHA-256 is
//! stored, so a database leak does not leak live sessions.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::api::{ApiError, AppState};
use crate::db::{self, UserRow};

pub const COOKIE: &str = "th_session";
const STATE_COOKIE: &str = "th_oauth_state";

fn token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn hash(t: &str) -> String {
    hex::encode(Sha256::digest(t.as_bytes()))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn set_cookie(name: &str, value: &str, max_age: i64, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
    .expect("cookie header")
}

pub async fn current_user(st: &AppState, headers: &HeaderMap) -> Result<Option<UserRow>, ApiError> {
    let Some(t) = cookie_value(headers, COOKIE) else {
        return Ok(None);
    };
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1 AND s.expires_at > now()",
    )
    .bind(hash(&t))
    .fetch_optional(&st.pool)
    .await
    .map_err(ApiError::internal)?;
    Ok(row)
}

pub async fn require_user(st: &AppState, headers: &HeaderMap) -> Result<UserRow, ApiError> {
    let u = current_user(st, headers).await?.ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "sign_in_required",
            "Sign in with GitHub first.",
            "Use the Sign in button.",
        )
    })?;
    if let Some(until) = u.banned_until {
        if until > Utc::now() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "banned",
                &format!("This account is suspended until {}.", until.format("%Y-%m-%d")),
                "Three burned stakes trigger a 30-day suspension. Appeals go to the governing body.",
            ));
        }
    }
    Ok(u)
}

async fn start_session(st: &AppState, user_id: i64) -> Result<HeaderValue, ApiError> {
    let t = token();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1,$2,$3)")
        .bind(hash(&t))
        .bind(user_id)
        .bind(Utc::now() + Duration::days(30))
        .execute(&st.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(set_cookie(
        COOKIE,
        &t,
        30 * 86400,
        st.cfg.public_url.starts_with("https://"),
    ))
}

/// Create or refresh a user, applying bootstrap governors from config and the monthly grant.
/// Create or refresh a user. Real users are keyed by GitHub's numeric account id, never by login:
/// logins can be renamed and re-registered by someone else. Bootstrap governors come from
/// TRAILHEAD_GOVERNOR_IDS (numeric ids). A login listed in TRAILHEAD_GOVERNORS is honoured only the
/// first time that login is ever seen, so a freed login cannot inherit governor rights.
pub async fn upsert_user(
    st: &AppState,
    github_id: Option<i64>,
    login: &str,
    account_created_at: Option<chrono::DateTime<Utc>>,
) -> Result<UserRow, ApiError> {
    let created = account_created_at.unwrap_or_else(Utc::now);
    let mut tx = st.pool.begin().await.map_err(ApiError::internal)?;
    // Serialise sign-ups for the same login so the checks below cannot race.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(login.to_lowercase())
        .execute(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    let existing: Option<UserRow> = match github_id {
        Some(gid) => sqlx::query_as("SELECT * FROM users WHERE github_id = $1")
            .bind(gid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?,
        None => sqlx::query_as("SELECT * FROM users WHERE login = $1 AND github_id IS NULL")
            .bind(login)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?,
    };
    // Someone else holds this login in our table (they renamed on GitHub, or it is a dev account):
    // move them aside so the login is free, and remember that this login has history.
    let squatter: Option<UserRow> =
        sqlx::query_as("SELECT * FROM users WHERE lower(login) = lower($1) AND id <> $2")
            .bind(login)
            .bind(existing.as_ref().map(|u| u.id).unwrap_or(-1))
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
    let login_had_history = squatter.is_some()
        || sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM events WHERE kind = 'user.joined' AND lower(payload->>'login') = lower($1))",
        )
        .bind(login)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::internal)?;
    if let Some(old) = &squatter {
        let moved = format!("{}~renamed-{}", old.login, old.id);
        sqlx::query("UPDATE users SET login = $2 WHERE id = $1")
            .bind(old.id)
            .bind(&moved)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
        db::append_event(
            &mut tx,
            "user.login_released",
            None,
            "auth",
            json!({"login": login, "previous_holder": old.id, "now": moved}),
        )
        .await
        .map_err(ApiError::internal)?;
    }
    let gov_by_id = github_id
        .map(|g| st.cfg.governor_ids.contains(&g))
        .unwrap_or(false);
    let gov_by_login = st.cfg.bootstrap_governors.contains(&login.to_lowercase())
        && !login_had_history
        && existing.is_none();
    let user = match existing {
        Some(u) => sqlx::query_as::<_, UserRow>(
            "UPDATE users SET login = $2, is_governor = is_governor OR $3 WHERE id = $1 RETURNING *",
        )
        .bind(u.id)
        .bind(login)
        .bind(gov_by_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::internal)?,
        None => {
            let gov = gov_by_id || gov_by_login;
            let u = sqlx::query_as::<_, UserRow>(
                "INSERT INTO users (github_id, login, account_created_at, is_governor) VALUES ($1,$2,$3,$4) RETURNING *",
            )
            .bind(github_id)
            .bind(login)
            .bind(created)
            .bind(gov)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::internal)?;
            db::append_event(&mut tx, "user.joined", None, login, json!({"login": login, "github_id": github_id, "governor": gov}))
                .await
                .map_err(ApiError::internal)?;
            u
        }
    };
    tx.commit().await.map_err(ApiError::internal)?;
    let tier = crate::users::tier_of(&st.pool, &user)
        .await
        .map_err(ApiError::internal)?;
    db::ensure_monthly_grant(&st.pool, user.id, tier.monthly_credits())
        .await
        .map_err(ApiError::internal)?;
    Ok(user)
}

pub async fn github_login(State(st): State<AppState>) -> Result<Response, ApiError> {
    let Some(client_id) = st.cfg.github_client_id.clone() else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth_not_configured",
            "GitHub sign-in is not configured on this server.",
            "Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, or TRAILHEAD_DEV_LOGIN=1 for local runs.",
        ));
    };
    let state = token();
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={client_id}&scope=read:user%20user:email&state={state}&redirect_uri={}/auth/github/callback",
        st.cfg.public_url
    );
    let mut resp = Redirect::to(&url).into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(
            STATE_COOKIE,
            &state,
            600,
            st.cfg.public_url.starts_with("https://"),
        ),
    );
    Ok(resp)
}

#[derive(Deserialize)]
pub struct Callback {
    code: String,
    state: String,
}

pub async fn github_callback(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<Callback>,
) -> Result<Response, ApiError> {
    if cookie_value(&headers, STATE_COOKIE).as_deref() != Some(q.state.as_str()) {
        return Err(ApiError::bad(
            "oauth_state",
            "Sign-in state did not match.",
            "Start sign-in again.",
        ));
    }
    let (Some(id), Some(secret)) = (
        st.cfg.github_client_id.clone(),
        st.cfg.github_client_secret.clone(),
    ) else {
        return Err(ApiError::bad(
            "oauth_not_configured",
            "GitHub sign-in is not configured.",
            "",
        ));
    };
    let tok: serde_json::Value = st
        .http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&json!({"client_id": id, "client_secret": secret, "code": q.code}))
        .send()
        .await
        .map_err(ApiError::internal)?
        .json()
        .await
        .map_err(ApiError::internal)?;
    let access = tok["access_token"].as_str().ok_or_else(|| {
        ApiError::bad(
            "oauth_failed",
            "GitHub did not return a token.",
            "Try signing in again.",
        )
    })?;
    let gh: serde_json::Value = st
        .http
        .get("https://api.github.com/user")
        .bearer_auth(access)
        .header("User-Agent", "agentreks-trailhead")
        .send()
        .await
        .map_err(ApiError::internal)?
        .json()
        .await
        .map_err(ApiError::internal)?;
    let login = gh["login"]
        .as_str()
        .ok_or_else(|| ApiError::bad("oauth_failed", "No GitHub login returned.", ""))?;
    let created = gh["created_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc));
    let user = upsert_user(&st, gh["id"].as_i64(), login, created).await?;
    let cookie = start_session(&st, user.id).await?;
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().append(header::SET_COOKIE, cookie);
    resp.headers_mut()
        .append(header::SET_COOKIE, set_cookie(STATE_COOKIE, "", 0, false));
    Ok(resp)
}

#[derive(Deserialize)]
pub struct DevLogin {
    login: String,
    /// Days since the (pretend) GitHub account was created; defaults to 400.
    account_age_days: Option<i64>,
}

pub async fn dev_login(
    State(st): State<AppState>,
    Json(b): Json<DevLogin>,
) -> Result<Response, ApiError> {
    if !st.cfg.dev_login {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "Not found.",
            "",
        ));
    }
    let login = b.login.trim();
    if login.is_empty()
        || login.len() > 39
        || !login.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::bad(
            "bad_login",
            "Use a GitHub-style login: letters, digits and dashes.",
            "",
        ));
    }
    let created = Utc::now() - Duration::days(b.account_age_days.unwrap_or(400));
    let user = upsert_user(&st, None, login, Some(created)).await?;
    let cookie = start_session(&st, user.id).await?;
    let mut resp = Json(json!({"ok": true, "login": user.login})).into_response();
    resp.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(resp)
}

pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    if let Some(t) = cookie_value(&headers, COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(hash(&t))
            .execute(&st.pool)
            .await
            .map_err(ApiError::internal)?;
    }
    let mut resp = (StatusCode::OK, Json(json!({"ok": true}))).into_response();
    resp.headers_mut()
        .append(header::SET_COOKIE, set_cookie(COOKIE, "", 0, false));
    Ok(resp)
}
