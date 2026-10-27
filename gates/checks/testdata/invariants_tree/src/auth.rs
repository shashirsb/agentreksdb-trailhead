//! Synthetic fixture for gates/checks/invariants.py. NOT REAL CODE.
//! This file exists so `authz.helper-exists` (a tree_count invariant) passes here; the
//! invariants_tree_deleted/ fixture is the same tree with this helper removed.

use axum::http::HeaderMap;

pub async fn require_user(st: &AppState, headers: &HeaderMap) -> Result<UserRow, ApiError> {
    let token = cookie_value(headers, "th_session").ok_or(ApiError::Unauthorized)?;
    db::session_user(&st.pool, &hash(&token))
        .await?
        .ok_or(ApiError::Unauthorized)
}

pub async fn require_admin(st: &AppState, headers: &HeaderMap) -> Result<UserRow, ApiError> {
    let u = require_user(st, headers).await?;
    if !u.is_admin {
        return Err(ApiError::Forbidden);
    }
    Ok(u)
}
