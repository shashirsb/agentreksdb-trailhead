//! Synthetic fixture for gates/checks/invariants.py. NOT REAL CODE.
//! Contains deliberate violations; see testdata/README.md for the expected findings.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;

use crate::auth::require_user;

/// GOOD: authorizes before doing anything.
pub async fn get_intent(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let user = require_user(&st, &headers).await?;
    Ok(Json(json!({ "id": id, "owner": user.id })))
}

/// VIOLATION authz.handler-authorizes: the authorization call was deleted. The body still
/// mentions it in a comment — which is why the checker blanks comments before matching.
/// let user = require_user(&st, &headers).await?;
pub async fn governor_decide(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<Decision>,
) -> Result<Json<Value>, ApiError> {
    db::set_decision(&st.pool, id, body.decision).await?;
    Ok(Json(json!({ "ok": true })))
}

/// VIOLATION authz.handler-authorizes: a string that looks like the helper is not the helper.
pub async fn kill_switch(State(st): State<AppState>, headers: HeaderMap) -> Result<(), ApiError> {
    tracing::info!("require_user(&st, &headers)");
    st.set_kill_switch(true).await?;
    Ok(())
}

/// ALLOWED: `healthz` is in allow_fns — a liveness probe with no data.
pub async fn healthz(State(_st): State<AppState>) -> &'static str {
    "ok"
}

/// Not selected: takes no extractor, so it is not reachable from the router.
pub fn render_intent(row: &IntentRow) -> String {
    format!("intent {}", row.id)
}
