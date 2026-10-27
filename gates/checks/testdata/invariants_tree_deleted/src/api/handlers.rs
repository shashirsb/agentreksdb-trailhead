//! Synthetic fixture: the same handlers as invariants_tree/, with the authorization helper
//! and all of its call sites DELETED. `authz.helper-exists` is the backstop for this.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;

pub async fn get_intent(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let _ = headers;
    Ok(Json(db::intent(&st.pool, id).await?))
}
