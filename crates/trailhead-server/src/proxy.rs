//! `trailhead model-proxy`: the only door from a sandbox to the model provider.
//!
//! Sandboxes run with no internet route except this proxy, and with a placeholder API key. The proxy
//! drops whatever credentials the sandbox sends, injects the real key, allows only the Messages API,
//! and pins the model: a request for any model other than the pinned ones is refused. So a compromised
//! sandbox can neither read the key nor switch models. The request body is rebuilt from an allow-list
//! (no `mcp_servers`, no server-side tools such as web fetch or code execution), so the model provider
//! cannot be used as a second egress path, and the proxy itself requires a shared token.

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::sync::Arc;

#[derive(Clone)]
struct P {
    key: Arc<String>,
    token: Arc<String>,
    upstream: Arc<String>,
    allowed_models: Arc<Vec<String>>,
    http: reqwest::Client,
}

pub async fn serve(
    bind: &str,
    key: String,
    token: String,
    upstream: String,
    allowed_models: Vec<String>,
) -> anyhow::Result<()> {
    if token.len() < 16 {
        anyhow::bail!("TRAILHEAD_PROXY_TOKEN must be at least 16 characters");
    }
    let st = P {
        key: Arc::new(key),
        token: Arc::new(token),
        upstream: Arc::new(upstream.trim_end_matches('/').to_string()),
        allowed_models: Arc::new(allowed_models),
        http: reqwest::Client::new(),
    };
    let app = Router::new().fallback(forward).with_state(st);
    let l = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("model proxy on {bind}");
    axum::serve(l, app).await?;
    Ok(())
}

const BODY_KEYS: [&str; 13] = [
    "model",
    "messages",
    "system",
    "max_tokens",
    "temperature",
    "top_p",
    "top_k",
    "stop_sequences",
    "stream",
    "metadata",
    "tools",
    "tool_choice",
    "thinking",
];

/// Rebuild the request from allowed fields only, refusing unpinned models and server-side tools.
pub fn sanitize(body: &[u8], allowed: &[String]) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "body is not JSON".to_string())?;
    let obj = v.as_object().ok_or("body must be a JSON object")?;
    let m = obj
        .get("model")
        .and_then(|m| m.as_str())
        .ok_or("request names no model")?;
    if !allowed.iter().any(|a| a == m) {
        return Err(format!("model {m} is not pinned"));
    }
    let mut out = serde_json::Map::new();
    for k in BODY_KEYS {
        if let Some(val) = obj.get(k) {
            out.insert(k.to_string(), val.clone());
        }
    }
    if let Some(tools) = out.get("tools").and_then(|t| t.as_array()) {
        for t in tools {
            // Client tools (name + input_schema, optionally type "custom") run in the sandbox.
            // Typed server tools (web_search_*, web_fetch_*, code_execution_*, ...) would run at the
            // provider and reach the internet, so they are refused.
            if let Some(ty) = t.get("type").and_then(|x| x.as_str()) {
                if ty != "custom" {
                    return Err(format!("tool type {ty} is not allowed"));
                }
            }
        }
    }
    serde_json::to_vec(&serde_json::Value::Object(out)).map_err(|e| e.to_string())
}

const BLOCKED_BETAS: [&str; 7] = [
    "mcp",
    "web-fetch",
    "web-search",
    "code-execution",
    "files-api",
    "computer-use",
    "skills",
];

fn filter_betas(v: &str) -> String {
    v.split(',')
        .map(str::trim)
        .filter(|b| !b.is_empty() && !BLOCKED_BETAS.iter().any(|x| b.contains(x)))
        .collect::<Vec<_>>()
        .join(",")
}

async fn forward(
    State(st): State<P>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path();
    if method != Method::POST || !(path == "/v1/messages" || path == "/v1/messages/count_tokens") {
        return (StatusCode::FORBIDDEN, "only POST /v1/messages is allowed").into_response();
    }
    let presented = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .unwrap_or("");
    if presented.len() != st.token.len()
        || presented
            .bytes()
            .zip(st.token.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            != 0
    {
        return (StatusCode::UNAUTHORIZED, "bad proxy token").into_response();
    }
    let clean = match sanitize(&body, &st.allowed_models) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("refused: {e}");
            return (StatusCode::FORBIDDEN, e).into_response();
        }
    };
    let mut req = st
        .http
        .post(format!("{}{}", st.upstream, path))
        .header("x-api-key", st.key.as_str())
        .header("content-type", "application/json")
        .body(clean);
    for h in ["anthropic-version", "accept"] {
        if let Some(v) = headers.get(h) {
            req = req.header(h, v);
        }
    }
    if let Some(b) = headers.get("anthropic-beta").and_then(|v| v.to_str().ok()) {
        let kept = filter_betas(b);
        if !kept.is_empty() {
            req = req.header("anthropic-beta", kept);
        }
    }
    match req.send().await {
        Ok(r) => {
            let status =
                StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let ct = r.headers().get("content-type").cloned();
            let mut resp = Response::new(Body::from_stream(r.bytes_stream()));
            *resp.status_mut() = status;
            if let Some(ct) = ct {
                resp.headers_mut().insert("content-type", ct);
            }
            resp
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pinned_models_and_known_fields_pass() {
        let allowed = vec!["claude-opus-5-5".to_string()];
        let out = sanitize(br#"{"model":"claude-opus-5-5","messages":[],"mcp_servers":[{"url":"x"}],"container":"c"}"#, &allowed).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("mcp_servers").is_none() && v.get("container").is_none());
        assert!(sanitize(br#"{"model":"other"}"#, &allowed).is_err());
        assert!(sanitize(b"{}", &allowed).is_err());
        // duplicate keys: serde keeps the last, and the forwarded body is our re-serialisation
        let dup = sanitize(br#"{"model":"other","model":"claude-opus-5-5"}"#, &allowed).unwrap();
        assert!(String::from_utf8(dup).unwrap().contains("claude-opus-5-5"));
    }

    #[test]
    fn server_tools_are_refused() {
        let allowed = vec!["m".to_string()];
        assert!(sanitize(
            br#"{"model":"m","tools":[{"name":"Read","input_schema":{}}]}"#,
            &allowed
        )
        .is_ok());
        assert!(sanitize(
            br#"{"model":"m","tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}"#,
            &allowed
        )
        .is_err());
    }

    #[test]
    fn betas_are_filtered() {
        assert_eq!(
            filter_betas("prompt-caching-2024-07-31, mcp-client-2025-04-04,web-fetch-2025-09-10"),
            "prompt-caching-2024-07-31"
        );
    }
}
