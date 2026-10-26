//! GitHub App client. The App is the only identity allowed to push to the target repo; the
//! commit itself is signed by `.github/workflows/commit.yml` (gitsign, workload identity), so
//! no long-lived signing key exists anywhere.

use chrono::Utc;
use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::config::Config;

pub struct GitHub<'a> {
    pub cfg: &'a Config,
    pub http: &'a reqwest::Client,
}

impl<'a> GitHub<'a> {
    fn app_jwt(&self) -> anyhow::Result<String> {
        let app_id = self
            .cfg
            .github_app_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GITHUB_APP_ID not set"))?;
        let pem = self
            .cfg
            .github_app_key_pem
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GitHub App key not set"))?;
        let now = Utc::now().timestamp();
        let claims = json!({"iat": now - 60, "exp": now + 540, "iss": app_id});
        Ok(encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes())?,
        )?)
    }

    async fn installation_token(&self) -> anyhow::Result<String> {
        let inst = self
            .cfg
            .github_installation_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("GITHUB_INSTALLATION_ID not set"))?;
        let v: Value = self
            .http
            .post(format!(
                "https://api.github.com/app/installations/{inst}/access_tokens"
            ))
            .bearer_auth(self.app_jwt()?)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "agentreks-trailhead")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        v["token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("no installation token"))
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<Value> {
        let t = self.installation_token().await?;
        let mut req = self
            .http
            .request(method, format!("https://api.github.com{path}"))
            .bearer_auth(t)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "agentreks-trailhead");
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("GitHub {path} -> {status}: {text}");
        }
        Ok(if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        })
    }

    /// Ask the signing workflow to fetch the bundle, verify it against the ledger, sign and open the PR.
    pub async fn dispatch_commit(&self, intent_id: i64) -> anyhow::Result<()> {
        self.call(
            reqwest::Method::POST,
            &format!(
                "/repos/{}/actions/workflows/commit.yml/dispatches",
                self.cfg.trailhead_repo
            ),
            Some(json!({"ref": "main", "inputs": {"intent_id": intent_id.to_string()}})),
        )
        .await?;
        Ok(())
    }

    pub async fn add_labels(&self, pr: i64, labels: &[String]) -> anyhow::Result<()> {
        self.call(
            reqwest::Method::POST,
            &format!("/repos/{}/issues/{pr}/labels", self.cfg.target_repo),
            Some(json!({"labels": labels})),
        )
        .await?;
        Ok(())
    }

    pub async fn comment(&self, pr: i64, body: &str) -> anyhow::Result<()> {
        self.call(
            reqwest::Method::POST,
            &format!("/repos/{}/issues/{pr}/comments", self.cfg.target_repo),
            Some(json!({"body": body})),
        )
        .await?;
        Ok(())
    }

    /// Merge through the repo's merge queue when one is required, else a plain squash merge is refused
    /// by the ruleset; we always try the queue first.
    pub async fn merge(&self, pr: i64) -> anyhow::Result<()> {
        let pr_v = self
            .call(
                reqwest::Method::GET,
                &format!("/repos/{}/pulls/{pr}", self.cfg.target_repo),
                None,
            )
            .await?;
        let node_id = pr_v["node_id"].as_str().unwrap_or_default().to_string();
        let q = json!({
            "query": "mutation($id: ID!) { enqueuePullRequest(input: {pullRequestId: $id}) { mergeQueueEntry { position } } }",
            "variables": {"id": node_id}
        });
        let r = self
            .call(reqwest::Method::POST, "/graphql", Some(q))
            .await?;
        if r.get("errors").is_some() {
            // No merge queue on this repo: merge directly (the ruleset still requires every check).
            self.call(
                reqwest::Method::PUT,
                &format!("/repos/{}/pulls/{pr}/merge", self.cfg.target_repo),
                Some(json!({"merge_method": "merge"})),
            )
            .await?;
        }
        Ok(())
    }

    pub async fn close(&self, pr: i64) -> anyhow::Result<()> {
        self.call(
            reqwest::Method::PATCH,
            &format!("/repos/{}/pulls/{pr}", self.cfg.target_repo),
            Some(json!({"state": "closed"})),
        )
        .await?;
        Ok(())
    }
}

/// Verify `X-Hub-Signature-256` over the raw body.
pub fn verify_webhook(secret: &str, body: &[u8], header: &str) -> bool {
    let Some(sig_hex) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(sig) = hex::decode(sig_hex) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_signature() {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"s3cret").unwrap();
        mac.update(b"{}");
        let good = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_webhook("s3cret", b"{}", &good));
        assert!(!verify_webhook("other", b"{}", &good));
        assert!(!verify_webhook("s3cret", b"{}", "sha1=abc"));
    }
}
