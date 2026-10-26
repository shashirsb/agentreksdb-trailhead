use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Clone, Debug)]
pub struct AgentFile {
    pub generation: Generation,
    pub chat: Chat,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Generation {
    pub model_id: String,
    pub harness: String,
    pub max_budget_usd: f64,
    pub max_turns: u32,
    pub wall_clock_minutes: u64,
    pub allowed_tools: Vec<String>,
    pub terms_version: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Chat {
    pub model_id: String,
    pub max_tokens: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SandboxDriver {
    /// No model call: writes the approved spec into docs/intents/<id>.md. For local runs and tests.
    DryRun,
    /// Runs `TRAILHEAD_SANDBOX_COMMAND` (see deploy/sandbox/run.sh) inside the isolation you provide.
    Command(String),
}

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub bind: String,
    pub public_url: String,
    pub web_dir: PathBuf,
    pub dev_login: bool,
    pub enforce_window: bool,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub github_app_id: Option<String>,
    pub github_app_key_pem: Option<String>,
    pub github_installation_id: Option<String>,
    pub webhook_secret: Option<String>,
    pub target_repo: String,
    pub trailhead_repo: String,
    pub bot_login: String,
    pub tick_token: Option<String>,
    pub ledger_key_hex: Option<String>,
    pub anthropic_api_key: Option<String>,
    pub sandbox: SandboxDriver,
    pub work_dir: PathBuf,
    pub bootstrap_governors: Vec<String>,
    /// GitHub numeric account ids that are governors (preferred over logins, which can be renamed).
    pub governor_ids: Vec<i64>,
    pub daily_budget_credits: i64,
    pub agent: AgentFile,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

fn flag(k: &str, default: bool) -> bool {
    env(k)
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        let agent_path = env("TRAILHEAD_AGENT_TOML").unwrap_or_else(|| "agent.toml".into());
        let agent: AgentFile = toml::from_str(
            &std::fs::read_to_string(&agent_path)
                .map_err(|e| anyhow::anyhow!("reading {agent_path}: {e}"))?,
        )?;
        let key_pem = match env("GITHUB_APP_PRIVATE_KEY_PATH") {
            Some(p) => {
                Some(std::fs::read_to_string(&p).map_err(|e| anyhow::anyhow!("reading {p}: {e}"))?)
            }
            None => env("GITHUB_APP_PRIVATE_KEY"),
        };
        let sandbox = match env("TRAILHEAD_SANDBOX_COMMAND") {
            Some(cmd) if env("TRAILHEAD_SANDBOX").as_deref() == Some("command") => {
                SandboxDriver::Command(cmd)
            }
            _ => SandboxDriver::DryRun,
        };
        Ok(Config {
            database_url: env("DATABASE_URL")
                .ok_or_else(|| anyhow::anyhow!("DATABASE_URL is required"))?,
            bind: env("TRAILHEAD_BIND").unwrap_or_else(|| "127.0.0.1:8080".into()),
            public_url: env("TRAILHEAD_PUBLIC_URL")
                .unwrap_or_else(|| "http://127.0.0.1:8080".into()),
            web_dir: env("TRAILHEAD_WEB_DIR")
                .unwrap_or_else(|| "web".into())
                .into(),
            dev_login: flag("TRAILHEAD_DEV_LOGIN", false),
            enforce_window: flag("TRAILHEAD_ENFORCE_WINDOW", true),
            github_client_id: env("GITHUB_CLIENT_ID"),
            github_client_secret: env("GITHUB_CLIENT_SECRET"),
            github_app_id: env("GITHUB_APP_ID"),
            github_app_key_pem: key_pem,
            github_installation_id: env("GITHUB_INSTALLATION_ID"),
            webhook_secret: env("GITHUB_WEBHOOK_SECRET"),
            target_repo: env("TRAILHEAD_TARGET_REPO")
                .unwrap_or_else(|| "shashirsb/agentreksdb".into()),
            trailhead_repo: env("TRAILHEAD_REPO")
                .unwrap_or_else(|| "shashirsb/agentreksdb-trailhead".into()),
            bot_login: env("TRAILHEAD_BOT_LOGIN")
                .unwrap_or_else(|| "agentreks-trailhead[bot]".into()),
            tick_token: env("TRAILHEAD_TICK_TOKEN"),
            ledger_key_hex: env("TRAILHEAD_LEDGER_KEY"),
            anthropic_api_key: env("ANTHROPIC_API_KEY"),
            sandbox,
            work_dir: env("TRAILHEAD_WORK_DIR")
                .unwrap_or_else(|| "/tmp/trailhead-work".into())
                .into(),
            bootstrap_governors: env("TRAILHEAD_GOVERNORS")
                .map(|s| {
                    s.split(',')
                        .map(|x| x.trim().to_lowercase())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            governor_ids: env("TRAILHEAD_GOVERNOR_IDS")
                .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
                .unwrap_or_default(),
            daily_budget_credits: env("TRAILHEAD_DAILY_BUDGET_CREDITS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(100_000),
            agent,
        })
    }

    pub fn github_app_configured(&self) -> bool {
        self.github_app_id.is_some()
            && self.github_app_key_pem.is_some()
            && self.github_installation_id.is_some()
    }
}
