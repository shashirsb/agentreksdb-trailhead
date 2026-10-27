//! `trailhead` — server, worker and CLI for the AgentreksDB contribution portal.
//!
//! ```text
//! trailhead serve            # API + web UI + in-process worker and train clock
//! trailhead worker           # worker only (scale out separately)
//! trailhead migrate          # apply database migrations
//! trailhead policy check     # the diff-policy gate, used by gate-diff-policy.yml
//! trailhead conformance check # does the diff only do what the spec asked for?
//! trailhead doctor           # is everything this deployment depends on actually working?
//! trailhead guardrails FILE  # evaluate a prompt against the guardrail rules
//! trailhead ledger verify    # recompute the whole public hash chain
//! trailhead verify SHA       # show the provenance of a commit from a Trailhead server
//! trailhead keygen           # print a new ledger signing key
//! trailhead model-proxy      # key-injecting, model-pinning proxy for sandboxes
//! ```

// Neither crate needs `unsafe`, and the compiler is a better guard than a regex. `forbid` (not
// `deny`) is the point: a generated patch cannot re-enable it with a local `#[allow]` or an
// `#[expect]`, both of which the diff-policy rules would otherwise have to chase by hand.
#![forbid(unsafe_code)]

mod api;
mod auth;
mod config;
mod db;
mod doctor;
mod github;
mod interviewer;
mod proxy;
mod sandbox;
mod signals;
mod users;
mod worker;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use trailhead_core::{diffpolicy, guardrails, ledger};

#[derive(Parser)]
#[command(
    name = "trailhead",
    version,
    about = "The portal where AgentreksDB is written only by AI from public intent"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the API, web UI, worker and train clock.
    Serve {
        /// Do not run the worker in this process.
        #[arg(long)]
        no_worker: bool,
    },
    /// Run only the pipeline worker and train clock.
    Worker,
    /// Apply database migrations.
    Migrate,
    /// Diff-policy gate.
    /// Check every outside dependency (database, model API, GitHub App) and report what is wrong.
    Doctor,
    /// Check that a diff only does what its spec asked for.
    Conformance {
        #[command(subcommand)]
        cmd: ConformanceCmd,
    },
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Evaluate a prompt file (or stdin with `-`) against the guardrail rules.
    Guardrails { file: PathBuf },
    /// Check that every acceptance criterion in a spec is backed by a real test.
    ///
    /// `--tests` takes a JSON array of {id, covers[], added_in_diff, fail_before}. The gate
    /// builds it from `cargo nextest list --message-format json` plus the `trailhead:` doc
    /// comments in the source.
    Trace {
        /// Spec JSON (the `spec` field of GET /api/intents/:id).
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        tests: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Public ledger tools.
    Ledger {
        #[command(subcommand)]
        cmd: LedgerCmd,
    },
    /// Look up a commit's provenance on a Trailhead server.
    Verify {
        sha: String,
        #[arg(long, env = "TRAILHEAD_URL", default_value = "http://127.0.0.1:8080")]
        api: String,
    },
    /// Generate a ledger signing key (hex seed).
    Keygen,
    /// Key-injecting, model-pinning proxy that sandboxes use to reach the model provider.
    ModelProxy {
        #[arg(long, default_value = "0.0.0.0:8888")]
        bind: String,
        #[arg(long, default_value = "https://api.anthropic.com")]
        upstream: String,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Check a diff manifest; prints the verdict JSON and exits 1 on block.
    Check {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "gates/diff-policy.toml")]
        policy: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConformanceCmd {
    /// Check a diff manifest against the spec that justified it; exits 1 on block.
    Check {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        spec: PathBuf,
        /// Optional hunk → requirement map the generator emits. Without it, tracing is skipped
        /// rather than failing every file, so the gate can ship before the generator emits one.
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LedgerCmd {
    /// Recompute every hash from genesis (reads the database directly).
    Verify,
    /// Verify a public Trailhead ledger over HTTP without trusting the server: fetch every event,
    /// recompute the chain, and check the server's signed checkpoint against a pinned public key.
    VerifyRemote {
        #[arg(long, env = "TRAILHEAD_URL")]
        api: String,
        /// The ledger public key (hex), published out of band and pinned by the verifier.
        #[arg(long, env = "TRAILHEAD_LEDGER_PUBKEY")]
        pubkey: String,
        /// Also require that event SEQ is `generation.result` for INTENT with this patch hash and base.
        #[arg(long, requires_all = ["intent", "patch_sha256", "base"])]
        seq: Option<i64>,
        #[arg(long)]
        intent: Option<i64>,
        #[arg(long)]
        patch_sha256: Option<String>,
        #[arg(long)]
        base: Option<String>,
    },
}

async fn state(cfg: config::Config) -> anyhow::Result<api::AppState> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&cfg.database_url)
        .await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    let key = match cfg.ledger_key_hex.as_deref() {
        Some(k) => ledger::signing_key(Some(k))?,
        None => {
            // Persist a generated key so checkpoints stay verifiable across restarts.
            let stored = db::setting(&pool, "ledger_key_seed").await?;
            match stored {
                Some(s) => ledger::signing_key(Some(&s))?,
                None => {
                    tracing::warn!("TRAILHEAD_LEDGER_KEY not set; generating one and storing it in the database (fine for local runs only)");
                    let k = ledger::signing_key(None)?;
                    let mut tx = pool.begin().await?;
                    db::set_setting(&mut tx, "ledger_key_seed", &hex::encode(k.to_bytes())).await?;
                    tx.commit().await?;
                    k
                }
            }
        }
    };
    Ok(api::AppState {
        pool,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?,
        guardrails: Arc::new(guardrails::Policy::default_policy()),
        diff_policy: Arc::new(diffpolicy::Policy::parse(worker::DIFF_POLICY)?),
        ledger_key: Arc::new(key),
        cfg: Arc::new(cfg),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve { no_worker } => {
            let st = state(config::Config::from_env()?).await?;
            if !no_worker {
                tokio::spawn(worker::run(st.clone()));
            }
            let bind = st.cfg.bind.clone();
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!(
                "Trailhead listening on http://{bind} (model {})",
                st.cfg.agent.generation.model_id
            );
            axum::serve(
                listener,
                api::router(st).layer(tower_http::trace::TraceLayer::new_for_http()),
            )
            .await?;
        }
        Cmd::Worker => worker::run(state(config::Config::from_env()?).await?).await,
        Cmd::Migrate => {
            let cfg = config::Config::from_env()?;
            let pool = sqlx::PgPool::connect(&cfg.database_url).await?;
            sqlx::migrate!("../../migrations").run(&pool).await?;
            println!("migrations applied");
        }
        Cmd::Policy {
            cmd:
                PolicyCmd::Check {
                    manifest,
                    policy,
                    out,
                },
        } => {
            let m: diffpolicy::Manifest = serde_json::from_slice(&std::fs::read(&manifest)?)?;
            let p = diffpolicy::Policy::parse(&std::fs::read_to_string(&policy)?)?;
            let v = p.check(&m);
            let s = serde_json::to_string_pretty(&v)?;
            println!("{s}");
            if let Some(o) = out {
                std::fs::write(o, &s)?;
            }
            if v.verdict == diffpolicy::Outcome::Block {
                std::process::exit(1);
            }
        }
        Cmd::Doctor => {
            let code = doctor::run(&config::Config::from_env()?).await?;
            std::process::exit(code);
        }
        Cmd::Conformance {
            cmd:
                ConformanceCmd::Check {
                    manifest,
                    spec,
                    trace,
                    out,
                },
        } => {
            let m: diffpolicy::Manifest = serde_json::from_slice(&std::fs::read(&manifest)?)?;
            let sp: trailhead_core::spec::Spec = serde_json::from_slice(&std::fs::read(&spec)?)?;
            let tm: trailhead_core::conformance::TraceMap = match &trace {
                Some(p) => serde_json::from_slice(&std::fs::read(p)?)?,
                None => Default::default(),
            };
            let r = trailhead_core::conformance::check(&sp, &m, &tm);
            let s = serde_json::to_string_pretty(&r)?;
            println!("{s}");
            if let Some(o) = out {
                std::fs::write(o, &s)?;
            }
            if r.blocked() {
                std::process::exit(1);
            }
        }
        Cmd::Trace { spec, tests, out } => {
            let sp: trailhead_core::spec::Spec = serde_json::from_slice(&std::fs::read(&spec)?)?;
            let ts: Vec<trailhead_core::trace::TestCase> =
                serde_json::from_slice(&std::fs::read(&tests)?)?;
            let r = trailhead_core::trace::report(&sp, &ts);
            let s = serde_json::to_string_pretty(&r)?;
            println!("{s}");
            if let Some(o) = out {
                std::fs::write(o, &s)?;
            }
            // A criterion with no test behind it is a promise nobody kept, so the gate blocks.
            if !r.ok {
                std::process::exit(1);
            }
        }
        Cmd::Guardrails { file } => {
            let text = if file.as_os_str() == "-" {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                s
            } else {
                std::fs::read_to_string(file)?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &guardrails::Policy::default_policy().evaluate(&text)
                )?
            );
        }
        Cmd::Ledger {
            cmd: LedgerCmd::Verify,
        } => {
            let cfg = config::Config::from_env()?;
            let pool = sqlx::PgPool::connect(&cfg.database_url).await?;
            let r = api::verify_chain(&pool).await?;
            println!("{}", serde_json::to_string_pretty(&r)?);
            if !r.ok {
                std::process::exit(1);
            }
        }
        Cmd::Ledger {
            cmd:
                LedgerCmd::VerifyRemote {
                    api,
                    pubkey,
                    seq,
                    intent,
                    patch_sha256,
                    base,
                },
        } => {
            let api = api.trim_end_matches('/').to_string();
            let http = reqwest::Client::new();
            // Checkpoint first: its seq bounds the events we must reproduce.
            let cp: serde_json::Value = http
                .get(format!("{api}/api/ledger/checkpoint"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let cp_seq = cp["seq"].as_i64().unwrap_or(0);
            let cp_head = cp["head"].as_str().unwrap_or_default().to_string();
            let sig = cp["signature"].as_str().unwrap_or_default();
            if !ledger::verify_checkpoint(&pubkey, cp_seq, &cp_head, sig) {
                anyhow::bail!("checkpoint signature does not verify against the pinned public key");
            }
            let mut prev = ledger::GENESIS.to_string();
            let mut after = 0i64;
            let mut target: Option<ledger::Event> = None;
            while after < cp_seq {
                let page: serde_json::Value = http
                    .get(format!("{api}/api/ledger?after={after}&limit=500"))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                let events: Vec<ledger::Event> = serde_json::from_value(page["events"].clone())?;
                if events.is_empty() {
                    anyhow::bail!("ledger ended at seq {after}, checkpoint claims {cp_seq}");
                }
                let events: Vec<ledger::Event> =
                    events.into_iter().take_while(|e| e.seq <= cp_seq).collect();
                if events.first().map(|e| e.seq) != Some(after + 1) {
                    anyhow::bail!("gap in ledger after seq {after}");
                }
                let r = ledger::verify(&prev, &events);
                if !r.ok {
                    anyhow::bail!("hash chain broken at seq {:?}", r.first_bad_seq);
                }
                if let Some(want) = seq {
                    if let Some(e) = events.iter().find(|e| e.seq == want) {
                        target = Some(e.clone());
                    }
                }
                prev = r.head;
                after = events.last().map(|e| e.seq).unwrap_or(after);
            }
            if prev != cp_head {
                anyhow::bail!("recomputed head {prev} != signed checkpoint head {cp_head}");
            }
            if let Some(want) = seq {
                let e = target.ok_or_else(|| {
                    anyhow::anyhow!("seq {want} is not covered by the signed checkpoint")
                })?;
                let ok = e.kind == "generation.result"
                    && e.intent_id == intent
                    && e.payload["patch_sha256"].as_str() == patch_sha256.as_deref()
                    && e.payload["base"].as_str() == base.as_deref()
                    && e.payload["discarded"].as_bool() != Some(true);
                if !ok {
                    anyhow::bail!("event {want} is not the generation result for intent {intent:?} with that patch and base");
                }
            }
            println!(
                "{}",
                serde_json::json!({"ok": true, "checked_through": cp_seq, "head": cp_head})
            );
        }
        Cmd::Verify { sha, api } => {
            let v: serde_json::Value =
                reqwest::get(format!("{}/api/verify/{sha}", api.trim_end_matches('/')))
                    .await?
                    .json()
                    .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            if v["found"] != true {
                std::process::exit(1);
            }
        }
        Cmd::ModelProxy { bind, upstream } => {
            let key = std::env::var("ANTHROPIC_API_KEY")
                .map_err(|_| anyhow::anyhow!("ANTHROPIC_API_KEY is required"))?;
            let agent_path =
                std::env::var("TRAILHEAD_AGENT_TOML").unwrap_or_else(|_| "agent.toml".into());
            let agent: config::AgentFile = toml::from_str(&std::fs::read_to_string(agent_path)?)?;
            // Generation model plus the small model the harness uses for housekeeping, if configured.
            let mut allowed = vec![agent.generation.model_id.clone()];
            if let Ok(extra) = std::env::var("TRAILHEAD_PROXY_EXTRA_MODELS") {
                allowed.extend(
                    extra
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                );
            }
            let token = std::env::var("TRAILHEAD_PROXY_TOKEN")
                .map_err(|_| anyhow::anyhow!("TRAILHEAD_PROXY_TOKEN is required (sandboxes present it instead of an API key)"))?;
            proxy::serve(&bind, key, token, upstream, allowed).await?;
        }
        Cmd::Keygen => {
            let k = ledger::signing_key(None)?;
            println!("TRAILHEAD_LEDGER_KEY={}", hex::encode(k.to_bytes()));
            println!(
                "# public key: {}",
                hex::encode(k.verifying_key().to_bytes())
            );
        }
    }
    Ok(())
}
