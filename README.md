# Trailhead

**The portal where AgentreksDB is written only by AI, from public intent, forever open source.**

Contributors never upload code. They describe what they want; an interviewer turns that into a precise
spec; one pinned model writes the code in a sealed sandbox on the project's keys; hard gates prove it; a
human governor decides on a weekly train. Every prompt, verdict, decision and credit movement is in a public,
hash-chained ledger that cannot be edited.

```
intent ─▶ spec chat ─▶ guardrails ─▶ generation ─▶ signed commit ─▶ tests·perf ─▶ diff-policy ─▶ governor ─▶ main
 (you)    (validator)   (advisory)   (pinned model,   (gitsign,       (blocking)     (blocking,     (Fri 00:00 PT,
                                      sandbox,         workflow                       aimed at        humans gate,
                                      no keys inside)  identity only)                 malice)         never write)
```

**Money never affects ranking.** Credits buy model inference and nothing else: no term of the queue score, no
vote weight, no review influence, no merge rights, no roadmap say, no naming rights. Community votes outrank
every other term combined — see the formula and its invariants in [CONTRIBUTING.md](CONTRIBUTING.md).

Vulnerabilities go through GitHub private vulnerability reporting or security@agentreks.dev, never a public
issue or intent: see [SECURITY.md](SECURITY.md) for severity bands, fix SLAs and the disclosure window.

The charter is binding: [CHARTER.md](CHARTER.md) (open source forever, no proprietary edition, no CLA),
[GOVERNANCE.md](GOVERNANCE.md), [CONTRIBUTING.md](CONTRIBUTING.md), [docs/TRANSPARENCY.md](docs/TRANSPARENCY.md).

## What is in this repo

| Path | What it is |
| --- | --- |
| `crates/trailhead-core` | Pure, tested rules: spec readiness (EARS + Given/When/Then), guardrails, diff-policy engine, weekly train clock (America/Los_Angeles, DST-safe), hash-chained ledger + signed checkpoints, credits, quadratic votes, reputation tiers, the priority score (no money term), SLSA/in-toto provenance |
| `crates/trailhead-server` | `trailhead` binary: Axum API + web UI, Postgres job-queue worker, GitHub App client, webhook handler, interviewer, sandbox drivers, key-injecting model proxy, CLI (`policy check`, `ledger verify`, `verify`, `keygen`) |
| `migrations/` | Postgres schema; `events` and `credit_entries` are append-only by trigger |
| `web/` | The Trailhead site (three themes, works at 375px) |
| `gates/` | Workflows, policies, CODEOWNERS and ruleset to install into a target repo |
| `.github/workflows/commit.yml` | The only path to a commit: fetch bundle → check hash against ledger → apply → gitsign → PR |
| `deploy/` | Dockerfile, local and production compose (Caddy HTTPS), sandbox image + launcher, one-shot GCP setup (`deploy/gcp/setup.sh`) |
| `site/` | The AgentreksDB website served at www.agentreksdb.com |
| `agent.toml` | The pinned model and generation limits (changing it is a public "model rotation") |
| `scripts/e2e.sh` | End-to-end test against real Postgres and a real test app |

## Run it locally (5 minutes)

```bash
docker compose -f deploy/docker-compose.yml up --build
open http://localhost:8080        # use "Dev sign-in" as `gov` (a governor) or any other name
```

Without Docker: `DATABASE_URL=postgres://… TRAILHEAD_DEV_LOGIN=1 TRAILHEAD_ENFORCE_WINDOW=0 TRAILHEAD_GOVERNORS=gov cargo run -- serve`.

Locally, generation uses the dry-run driver (no model call) and repo-side gates are marked *simulated*;
nothing pretends to be real.

## Test

```bash
cargo test --all                                             # 50+ unit tests
DATABASE_URL=postgres://…/empty_db FAKE_MODEL_REPO=../agentreksdb-trailhead-helloworld scripts/e2e.sh
```

The end-to-end script signs in users, takes an intent through the interviewer to a ready spec, generates a
real code change to the [test app](https://github.com/shashirsb/agentreksdb-trailhead-helloworld) with
`cargo test`, merges it as a governor, proves the diff-policy gate blocks a hidden network call, proves the
guardrails hold a prompt injection before any tokens are spent, checks the Sunday/Friday Pacific train, and
verifies the ledger hash chain and that the database refuses edits to it.

## Go live

One command from a Mac with `gcloud` and `gh` installed:

```bash
bash deploy/gcp/setup.sh
```

It creates the GitHub App (you click Create and Install), asks for the Anthropic key, generates every other
secret, sets both repos' secrets and variables, creates a free-tier e2-micro VM with a static IP, budget
alert, Secret Manager secrets and nightly backups, waits for the GoDaddy DNS records it prints, and waits
until https://www.agentreksdb.com and https://trailhead.agentreksdb.com are live. Manual alternative:
[docs/DEPLOY.md](docs/DEPLOY.md).

## Status

Working MVP, tested end to end locally. Not yet connected to a live GitHub App or model key, so no real
signed PR has been produced yet. The Firecracker sandbox profile is documented, not built; the Docker
profile is the current default.

Apache-2.0. AI-generated files are additionally dedicated to the public domain where copyright does not
subsist (see NOTICE).
