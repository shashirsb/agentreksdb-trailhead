# Deploying Trailhead

Four pieces: a GitHub App, the Trailhead server (with Postgres), the model proxy + sandbox, and the gates
in the target repo. Start with the test app `shashirsb/agentreksdb-trailhead-helloworld`; switch the target
to `shashirsb/agentreksdb` once a full intent has gone through.

Never paste keys or secrets into chats, issues or intents. Everything in Trailhead is public.

## 1. GitHub App

1. github.com/settings/apps/new → name `agentreks-trailhead` (bot login `agentreks-trailhead[bot]`),
   homepage `https://github.com/shashirsb/agentreksdb-trailhead`.
2. Identifying and authorizing users → callback URL `https://<host>/auth/github/callback`.
3. Webhook → active, URL `https://<host>/api/webhooks/github`, secret = `openssl rand -hex 32`
   (this is `GITHUB_WEBHOOK_SECRET`).
4. Repository permissions: Contents RW, Pull requests RW, Issues RW, Actions RW, Checks R, Metadata R,
   **Workflows: no access** (the bot can never change CI).
5. Events: Pull request, Check run. Installable only on this account.
6. Note the App ID; generate a client secret (with the Client ID) and a private key (`.pem`).
7. Install on `agentreksdb-trailhead` and `agentreksdb-trailhead-helloworld` (later `agentreksdb`).
   The installation ID is the number at the end of the installation settings URL.

## 2. Repo settings (Settings → Secrets and variables → Actions)

`agentreksdb-trailhead` (runs `commit.yml`, the signing workflow)

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `TRAILHEAD_APP_PRIVATE_KEY` | contents of the `.pem` |
| Variable | `TRAILHEAD_APP_ID` | App ID |
| Variable | `TRAILHEAD_URL` | `https://<host>` |
| Variable | `TRAILHEAD_TARGET_REPO` | `shashirsb/agentreksdb-trailhead-helloworld` |
| Variable | `TRAILHEAD_TARGET_REPO_NAME` | `agentreksdb-trailhead-helloworld` |
| Variable | `TRAILHEAD_BOT_LOGIN` | `agentreks-trailhead[bot]` |

Target repo (gates)

| Kind | Name | Value |
| --- | --- | --- |
| Variable | `WORKSPACE_DIR` | `.` for the test app, `agentreksdb` for the database |
| Variable | `TRAILHEAD_URL` | `https://<host>` |
| Variable | `TRAILHEAD_BOT_LOGIN` | `agentreks-trailhead[bot]` |
| Secret | `TRAILHEAD_TICK_TOKEN` | same value as the server's `TRAILHEAD_TICK_TOKEN` |
| Secret (optional) | `OPENAI_KEY` | AI reviewer from a different model family than the generator |

Then apply the ruleset: `gh api -X POST repos/<owner>/<target>/rulesets --input gates/rulesets/main.json`.

## 3. Server

Any small VM or container host with HTTPS and managed Postgres 16 (e.g. Hetzner + Caddy, or Fly.io).

```bash
docker build -t trailhead --build-arg TRAILHEAD_GIT_SHA=$(git rev-parse HEAD) .
trailhead keygen        # → TRAILHEAD_LEDGER_KEY (keep it; publish the public key)
```

Environment: see `.env.example`. Minimum for production: `DATABASE_URL`, `TRAILHEAD_PUBLIC_URL`,
`TRAILHEAD_GOVERNORS=shashirsb`, `TRAILHEAD_TARGET_REPO`, `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_PATH`,
`GITHUB_INSTALLATION_ID`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_WEBHOOK_SECRET`,
`TRAILHEAD_TICK_TOKEN`, `TRAILHEAD_LEDGER_KEY`, `ANTHROPIC_API_KEY` (interviewer),
`TRAILHEAD_SANDBOX=command`, `TRAILHEAD_SANDBOX_COMMAND=deploy/sandbox/launch.sh`.
Leave `TRAILHEAD_DEV_LOGIN` and `TRAILHEAD_ENFORCE_WINDOW` at their defaults (off / on).

## 4. Anthropic key, proxy and sandbox

1. console.anthropic.com → Settings → API keys → create `trailhead-generation`; set a monthly spend limit
   under Settings → Limits.
2. Give the key only to the server (`ANTHROPIC_API_KEY`, for the interviewer) and to the model proxy.
   Sandboxes never get it.
3. Set up the proxy network and sandbox image: [deploy/sandbox/README.md](../deploy/sandbox/README.md).

## 5. First real run

1. Sign in with GitHub at `https://<host>` as `shashirsb` (interim governor).
2. File a small intent against the test app, answer the interviewer until the spec is ready, submit.
3. Watch the ledger: guardrails → generation → `commit.yml` run → PR on the test app → gate checks.
4. In the review window (Sunday 00:00 PT → Friday 00:00 PT) decide it from the Governor page.
5. Run `trailhead verify <sha> --api https://<host>` and `gitsign verify` on the merged commit.
