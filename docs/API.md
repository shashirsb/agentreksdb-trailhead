# Trailhead HTTP API

All responses are JSON. Every read endpoint is public (no auth) because everything in Trailhead is public;
writes need a session cookie (`th_session`) from GitHub sign-in. Errors are
`{"error": {"code": "<stable_code>", "message": "...", "hint": "..."}}` with a 4xx/5xx status.

## Auth
| Method | Path | Notes |
| --- | --- | --- |
| GET | `/auth/github/login` | redirects to GitHub OAuth |
| GET | `/auth/github/callback` | sets `th_session`, redirects to `/` |
| POST | `/auth/logout` | clears the session |
| POST | `/auth/dev-login` `{"login":"alice"}` | only when `TRAILHEAD_DEV_LOGIN=1`; for local runs and tests |
| GET | `/api/me` | `{"user": User \| null}` |

`User = {id, login, tier, rep_points, is_governor, credits_balance, created_at}`
Tiers: `visitor`, `contributor`, `builder`, `steward`, `governor`.

## Intents
`Intent = {id, title, area, author, status, stage, stake_credits, change_type, risk, train, branch, pr_number,
commit_sha, votes, spec, readiness, created_at, updated_at}`

- `status`: `draft` (chat in progress) · `submitted` · `guardrails` · `held` (red guardrail) · `generating` ·
  `gates` · `review` (all gates green, waiting for governor) · `flagged` (a gate blocked) · `merged` · `on_hold` ·
  `rejected`
- `stage` 1–8 matches the pipeline: 1 Portal · 2 Intent chat · 3 Guardrails · 4 Generation · 5 Signed commit ·
  6 Tests·perf · 7 Diff-policy · 8 Governor
- `risk`: `green` | `amber` | `red` | null
- `readiness = {ready: bool, missing: [field], weak: [field], questions: [string]}`

| Method | Path | Body / query | Returns |
| --- | --- | --- | --- |
| GET | `/api/intents` | `?status=&limit=&before=` | `{"intents":[Intent]}` newest first |
| POST | `/api/intents` | `{title, area, intent, stake_credits}` | `{"intent": Intent}` (status `draft`, stake held) |
| GET | `/api/intents/:id` | | `{"intent", "messages":[{role,body,created_at}], "gates":[{gate,verdict,detail,created_at}], "events":[Event], "decision": Decision\|null}` |
| POST | `/api/intents/:id/messages` | `{body}` (author only, status `draft`) | `{"reply": {role:"ai",body}, "spec", "readiness"}` |
| POST | `/api/intents/:id/submit` | (author only; readiness.ready must be true) | `{"intent"}` → status `submitted` |
| POST | `/api/intents/:id/vote` | `{points}` quadratic: cost = points² from 100/quarter | `{"votes", "budget_left"}` |

## Weekly train
| GET | `/api/train` | `{"train": "2026-W44", "now_pt", "cutoff_pt", "decision_pt", "phase": "intake"\|"review", "counts": {...}}` |

Cutoff = Sunday 00:00 America/Los_Angeles; decision = the following Friday 00:00 America/Los_Angeles.

| POST | `/api/train/tick` | `Authorization: Bearer $TRAILHEAD_TICK_TOKEN` | runs cutoff/decision transitions now (the server also ticks every minute) |

## Generation bundles (for the signing workflow)
| GET | `/api/bundles/:intent_id` | `{"intent_id","base","patch_b64","patch_sha256","message","provenance","ledger_seq"}` — the patch the worker produced; `.github/workflows/commit.yml` verifies `patch_sha256` against ledger event `ledger_seq`, applies it, signs with gitsign and opens the PR |

## Governor (governors only)
| GET | `/api/governor/queue` | `{"items":[{intent, gates, ai_review}]}` |
| POST | `/api/governor/:id/decide` | `{decision: "merge"\|"hold"\|"reject", reason}` (reason required) | `{"decision": Decision}` |

`Decision = {intent_id, train, decision, reason, governor, created_at}`

## Public ledger
`Event = {seq, ts, kind, intent_id, actor, payload, prev_hash, hash}`; `hash = sha256(prev_hash || canonical_json(seq, ts, kind, intent_id, actor, payload))`.

| GET | `/api/ledger` | `?after=<seq>&limit=` | `{"events":[Event]}` |
| GET | `/api/ledger/verify` | | `{"ok": bool, "checked": n, "head": hash, "first_bad_seq": n\|null}` |
| GET | `/api/ledger/checkpoint` | | `{"seq", "head", "signature", "public_key"}` (ed25519) |

## Credits, stats, verify, webhooks
| GET | `/api/credits` | (signed in) `{"balance", "entries":[{kind,credits,intent_id,memo,created_at}]}` |
| GET | `/api/stats` | `{"open","in_review","merged","credits_spent","credits_staked","train"}` |
| GET | `/api/verify/:sha` | `{"found", "intent_id", "provenance"}` |
| POST | `/api/webhooks/github` | GitHub App webhook, HMAC-SHA256 verified (`X-Hub-Signature-256`) |
