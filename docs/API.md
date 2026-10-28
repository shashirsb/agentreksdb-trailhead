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

`User = {id, login, tier, rep_points, is_governor, credits_balance, created_at, rights, invite_quota}`
Tiers: `visitor`, `contributor`, `builder`, `steward`, `governor`.

- `rights = {request_features, develop, create_org}` (booleans) is what this account may do right now. It is
  computed on every request from the `user_rights` view, not stored, so it reflects a revocation immediately.
  Signing in and reading are open, and voting needs a tier rather than an invitation; `request_features` gates `POST /api/intents` and
  `develop` gates `POST /api/intents/:id/submit` (see Invitations).
- `invite_quota` is the number of live invitations this tier may hold at once (see Invitations). `null` means
  unlimited, which only `governor` has; `0` means this tier may invite nobody.

## Invitations
Signing up is open. Opening an intent (requesting a feature) and submitting one (working on a release) need an
invitation, and so does creating an organisation. An invitation names a GitHub login; it is redeemed
automatically when that account signs in, including an account that already existed. There is no code to enter.

An invitation is deliberately not a secret. Only the named account can redeem it, so a leaked one is worthless,
and the list below is public. This is the opposite of an organisation key, which is handed to a whole team and so
is a bearer token: hashed, capped and revocable. Do not turn invitations into codes; that would add a leakage
risk the login binding removes.

`Invite = {id, login, kind, note, issued_by, revoked_by, state}`. `kind`: `requester` (may request features),
`developer` (the same, plus work landing in a release), `org_admin` (the same, plus creating one organisation).
`state`: `open` · `accepted` · `revoked` (`revoked` wins once an invitation has been revoked, even if it had
been accepted). `login` is stored lowercase without a leading `@`; `revoked_by` is null unless revoked.

Today any invitation, of any kind, satisfies both `request_features` and `develop`; `kind` is recorded as
provenance and only `org_admin` changes what the holder can do (`create_org`). Organisation staff who redeem
their employer's key also get both rights.

| Method | Path | Body / query | Returns |
| --- | --- | --- | --- |
| GET | `/api/invites` | | `{"invites":[Invite]}` newest first, at most 500. Public on purpose: who was admitted, by whom and why should not be an insider's list |
| POST | `/api/invites` | `{login, kind, note?}` (signed in) | `{"id", "login", "kind"}` |
| DELETE | `/api/invites/:id` | `{"reason"?}`, or no body at all | `{"ok": true}` |

Who may issue what:

| Tier | `requester` | `developer`, `org_admin` | Live invitations held at once (`invite_quota`) |
| --- | --- | --- | --- |
| governor | yes | yes | unlimited (`null`) |
| steward | yes | no | 10 |
| builder | yes | no | 3 |
| contributor, visitor | no | no | 0 |

The quota counts invitations you issued that are neither accepted nor revoked, not invitations issued over
all time, so a slot frees up when the invitee signs in or when you revoke. There is at most one live invitation
per login.

`POST /api/invites` errors:

| Status | Code | When |
| --- | --- | --- |
| 400 | `bad_kind` | `kind` is not `requester`, `developer` or `org_admin` |
| 400 | `bad_login` | not a possible GitHub login: letters, digits and single hyphens, no leading or trailing hyphen, up to 39 characters. A leading `@` and case are normalised away |
| 400 | `bad_note` | `note` longer than 280 characters. The note is public |
| 403 | `not_permitted` | this tier may not issue that kind (checked before quota, so a visitor never sees a spare slot) |
| 403 | `quota_exhausted` | already holding `invite_quota` live invitations |
| 409 | `already_invited` | the login already has a live invitation; revoke it first to change its kind. An accepted or revoked one does not block a new invitation |

`DELETE /api/invites/:id`: the issuer may revoke their own invitation and a governor may revoke anyone's. It
works after acceptance as well as before, and takes effect on the next request because `rights` is computed
from the invitation rather than cached. An id that does not exist, is already revoked, or belongs to someone
else (for a non-governor) all return the same `404 not_found`, so ids cannot be probed.

Issuing and revoking are written to the ledger as `invite.issued` and `invite.revoked`; redemption at sign-in is
`invite.accepted`.

Gates elsewhere return `403 invitation_required` (message and hint say which activity): `POST /api/intents`,
`POST /api/intents/:id/submit` and `POST /api/orgs`. Creating an organisation needs `rights.create_org`, which
only an `org_admin` invitation (or a governor) grants.

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
| POST | `/api/intents` | `{title, area, intent, stake_credits}` | `{"intent": Intent}` (status `draft`, stake held); `403 invitation_required` unless `rights.request_features` |
| GET | `/api/intents/:id` | | `{"intent", "messages":[{role,body,created_at}], "gates":[{gate,verdict,detail,created_at}], "events":[Event], "decision": Decision\|null}` |
| POST | `/api/intents/:id/messages` | `{body}` (author only, status `draft`) | `{"reply": {role:"ai",body}, "spec", "readiness"}` |
| POST | `/api/intents/:id/submit` | (author only; readiness.ready must be true) | `{"intent"}` → status `submitted`; `403 invitation_required` unless `rights.develop` (checked again here because an invitation can be revoked while a draft is open) |
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
