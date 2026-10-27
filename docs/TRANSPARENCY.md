# Transparency: permanent, honestly

Everything Trailhead does is recorded in a public ledger: intents, chat messages, prompts sent to models, model
responses, guardrail verdicts, gate results, reviews, governor decisions and reasons, credits granted, bought,
staked, refunded, burned and spent, and key rotations. There is one exception, conduct reports, at the end of
this page.

## What "permanent" means

- **The hash chain is permanent.** Each ledger event's hash covers the previous event's hash *and the event's
  full payload*. Changing or deleting any event breaks every hash after it, and anyone can check the chain at
  `/api/ledger/verify`. The `events` table is also append-only in Postgres: a trigger raises on any UPDATE,
  DELETE or TRUNCATE, so the database refuses the edit before the chain would even notice.
- **Checkpoints are signed by the project, and only by the project.** The head of the chain is signed with an
  ed25519 key held in the Trailhead backend's secret store and served, with its public key, from
  `/api/ledger/checkpoint`; signed heads are stored in the project's own `checkpoints` table. There is today
  **no witness, no mirror and no external anchor**: nothing outside the project holds a copy of any head. A
  reader who does not trust the project can compare checkpoints they fetched themselves at different times, and
  can verify the whole chain, but cannot yet prove that the head they see today is consistent with the head
  someone else saw last month. Fixing that is the planned work below.
- **Payloads are permanent, except where the law compels otherwise.** The words, prompts and responses behind each
  hash stay public forever, with one exception: when a court order, a valid legal request under data-protection
  law (for example GDPR Article 17), or a valid copyright notice requires us to remove a payload.

## Removing a payload

An earlier version of this page said a removed payload becomes a tombstone and "the chain still verifies",
while the code hashed each payload inline, so a removal broke verification from that event onward. The page
promised something the arithmetic could not deliver. That is now fixed in the code rather than walked back on
the page.

Since migration 0006, every new event commits to `sha256(salt || payload)` instead of to the payload itself.
Removing a payload deletes the payload and its salt and keeps the commitment, so the chain still verifies for
everyone while the content is genuinely gone. `scripts/e2e.sh` removes a payload on every run and then checks
that both `/api/ledger/verify` and an independent `trailhead ledger verify-remote` still pass.

The salt is the part that makes a removal real. Most payloads are short and predictable — a verdict, a decision,
an amount — and an unsalted hash of a small value can be reversed by hashing the candidates until one matches.
Deleting a 32-byte random salt along with the payload removes that possibility.

What this does and does not give you:

- A removal is **deliberate and recorded**. `UPDATE` and `DELETE` on `events` are still refused by the
  append-only trigger. The only route is `remove_event_payload(seq, reason)`, which requires a public reason,
  and the removal is itself appended to the ledger. That something was removed, when, and on whose authority
  stays public; only the content goes.
- Anyone **holding a copy** of the original payload can still prove what it was, because the commitment is
  unchanged. A removal hides content from future readers; it does not rewrite the past for people who already
  read it.
- **Events written before 0006 cannot be removed.** Their hashes cover their payloads directly, so removing one
  would break every hash after it. `remove_event_payload` refuses them by name rather than corrupting the chain,
  and says why. If a removal of a pre-0006 payload is ever legally compelled, the fallback is the old plan: a
  deliberate schema-level intervention, announced in advance, with the last clean checkpoint and the exact break
  point published so anyone can verify up to that sequence number and see where and why verification stops.
- No removal has happened. If one ever does, it is announced, not discovered.

We publish a count of removals and their legal bases in a regular transparency report.

## The planned design (not yet implemented)

None of the following is built. It is recorded here so that the gap between what we promise and what runs is
visible, and so the design can be argued with before it is written.

- **An RFC 9162 Merkle tree served as static tiles.** A tiled, append-only log would let any reader check
  inclusion and consistency proofs offline, instead of trusting a single `verify` endpoint.
- **k-of-n witness cosignatures.** Independent witnesses outside the project would cosign each tree head, and a
  head would count as witnessed only with at least k signatures. This is what would actually make a quiet
  rewrite detectable.
- **External anchors.** Checkpoints mirrored into a public git repository, and anchored in Sigstore Rekor and
  OpenTimestamps, so the head is pinned in places the project does not control.

Note: generated commits already have a separate, working trust path — gitsign keyless signing with the Trailhead
workflow identity, logged in Rekor, checked by the attestation gate. That covers commits, not the ledger. Do not
read it as the ledger being anchored; it is not.

## Delayed publication

A few payloads cannot be published the moment they are written. Delay is handled so that the *existence* of the
record is never delayed:

1. The ledger entry is written **immediately**, in sequence, like any other event. It carries the payload's
   hash, the exception category, the reason, the planned release date and the approver.
2. Only the payload waits. Nothing is held back about the fact that a record exists, when it was made, or who
   decided to hold it.
3. On the planned release date the payload is published and a further event records the release.
4. A daily job lists every embargo that is past its planned release date, publicly, with its age. An overdue
   embargo is a visible failure, not a quiet one.

| Category | What is held | Released when |
| --- | --- | --- |
| Security embargo | The intent, prompts and responses behind an unfixed vulnerability | Per SECURITY.md: fix + 30 days, or 90 days from the report, whichever is later; never past 180 days |
| Secrets | The credential found inside a payload | Never. The rest of the payload is published at once; the credential itself is replaced by a redaction marker. The scan that would do this is not built yet (see below) |
| Personal-data erasure | A payload subject to a valid erasure request | Not released; handled as a removal above |
| Conduct reports | The report, and the fact that it was made | Not released. Unlike the others, a conduct report is not entered in the ledger at all: it goes to the conduct committee by email (CODE_OF_CONDUCT.md), and only the enforcement outcome is published, without identifying the reporter |
| Illegal content | The payload | Not released; the entry, hash and legal basis stay public |

For every category except conduct reports, these are exceptions to *publication*, not to *recording*: the
entry, its hash and its reason are public even when the payload is withheld permanently. Conduct reports are the
one category of project business that is kept out of the ledger entirely, so that a reporter is not identifiable
from the timing of an entry.

The delayed-publication mechanism and the overdue-embargo job are policy and design; neither is implemented yet.

## Secrets: the redaction pass is planned, not built

The intended rule: before an event is hashed, it is scanned for credentials, and a secret is replaced with
`[REDACTED:sha256(salt || secret)]`, so the record shows that a redaction happened without exposing the value.
Redaction happens only at ingest, never afterwards — which is the only point at which it can happen, given the
hash chain above.

**This scan does not exist yet.** There is no redaction code in the backend. What does exist is advisory: the
prompt guardrails (`policy/guardrails.toml`) flag an intent that asks for secrets or credentials to be exposed,
and route it amber or red before any tokens are spent. That stops a class of request; it does not clean a
payload. Until the ingest scan ships, the warning in "What you agree to" below is the only protection: do not
put a credential into an intent, a chat message or a comment, because what you write is hashed and published as
written.

## What you agree to when you contribute

By filing an intent, chatting with the interviewer or commenting, you agree that what you write is published
publicly and irrevocably under CC-BY-4.0. Do not include personal data about anyone, or anything you would not
want public forever.

## Conduct reports

Code of conduct reports are not published, and not recorded in the ledger (CODE_OF_CONDUCT.md). Only
enforcement outcomes are published, without identifying the reporter. This is the single exception to section
5.1 of the charter, and it exists to protect reporters.
