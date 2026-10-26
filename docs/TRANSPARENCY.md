# Transparency: permanent, honestly

Everything Trailhead does is recorded in a public ledger: intents, chat messages, prompts sent to models, model
responses, guardrail verdicts, gate results, reviews, governor decisions and reasons, credits granted, bought,
staked, refunded, burned and spent, and key rotations.

## What "permanent" means

- **The hash chain is permanent.** Each ledger event carries the hash of the event before it. Changing or deleting
  any event breaks every hash after it, and anyone can check the chain at `/api/ledger/verify`.
- **Checkpoints are signed and witnessed.** The head of the chain is signed regularly, published, and mirrored
  outside the project so that history cannot be rewritten quietly.
- **Payloads are permanent, except where the law compels otherwise.** The words, prompts and responses behind each
  hash stay public forever, with one exception: when a court order, a valid legal request under data-protection
  law (for example GDPR Article 17), or a valid copyright notice requires us to remove a payload.

## How a legally compelled removal works

We never rewrite the ledger. Instead:

1. The payload is replaced with a tombstone, or its encryption key is destroyed.
2. A new ledger event records: the sequence number of the affected event, its original hash, the date, the legal
   basis, and who required the removal (as far as the law allows us to say).
3. The original hash stays in the chain, so the chain still verifies and everyone can see that something was
   removed, when and why.

We publish a count of removals and their legal bases in a regular transparency report.

## Secrets are redacted before anything is recorded

Before an event is hashed, it is scanned for credentials. A secret is replaced with
`[REDACTED:sha256(salt || secret)]`, so the record shows that a redaction happened without exposing the value.
Redaction happens only at ingest, never afterwards.

## What you agree to when you contribute

By filing an intent, chatting with the interviewer or commenting, you agree that what you write is published
publicly and irrevocably under CC-BY-4.0. Do not include personal data about anyone, or anything you would not
want public forever.

## The one exception

Code of conduct reports are not published (CODE_OF_CONDUCT.md). Only enforcement outcomes are.
