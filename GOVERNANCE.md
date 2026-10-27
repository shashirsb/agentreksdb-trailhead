# Governance

AgentreksDB is written only by AI. Humans govern it: they write intents, review what the pinned model produced,
and decide what merges. This document says who decides, how, and on what schedule. It operates under CHARTER.md.

## 1. Roles

| Role | Who | Can |
| --- | --- | --- |
| Visitor | anyone with an eligible GitHub account | file intents, comment |
| Contributor and above | see the tier table in CONTRIBUTING.md | vote, triage, review, nominate |
| Governor | an elected member of the governing body | decide merges, holds and rejections; amend policy |
| Election officer | a non-candidate appointed for each election | run the ballot |
| Community Review Board | three people elected annually from non-governors | decide final appeals |

## 2. The governing body

- Five seats.
- Terms are one year, staggered so two or three seats are elected each year.
- A governor may serve at most two consecutive terms, then must sit out one term.
- At most two seats may be held by people employed by, or paid by, the same organization.

## 3. Elections

- Candidates need at least 10 merged intents in the trailing 12 months.
- Voters need at least 1 merged intent in the trailing 12 months.
- Ballots are ranked (Condorcet method, Schulze completion).
- Each election is run by an election officer who is not a candidate.
- Results, ballots (anonymized) and tallies are published in the ledger.

## 4. Decisions

- Default is lazy consensus: a reviewed change is approved unless a governor objects within 72 hours.
- On objection, the decision is a simple majority of governors voting.
- Irreversible changes (storage format, consistency or replication protocol, wire format, license, charter,
  this document, the pinned model) need two thirds of all seats and a public comment period of at least 7 days.
  Charter amendments follow CHARTER.md section 8 instead.
- Every hold and every rejection carries a written reason. A rejection also states what would make the intent
  acceptable ("reconsider if ...").

## 5. The weekly train

All times are America/Los_Angeles wall-clock time, which follows US daylight saving time.

1. **Sunday 00:00 — cutoff.** Every intent with an open, generated pull request joins the train named for that
   ISO week (for example `train/2026-W44`). Anything that reaches that state later joins the next train.
2. **Sunday to Thursday — review.** Gates run, the AI reviewer reports, governors review.
3. **Friday 00:00 — decision.** Each pull request on the train ends in exactly one state: `merged`, `on_hold` or
   `rejected`, with a recorded reason.
4. **Silence is a hold.** A pull request without a decision at Friday 00:00 is placed `on_hold`. Nothing is ever
   merged by default.
5. **On hold** means the pull request stays open, leaves the current train, and rejoins a later train after it is
   updated. A pull request that stays on hold for 3 consecutive trains without activity is closed, and its stake
   is refunded.
6. Exceptions to the cutoff are not granted. Security fixes follow SECURITY.md instead.

## 6. Recusal and conflicts of interest

A governor does not vote on, and does not review, an intent that:

- they authored or co-authored;
- their employer or a paying client asked them to pursue, or stands to gain commercially from;
- touches a feature they or their employer are paid to deliver.

Recusals are recorded in the ledger.

## 7. Removal

A governor is removed by a two-thirds vote of the remaining seats, or automatically after missing 4 consecutive
weekly trains without notice. A vacated seat is filled by special election for the rest of the term.

## 8. Appeals

1. The author of a held or rejected intent may open a public appeal within 14 days.
2. One governor who was not involved in the decision re-reviews it.
3. If the author still disagrees, the full governing body votes.
4. Final escalation is the Community Review Board. Its majority decision is binding and recorded.

## 9. Keys and model invocations

- The model API keys, the GitHub App private key and the ledger checkpoint key are held by the Trailhead
  backend's secret store, never by an individual.
- At least two governors can rotate each key. Rotation is recorded in the ledger (never the key itself).
- Every model invocation is logged in the ledger with the model ID, token counts and cost, and the prompt and
  response hashes. Payloads are published as described in docs/TRANSPARENCY.md.
- No governor may invoke the pinned model on the project's keys outside the Trailhead pipeline.

## 10. Bootstrap

Until the first election, the founder, Shashi (GitHub `shashirsb`), acts as interim governor and holds all the
powers of the governing body, subject to CHARTER.md. The interim governor may not amend the charter. The first
election is held within 6 months of the first public train, or once 25 intents authored by people other than the
founder have merged, whichever comes first.
