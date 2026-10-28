# Governance

AgentreksDB is written only by AI. Humans govern it: they write intents, review what the pinned model produced,
and decide what merges. This document says who decides, how, and on what schedule. It operates under CHARTER.md.

## 1. Roles

| Role | Who | Can |
| --- | --- | --- |
| Visitor | anyone with a GitHub account | read everything, follow a release, comment. Filing an intent or working on a release needs an invitation (section 11) |
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

## 11. Admission

Signing up is open: anyone may create an account, read every intent and follow a release. Voting needs no
invitation but does need Contributor tier (CONTRIBUTING.md). Two actions need
an invitation: requesting a feature (opening an intent) and working on a release (submitting one). Creating an
organisation needs an organisation invitation.

The gate is on those actions, not on the account. Gating signup would have shut out readers, which a project
built on public intent cannot do, and would have locked out the staff of a paying organisation, who
must sign in before they can redeem their employer's key.

**Who may invite whom**

| Tier | May invite | Live invitations at once |
| --- | --- | --- |
| Governor | requesters, developers, organisation admins | unlimited |
| Steward | requesters only | 10 |
| Builder | requesters only | 3 |
| Contributor, Visitor | nobody | 0 |

- A live invitation is one issued and neither accepted nor revoked. The quota counts live invitations, not
  invitations issued over all time, so it recycles as people join and bounds what one compromised account can
  do before anyone looks.
- A Contributor, with one merged intent, is deliberately given no invitations. If a single merge bought the
  power to admit others, the defences against fake accounts would be decoration. Tiers are earned and can be
  lost; the quota follows the tier.
- Organisations are admitted by the governor alone, with an `org_admin` invitation. An organisation is a funded
  group of voters, and the vote discount for colleagues (CONTRIBUTING.md) can only apply to a group the project
  can see, so who may create one is not spread across everyone who has merged a few changes. Developer
  invitations are governor-only for the related reason that those who vote on a release should not also quietly
  choose who produces it.
- Staff of an organisation get the right to request features and to submit by redeeming their employer's
  organisation key. The employer vouches for them, and the key is capped and revocable.
- At present any invitation, of whatever kind, permits both requesting and working on a release. The kind is
  recorded as provenance; only the organisation invitation grants anything extra.

**Invitations are bound to a login, not to a secret.** An invitation names one GitHub login and is redeemed when
that account signs in. A leaked invitation is worthless to whoever finds it, so it never needs to be kept
secret, and the list of invitations, with who issued each and why, is public. An organisation key is the opposite
by necessity: it goes to a whole team, so it is a bearer token and is hashed, capped and revocable. Changing
invitations into codes would add a leakage risk that the binding removes.

**Revocation is immediate and works after acceptance.** The issuer may revoke their own invitation and a
governor may revoke any. Rights are computed from the invitations on each request and never cached, so a
revoked invitation stops working on the next request, even if it was accepted long ago. This includes work in
progress: submitting re-checks the right. Issuing and revoking are recorded in the ledger.

The admission chain behind every contributor is therefore reconstructible from the public ledger. The interim
governor named in section 10 is the first source of invitations.
