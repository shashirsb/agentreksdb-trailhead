# Contributing

AgentreksDB is written only by AI. You contribute **intent**: what the database should do and how we will know it
works. A pinned model writes the code on the project's infrastructure, gates prove it, and humans decide whether
it merges. See CHARTER.md section 4.

## Pull requests with human-written code are closed automatically

There is no path for human-written code, patches or diffs into main. If you open a pull request containing code,
a bot closes it with a link to this page. This is not a judgement of your code; it is the invariant that makes
the project trustworthy.

What you can open directly on GitHub: issues, discussions, and pull requests that only change specs or
documentation, signed off under the DCO (below).

## How to file an intent

1. Sign in to Trailhead with GitHub.
2. Choose **Request a feature**: give a title, the area (engine, search and vector, graph, memory, events,
   console, deploy) and a short description.
3. Talk it through in the intent chat. The interviewer asks until the spec is complete: the problem, what is in
   and out of scope, requirements written as "WHEN ... THE SYSTEM SHALL ...", acceptance tests in Given/When/Then
   (at least one negative case), constraints, risk and rollback plan.
4. Submit when the spec shows **ready**. Your stake is held.
5. Guardrails route the intent green, amber or red. Green and amber are generated; red is held for a human.
6. The pinned model generates the change in a sandbox and the backend opens an attested pull request.
7. Tests, performance and diff-policy gates run. The AI reviewer reports.
8. The weekly train decides: cutoff Sunday 00:00 America/Los_Angeles, decision by Friday 00:00. See GOVERNANCE.md.

Everything in these steps, including your chat, is public and permanent. Do not put personal data or secrets in
an intent.

## Developer Certificate of Origin

Specs, intents and docs are contributed under the DCO (https://developercertificate.org/) and licensed
CC-BY-4.0. Trailhead records your sign-off when you submit. Spec or doc pull requests on GitHub need a
`Signed-off-by: Your Name <email>` line in each commit (`git commit -s`). There is no CLA.

## Stakes

A stake is held when you submit an intent. It pays nothing to anyone; it prices out spam.

| Intent | Stake |
| --- | --- |
| Bug or small change | 500 credits ($5) |
| Feature | 2,500 credits ($25) |
| Protocol or consistency change | 10,000 credits ($100) |

- Your first intent needs no stake.
- **Refunded in full** when the intent merges, when a governor declines it in good faith, or when it is closed
  after 3 trains on hold.
- **Burned** for spam, a duplicate filed after a warning, a prompt-injection attempt, or 14 days without answering
  a clarification question. Burned stakes fund the community inference pool.

## Votes

Each account with Contributor tier or above gets 100 vote points per calendar quarter. Putting n votes on one
intent costs n squared points (1 vote = 1, 3 votes = 9, 10 votes = 100). No single account may hold more than 20
percent of an intent's votes, no account may put more than 10 points on one intent, and an account must be at
least 30 days old to vote at all. **Your own vote on your own intent counts zero** toward its score.

## How the queue is ordered

**Money is not an input.** No term below is a function of credits bought, donated, pledged or spent. There is no
paid lane, sponsored slot, expedited option or priority queue that money can reach. See CHARTER.md section 2.

    S = D x [ 55V + 9R + 4O + 17Fit + 9K + 6E ] x P

| Term | Max | What it measures |
| --- | --- | --- |
| **V** votes | 55 | Community quadratic votes. Conviction-weighted: a vote reaches full weight over a 14-day ramp, so early support counts more than a late push. A cluster/collusion discount shrinks votes that arrive together from accounts that behave as one. Normalised as `raw / (raw + median)`, so a single huge intent cannot rescale the whole board. The requester's own vote counts zero. |
| **R** record | 9 | The requester's previously merged intents that are still in main after 30 days. Log-scaled, so the tenth merge adds far less than the first. Decays 3 percent a month, and is halved if any of their work was reverted in the last 90 days. |
| **O** open source | 4 | Qualifying open-source repositories the requester has shared: not a fork, an OSI licence, at least 90 days old, still active, with real adoption. Log-scaled. |
| **Fit** roadmap fit | 17 | A governor's judgement that the intent fits the published roadmap or unblocks a dependency. Requires a written rationale and two signers; a bare score with no rationale is not accepted. |
| **K** stake tier | 9 | Which stake tier the change sits in (bug, feature, protocol). It reflects the size of the commitment, not the size of a payment: stakes are refundable and identical for everyone. |
| **E** effort bonus | 6 | A small-job bonus, `1 / (1 + size / median size)`, so small well-specified changes are not permanently crowded out by large ones. |
| **D** staleness | x0.2 to 1 | Multiplier that decays once 60 days pass without a new distinct supporter, halving roughly every 90 days down to a floor of 0.2. At 180 days idle the intent is archived. |
| **P** penalty | x0.1 to 1 | Multiplier for duplicates, spam or a governor hold. Every penalty carries a public reason; an unexplained penalty is a bug, so report it. |

### Reading your score breakdown

An intent's score is published as a breakdown rather than a single number (see the status note at the end of
this section). The breakdown gives each term's raw input, the normalised value, the weight, the points it
contributed, and the two multipliers, with the train it was computed for. Read it as a sum, not a ranking:
`S` is the bracket total multiplied by `D` and `P`, and the largest single lever is always V. If a term looks
wrong, the raw input next to it tells you whether the input or the maths is at fault. Fit always shows its
rationale text and its two signers. P always shows its reason.

### Two invariants you can check

1. **Community votes outrank everything else combined.** With `D = P = 1`, an intent with full community
   support and nothing else scores 55. An intent with zero votes and *every* other term maxed out scores
   `9 + 4 + 17 + 9 + 6 = 45`. Seniority alone (`R + O`) caps at 13. So neither seniority, nor fit, nor stake
   tier, nor size, nor all of them together, can outrank community votes.
2. **No amount of money changes any term.** V, R, O, Fit, K, E, D and P take votes, merge history, public
   repositories, a governor's written rationale, change type, diff size, elapsed time and penalties as
   inputs. Credits appear in none of them.

### Anti-gaming rules

- **Account age.** An account must be at least 30 days old to vote and at least 90 days old (or hold a
  verified organisation email) to participate at all.
- **Cluster discount.** Votes from accounts that register, vote and lapse together are treated as fewer
  votes. The discount is applied to the cluster, not to any one member, and the clustering signal is
  published with the breakdown.
- **Hidden tallies.** Vote counts for an open train are not shown until that train's cutoff, so nobody can
  aim just over a rival.
- **Snapshot freeze.** Scores are snapshotted 48 hours before the cutoff. Votes cast inside the freeze window
  count toward the next train, not this one.
- **Own vote excluded.** The requester's vote on their own intent counts zero.
- **No commit or repo farming.** R counts only merged intents still in main after 30 days, so churn and
  self-reverts earn nothing, and a revert within 90 days halves R. O counts only repositories that are not
  forks, carry an OSI licence, are 90+ days old, remain active and show real adoption, so repositories
  created to pad a profile do not qualify.

Implementation status: the formula, its weights and the per-term breakdown live in `crates/trailhead-core`
(`priority.rs`), where they are unit-tested, including a test that no monetary field can enter the inputs. The
vote-mass computation behind V (the conviction ramp and the cluster discount), the endpoint that publishes a
breakdown, the hidden tallies and the 48-hour freeze are not wired into the portal yet. The ledger records which
rules each train was decided under.

## Reputation tiers

Reputation comes only from merged intents that stay merged, weighted by reuse and reviews. Reverts take points
back. Points decay 3 percent a month. You need at least 30 days in a tier before promotion.

| Tier | Threshold | Free credits a month | Privileges |
| --- | --- | --- | --- |
| Visitor | GitHub account at least 90 days old, or verified organization email | 500 | file intents, comment |
| Contributor | 1 merged intent retained 30 days | 2,000 | vote (weight 1) |
| Builder | 5 merged, 90 days active, 2 reviews accepted | 10,000 | vote weight 3, triage |
| Steward | 20 merged across 2+ areas, 50 of the last 100 days active, no recent reverts | 50,000 + larger models | vote weight 5, nominate governors |
| Governor | elected (GOVERNANCE.md) | within the project quota | decide merges |

## Credits

1 credit = $0.01 of the model provider's list price, metered at actual cost. Every intent shows a receipt in
credits. Unused free credits expire at month end.

Organizations that need a feature can buy credits for their account: $0.015 per credit, in blocks from $150.
**Credits buy inference, never trust and never position.** They add no vote weight, no reputation, no review
approval, no merge rights, no roadmap say and no naming rights, and they are an input to no term of the queue
score. The work they fund is public. Purchases and spend appear in the public ledger.

### Organisations buying inference for their own people

An organisation can buy credits so its employees can file intents without paying personally. Its
members draw on that balance exactly as they would their own; the employer picks up the compute
bill. Create one, add members, buy credits: `POST /api/orgs`, `/api/orgs/:id/members`,
`/api/orgs/:id/credits`.

**It buys compute for a person. It buys nothing for a feature.** An intent written by a funded
employee sits in the queue at exactly the score it would have had if they had paid themselves —
there is no monetary term for the money to reach, and an end-to-end test asserts a funded and an
unfunded intent score identically.

The guarantee is structural rather than a promise. Organisation credits name a **member**, never
an intent: there is no column linking an organisation to an intent and no endpoint that funds a
named feature. That is the difference from the sponsor pools below, and the reason this is safe
where those were not.

One thing organisations genuinely do change is votes. A company with fifty staff is fifty
accounts that may all back the same intent, and that is not fraud but it is not fifty independent
opinions either. So an employer's combined vote on one intent counts in full for the first few
points and at a square-root rate after that: twelve colleagues weigh about six, while twelve
unrelated people weigh twelve. Recording who works where is what makes that possible — a link the
project can see is a cluster it can discount, where fifty unaffiliated-looking accounts are not.

Every purchase and every credit spent is in the public ledger with the organisation named.

### No earmarked funding

Nobody can pay for a named feature. Donations are unrestricted, and the project spends them wherever the
public queue already points.

An earlier version of Trailhead let an organization open a **sponsor pool** that paid the inference for a
feature it wanted. Its rules gave the sponsor nothing: no priority, no vote, no review influence, no merge
rights. The code enforced that, because the queue score has no monetary term for money to reach. It was still
removed before anyone pledged. Keeping that promise true needed disclosure, recusal, refunds and an audit of
every pool, and each of those is a place where it could quietly stop being true. A project whose central claim
is that it cannot be bought is safer with nothing to audit.

So if your organization wants a feature, the route is the same as everyone else's: file the intent, or back
one that already exists. If you want to help pay for the work in general, an unrestricted donation funds
whatever the votes put first.

## Conduct

Everyone follows CODE_OF_CONDUCT.md.
