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
percent of an intent's votes.

Priority = 0.45 x votes + 0.25 x log(1 + credits pledged) + 0.15 x stake tier + 0.15 x roadmap fit. One weekly slot
is reserved for community priority and ignores pledged credits entirely.

## Reputation tiers

Reputation comes only from merged intents that stay merged, weighted by reuse and reviews. Reverts take points
back. Points decay 3 percent a month. You need at least 30 days in a tier before promotion.

| Tier | Threshold | Free credits a month | Privileges |
| --- | --- | --- | --- |
| Visitor | GitHub account at least 90 days old, or verified organization email | 500 | file intents, comment |
| Contributor | 1 merged intent retained 30 days | 2,000 | vote (weight 1) |
| Builder | 5 merged, 90 days active, 2 reviews accepted | 10,000 + priority queue | vote weight 3, triage |
| Steward | 20 merged across 2+ areas, 50 of the last 100 days active, no recent reverts | 50,000 + larger models | vote weight 5, nominate governors |
| Governor | elected (GOVERNANCE.md) | within the project quota | decide merges |

## Credits

1 credit = $0.01 of the model provider's list price, metered at actual cost. Every intent shows a receipt in
credits. Unused free credits expire at month end.

Organizations that need a feature can buy credits for their account: $0.015 per credit, in blocks from $150.
**Credits buy inference, never trust.** They do not add vote weight, reputation, review approval or a governor
seat, and the work they fund is public. Purchases and spend appear in the public ledger.

## Conduct

Everyone follows CODE_OF_CONDUCT.md.
