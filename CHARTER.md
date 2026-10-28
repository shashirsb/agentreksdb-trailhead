# AgentreksDB Charter: open source, forever

This charter states the commitments that define AgentreksDB and Trailhead. Where it conflicts with any other
project document, this charter wins. Section 9 explains why parts of it can never be weakened. Sections 1 to 9
are in force; section 10 holds amended text that has been decided but not yet adopted, and says so.

## 1. Licensing

1.1 All AgentreksDB and Trailhead code is published under an OSI-approved open-source license. The current
license is Apache-2.0, with the public-domain dedication in NOTICE for fully AI-generated files.

1.2 The project may move to a different license only if that license is OSI-approved and at least as
permissive for users as the one it replaces. A move to a source-available, "business source", SSPL-style or
any other non-OSI license is prohibited.

1.3 Specifications, intents, prompts and documentation are published under CC-BY-4.0.

## 2. No proprietary edition, ever

2.1 There will never be an enterprise, commercial, premium, cloud-only or otherwise proprietary edition of
AgentreksDB or Trailhead.

2.2 Every feature, deploy kit, operator, dashboard and tool the project produces is open source under section 1.
No feature is withheld, delayed or gated behind payment, license keys or a hosted service.

2.3 Paid inference credits (see CONTRIBUTING.md) buy model inference for public work only. They never buy a
private feature, a private branch, vote weight, review approval or a governor seat. Every feature funded by
credits is merged into the public codebase or not at all.

2.4 A strengthened replacement for 2.3 is recorded in section 10. It is not yet part of this charter; section
10 states its status and why. Earmarked sponsorship of a named feature was considered and rejected: see 10.4.

## 3. No CLA

3.1 Contributors never sign a Contributor License Agreement or assign copyright. Contributions of specs, intents
and documentation are made under the Developer Certificate of Origin (`Signed-off-by`).

3.2 No person or organization, including the founder and the governing body, holds the rights needed to
relicense the project outside section 1.

## 4. The AI-only invariant

4.1 Code enters the main branch of an AgentreksDB repository in exactly one way: as a commit generated
server-side by the pinned model through the Trailhead pipeline and attested by the Trailhead backend.

4.2 There is no path for uploading a raw diff, patch or human-written code. Pull requests containing
human-written code are closed automatically.

4.3 The pinned model is named in `agent.toml`. Changing it is a public decision of the governing body, made
through a public rotation pull request with published validation results.

4.4 Humans write intents, specifications, reviews and decisions. Humans decide what merges. Humans never write
the code.

## 5. Everything is public

5.1 Every intent, chat transcript, prompt sent to a model, model response, gate result, governor decision and
reason, and every unit of money and credit received or spent, is recorded in the public ledger and readable by
anyone without an account.

5.2 Ledger entries are never deleted or edited. The only exception is a payload that the law compels the project
to remove; the handling of those cases is fixed in docs/TRANSPARENCY.md, and the entry's hash, date and legal
basis always remain public.

5.3 Governing-body discussion that leads to a decision happens in public channels. A decision that was not
recorded publicly did not happen.

## 6. Trademark

6.1 The names "AgentreksDB", "Agentreks", "Trailhead" and the mountain logo will be owned by a neutral nonprofit
organization whose own charter includes sections 1 to 5 of this charter.

6.2 Until that nonprofit exists, the founder holds the trademarks in trust for the project and commits to
transfer them, together with the project domains and signing keys, to the nonprofit within 90 days of its
formation, for no payment.

6.3 Trademarks are licensed for use under TRADEMARK.md and may never be used to make a proprietary edition appear
official.

## 7. Funding

7.1 The project is funded by unrestricted donations and paid inference credits, with every transaction public.
No donation may be earmarked for a named feature, module or release.

7.2 The project may sell support or services to users only if doing so needs no proprietary code and gives the
payer no control over the roadmap or merges.

7.3 An addition to this section is recorded in section 10 and is not yet part of this charter.

## 8. Amendment

8.1 This charter may be amended only by a vote of at least 4 of the 5 seats of the governing body, after a public
comment period of at least 30 days on the exact amended text.

8.2 During the interim period described in GOVERNANCE.md, the charter may not be amended at all, except to fix
typographical errors.

## 9. Commitments that cannot be weakened

9.1 Sections 1, 2, 3, 5 and this section 9 can only be amended to make them stronger for users and
contributors. Any amendment that would permit a non-OSI license, a proprietary edition, a CLA, private ledger
entries, or that would weaken this section, is void regardless of the vote that adopted it.

9.2 Anyone may rely on this section. A fork that preserves this charter is a legitimate continuation of the
project in spirit, and the project will not use its trademarks against a fork that follows TRADEMARK.md.

## 10. Pending amendment: money buys inference and nothing else

10.1 Status: **proposed, not adopted.** The decision that money never affects ranking has been taken and the
ranking code and CONTRIBUTING.md are being changed accordingly. Putting it into this charter is an amendment,
and section 8 governs amendments: 8.1 requires at least 4 of the 5 seats of the governing body and a public
comment period of at least 30 days on the exact text, and 8.2 bars any charter amendment during the interim
period in GOVERNANCE.md section 10, which has not ended — the interim governor may not amend the charter.
Until an elected governing body votes, sections 2.3 and 7 above remain the operative charter text and 10.3 to
10.5 below have no charter force. The stricter rule is in force now as project policy and in the ranking code:
policy may be stricter than this charter, never weaker.

10.2 When the vote is held, the text voted on is 10.3 to 10.5 exactly as written here, and the result, the
comment period and the tally are recorded in the public ledger.

10.3 Proposed replacement of 2.3. Paid inference credits buy model inference for public work, and nothing
else. No payment, donation, sponsorship, pledge, purchase, or in-kind contribution of money or compute ever
buys, in whole or in part:

- (a) queue position, priority, or any term of the ranking score;
- (b) votes, vote weight, or any influence on a tally;
- (c) a review, an approval, a reviewer assignment, or any review influence;
- (d) merge rights, or any say in what merges;
- (e) a say in the roadmap, a governor seat, or any other governance power;
- (f) naming rights over the project, a release, a feature, a module, or an identifier in the code.

No ranking term in Trailhead is a function of money, and there is no paid tier, expedited lane, sponsored slot
or paid placement. Every feature funded by credits is merged into the public codebase or not at all.

10.4 Proposed new clause 2.5: no earmarked funding. Nobody may pay for a named feature, module or release.
Donations are unrestricted, and the project spends them where the public queue already points.

An organisation may buy credits so its own members can pay for the inference their intents consume.
That is a purchase of compute on behalf of a person, not funding of a feature: the credits name a
member, there is no mechanism to point them at an intent, and a funded intent is ranked exactly as
an unfunded one. Where an employer's staff vote together, their combined vote on a single intent is
weighted to reflect that colleagues are not independent voters.

An earlier draft of this charter proposed "sponsor pools": an organization could fund the inference for a
feature it wanted, under rules that gave it no priority, no vote, no review influence and no merge rights.
That design was built and then removed before any sponsor pledged. The rules were sound on paper and held in
the code, but they needed auditing, recusal, refunds and disclosure to stay true, and every one of those is a
place where the promise could quietly fail. A project whose whole claim is that it cannot be bought is better
served by having nothing to audit: the surest way to keep money out of the queue is to refuse earmarked money
at the door. Unrestricted donations pay for whatever the queue puts first, which is what the votes decided.

10.5 Proposed new clause 7.4. Donations and paid inference credits give the payer no control over the roadmap,
the queue order, reviews or merges, and no naming rights.

10.6 Proposed addition to 9.1: clauses 10.3 (a) to (f) and 10.4, once adopted, may only be amended to make them
stronger for users and contributors.
