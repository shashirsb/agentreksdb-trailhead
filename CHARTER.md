# AgentreksDB Charter: open source, forever

This charter states the commitments that define AgentreksDB and Trailhead. Where it conflicts with any other
project document, this charter wins. Section 9 explains why parts of it can never be weakened.

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

7.1 The project is funded by donations, sponsorship and paid inference credits, with every transaction public.

7.2 The project may sell support or services to users only if doing so needs no proprietary code and gives the
payer no control over the roadmap or merges.

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
