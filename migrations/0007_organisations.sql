-- 0007 — organisation accounts: an employer buys inference for its own people.
--
-- An organisation buys credits so its employees can run intents without paying personally. The
-- money buys compute for a person. It does not buy anything for a feature.
--
-- That distinction is why this exists and sponsor pools (0004) do not. A pool named a FEATURE and
-- funded it. However carefully its rules were written, the money was attached to a queue item, so
-- keeping "this buys no priority" true needed disclosure, recusal, refunds and an audit of every
-- pool — four places it could quietly stop being true. An organisation balance is attached to its
-- MEMBERS. There is no column here that can reference an intent, and no API that points
-- organisation money at an intent somebody else wrote, so there is nothing to disclose or recuse
-- from. The absence of that column is the guarantee; everything else is policy.
--
-- The real risk organisations add is votes, not money: fifty employees are fifty accounts that may
-- all back the same intent. `credits::org_vote_weight` discounts a single employer's combined vote
-- on one intent, and recording membership is what makes that possible — a link the project can see
-- is a cluster it can discount, where fifty unaffiliated-looking accounts are not.

CREATE TABLE orgs (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    -- Verified by the members' email domain. Used to spot one employer voting as many people,
    -- and shown publicly beside their spend.
    verified_domain TEXT,
    created_by      BIGINT NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX orgs_name_lower ON orgs (lower(name));

CREATE TABLE org_members (
    org_id    BIGINT NOT NULL REFERENCES orgs(id),
    user_id   BIGINT NOT NULL REFERENCES users(id),
    -- 'admin' may buy credits and manage members; 'member' may only spend.
    role      TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    added_by  BIGINT NOT NULL REFERENCES users(id),
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
-- One employer per person. Without this, somebody could join several organisations and drain a
-- balance from each, and the vote discount would have no single cluster to apply.
CREATE UNIQUE INDEX org_members_one_org ON org_members (user_id);

-- Organisation money lives in the same append-only ledger as everything else, so it is audited by
-- the machinery that already exists rather than by a second set of rules.
ALTER TABLE credit_entries ADD COLUMN org_id BIGINT REFERENCES orgs(id);
ALTER TABLE credit_entries DROP CONSTRAINT IF EXISTS credit_entries_kind_check;
ALTER TABLE credit_entries ADD CONSTRAINT credit_entries_kind_check CHECK (kind IN (
    'grant', 'purchase', 'spend', 'stake_hold', 'stake_refund', 'stake_burn',
    'community_spend',
    'org_purchase',  -- credits an organisation bought for its members
    'org_spend'      -- a member spent them on their own intent's inference
));
-- Every organisation movement names its organisation, and no other kind may.
ALTER TABLE credit_entries ADD CONSTRAINT credit_org_kinds CHECK (
    (kind IN ('org_purchase', 'org_spend')) = (org_id IS NOT NULL)
);
CREATE INDEX credit_entries_org ON credit_entries (org_id, id) WHERE org_id IS NOT NULL;

-- Published so anyone can recompute it: money in, money out, what is left.
CREATE VIEW org_balances AS
SELECT o.id AS org_id,
       o.name,
       o.verified_domain,
       COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'org_purchase'), 0)::bigint AS purchased,
       COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'org_spend'), 0)::bigint     AS spent,
       (COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'org_purchase'), 0)
        - COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'org_spend'), 0))::bigint AS balance
FROM orgs o
LEFT JOIN credit_entries c ON c.org_id = o.id
GROUP BY o.id, o.name, o.verified_domain;

COMMENT ON TABLE orgs IS
    'An employer that buys inference for its own members. Deliberately has no intent_id anywhere: '
    'organisation money pays for a person''s compute, never for a named feature.';
