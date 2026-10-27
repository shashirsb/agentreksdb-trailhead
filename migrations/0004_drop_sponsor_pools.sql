-- 0004 — remove sponsor pools entirely.
--
-- 0003 introduced pools so an organisation could fund the inference for a feature it needed.
-- The rule was that money decides who PAYS, never where an intent sits in the queue. That rule
-- held in the code — `priority::Inputs` has no monetary field and a test forbids one — but the
-- feature was dropped anyway, because the safest way to keep money out of the queue is for the
-- project to take no earmarked money at all. There is now nothing to audit, recuse from, or
-- explain: every intent is paid for by its author's own credits, or by the community pool.
--
-- Pools shipped without a sponsor ever pledging, so there is nothing to unwind. The guard below
-- proves that before anything is dropped. If it ever fires, stop: a real sponsor's credits are
-- in the ledger, and `credit_entries` is append-only precisely so that money cannot be erased
-- to make a schema change convenient. Refund them through the API first.

DO $$
DECLARE n bigint;
BEGIN
    SELECT count(*) INTO n FROM credit_entries
     WHERE kind IN ('pool_pledge', 'pool_draw', 'pool_refund', 'pool_sweep');
    IF n > 0 THEN
        RAISE EXCEPTION
            'refusing to drop sponsor pools: % pool credit entries exist. Refund every open '
            'pool through the API, then remove this guard deliberately.', n;
    END IF;
END $$;

DROP VIEW IF EXISTS pool_balances;

-- The column goes before the table it references. Nothing may name a pool any more.
ALTER TABLE credit_entries DROP CONSTRAINT IF EXISTS credit_pool_kinds;
DROP INDEX IF EXISTS credit_entries_pool;
ALTER TABLE credit_entries DROP COLUMN IF EXISTS pool_id;

-- `community_spend` stays: the community pool covering a shortfall is still a real ledger
-- movement, and booking it keeps that account's money-in-equals-money-out check working.
ALTER TABLE credit_entries DROP CONSTRAINT IF EXISTS credit_entries_kind_check;
ALTER TABLE credit_entries ADD CONSTRAINT credit_entries_kind_check CHECK (kind IN (
    'grant', 'purchase', 'spend', 'stake_hold', 'stake_refund', 'stake_burn',
    'community_spend'
));

DROP TABLE IF EXISTS pool_recusals;
DROP TABLE IF EXISTS pool_sponsors;
DROP TABLE IF EXISTS sponsor_pools;
