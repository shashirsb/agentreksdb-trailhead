-- 0003 — sponsor pools, per-feature evidence, contributor signals.
--
-- Three things arrive together because they share one rule: everything here is public and
-- append-only, and none of it may touch queue position. Sponsor pools decide WHO PAYS for a
-- feature's inference; priority::Inputs has no monetary field, so no amount of money can move
-- a score. That is enforced in code by `priority::tests::money_cannot_move_the_score`.

-- ---------------------------------------------------------------------------
-- 1. Sponsor pools.
-- ---------------------------------------------------------------------------

-- An organisation funds a feature it needs. The pool is all-or-nothing: if the goal is not
-- met by the deadline nobody is charged, which is the Kickstarter rule and avoids half-funding
-- a feature that then stalls. Unclaimed money is ALWAYS refundable and never becomes the
-- operator's — that is the lesson of Bountysource, which changed its terms to keep unclaimed
-- bounties and then went bankrupt owing contributors.
CREATE TABLE sponsor_pools (
    id              BIGSERIAL PRIMARY KEY,
    title           TEXT NOT NULL,
    scope           TEXT NOT NULL,                       -- public description of the need
    intent_id       BIGINT REFERENCES intents(id),       -- NULL until a governor links one
    goal_credits    BIGINT NOT NULL CHECK (goal_credits > 0),
    per_intent_cap  BIGINT NOT NULL CHECK (per_intent_cap > 0),
    deadline        TIMESTAMPTZ NOT NULL,                -- all-or-nothing funding deadline
    expires_at      TIMESTAMPTZ NOT NULL,                -- unspent credits refunded by here
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','funded','active','completed','failed','rejected','expired')),
    created_by      BIGINT NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > deadline)
);
CREATE INDEX sponsor_pools_intent ON sponsor_pools(intent_id);
CREATE INDEX sponsor_pools_status ON sponsor_pools(status, deadline);

-- Who funded what, disclosed publicly. `interest_statement` is mandatory: a reader must be
-- able to see why an organisation wants a feature before judging the feature.
CREATE TABLE pool_sponsors (
    pool_id             BIGINT NOT NULL REFERENCES sponsor_pools(id),
    user_id             BIGINT NOT NULL REFERENCES users(id),
    org_name            TEXT NOT NULL,
    verified_org_domain TEXT,
    interest_statement  TEXT NOT NULL CHECK (length(btrim(interest_statement)) >= 10),
    kyc_level           TEXT NOT NULL DEFAULT 'basic' CHECK (kyc_level IN ('basic','verified','entity')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pool_id, user_id)
);

-- A governor who works for a sponsor must recuse themselves from that pool's intent. Recorded
-- here and mirrored into the ledger, so a reader can check it was honoured.
CREATE TABLE pool_recusals (
    pool_id     BIGINT NOT NULL REFERENCES sponsor_pools(id),
    user_id     BIGINT NOT NULL REFERENCES users(id),
    reason      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pool_id, user_id)
);

-- Pool movements join the existing credit ledger rather than living beside it, so one
-- append-only table still answers "where did every credit go".
ALTER TABLE credit_entries ADD COLUMN pool_id BIGINT REFERENCES sponsor_pools(id);
ALTER TABLE credit_entries DROP CONSTRAINT credit_entries_kind_check;
ALTER TABLE credit_entries ADD CONSTRAINT credit_entries_kind_check CHECK (kind IN (
    'grant','purchase','spend','stake_hold','stake_refund','stake_burn',
    'pool_pledge',   -- sponsor's credits move into the pool's hold
    'pool_draw',     -- the pool pays for one generation run
    'pool_refund',   -- unused credits returned pro rata
    'pool_sweep',    -- leftovers to the community pool, only if the sponsor chose that
    'community_spend' -- the community pool paying a shortfall (previously only an event)
));
CREATE INDEX credit_entries_pool ON credit_entries(pool_id, id) WHERE pool_id IS NOT NULL;

-- Every pool movement must name its pool, and no other kind may.
ALTER TABLE credit_entries ADD CONSTRAINT credit_pool_kinds CHECK (
    (kind IN ('pool_pledge','pool_draw','pool_refund','pool_sweep')) = (pool_id IS NOT NULL)
);

-- The books must balance: pledges = draws + refunds + sweeps + whatever is still held.
-- Published so anyone can recompute it; see `GET /api/pools/:id`.
CREATE VIEW pool_balances AS
SELECT p.id AS pool_id,
       COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'pool_pledge'), 0)::bigint AS pledged,
       COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'pool_draw'),   0)::bigint AS drawn,
       COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'pool_refund'), 0)::bigint AS refunded,
       COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'pool_sweep'),  0)::bigint AS swept,
       (COALESCE(SUM(c.credits) FILTER (WHERE c.kind = 'pool_pledge'), 0)
         - COALESCE(SUM(c.credits) FILTER (WHERE c.kind IN ('pool_draw','pool_refund','pool_sweep')), 0)
       )::bigint AS held
FROM sponsor_pools p
LEFT JOIN credit_entries c ON c.pool_id = p.id
GROUP BY p.id;

-- ---------------------------------------------------------------------------
-- 2. Per-feature evidence.
-- ---------------------------------------------------------------------------

-- One row per gate run, carrying enough to re-run it and enough to prove nobody edited the
-- results afterwards. `simulated` is explicit so the UI can never show a local dry-run as a
-- real pass.
CREATE TABLE evidence_runs (
    id                 BIGSERIAL PRIMARY KEY,
    intent_id          BIGINT NOT NULL REFERENCES intents(id),
    head_sha           TEXT NOT NULL,
    parent_sha         TEXT,
    gate               TEXT NOT NULL,
    check_name         TEXT NOT NULL,
    run_url            TEXT NOT NULL DEFAULT '',
    env                JSONB NOT NULL DEFAULT '{}'::jsonb,  -- toolchain, versions, command, seeds
    manifest_sha256    TEXT NOT NULL,                       -- hash over every blob hash
    attestation_bundle JSONB,                               -- Sigstore bundle from actions/attest
    rekor_log_index    BIGINT,
    ledger_seq         BIGINT,
    simulated          BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_runs_intent ON evidence_runs(intent_id, id);
CREATE INDEX evidence_runs_sha ON evidence_runs(head_sha);

CREATE TABLE test_results (
    run_id        BIGINT NOT NULL REFERENCES evidence_runs(id),
    test_id       TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'unit',
    status        TEXT NOT NULL CHECK (status IN ('pass','fail','flaky','skip','ignored')),
    attempts      JSONB NOT NULL DEFAULT '[]'::jsonb,
    duration_ms   BIGINT,
    output_sha256 TEXT,
    added_in_diff BOOLEAN NOT NULL DEFAULT false,
    -- Did this test FAIL on the parent commit? A test that already passed before the change
    -- proves nothing about the change. 'n/a' when it was not re-run against the parent.
    fail_before   TEXT NOT NULL DEFAULT 'n/a' CHECK (fail_before IN ('fail','pass','n/a')),
    PRIMARY KEY (run_id, test_id)
);

-- Requirement -> acceptance test -> Rust test. `source` records how the link was established:
-- a tag in the source, or a mutant that only this test caught.
CREATE TABLE acceptance_links (
    run_id         BIGINT NOT NULL REFERENCES evidence_runs(id),
    acceptance_id  TEXT NOT NULL,
    requirement_id TEXT NOT NULL,
    test_id        TEXT NOT NULL,
    source         TEXT NOT NULL CHECK (source IN ('tag','mutant')),
    PRIMARY KEY (run_id, acceptance_id, test_id, source)
);

CREATE TABLE mutant_results (
    run_id      BIGINT NOT NULL REFERENCES evidence_runs(id),
    mutant      TEXT NOT NULL,
    file        TEXT NOT NULL,
    line        INT,
    outcome     TEXT NOT NULL,
    caught_by   TEXT,
    diff_sha256 TEXT,
    PRIMARY KEY (run_id, mutant)
);

-- Content-addressed raw reports, stored outside GitHub so they outlive artifact retention.
CREATE TABLE evidence_blobs (
    sha256     TEXT PRIMARY KEY,
    media_type TEXT NOT NULL,
    size       BIGINT NOT NULL,
    uri        TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 3. Contributor signals.
-- ---------------------------------------------------------------------------

-- Public GitHub history, recomputed nightly rather than on demand so nobody can tune against
-- the score in a live loop. Every number is raw; normalisation and caps live in code, with the
-- weights in a versioned file, so a reader can recompute the result.
CREATE TABLE contributor_signals (
    user_id            BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    external_merged_prs INT NOT NULL DEFAULT 0,  -- merged by someone else, in repos they don't own
    external_repos      INT NOT NULL DEFAULT 0,  -- distinct repos above the quality floor
    active_weeks        INT NOT NULL DEFAULT 0,  -- weeks with commits on others' default branches
    shared_repos        INT NOT NULL DEFAULT 0,  -- qualifying OSS repos they published
    dependents          INT NOT NULL DEFAULT 0,  -- adoption of those repos
    scorecard           NUMERIC(4,2),            -- OpenSSF Scorecard of their best repo
    excluded            JSONB NOT NULL DEFAULT '[]'::jsonb, -- what was dropped and why, shown publicly
    opted_out           BOOLEAN NOT NULL DEFAULT false,     -- Trailhead-only scoring, no penalty
    score_version       TEXT NOT NULL DEFAULT 'v2',
    etag                TEXT,
    fetched_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Cached per-intent priority inputs and the published breakdown, frozen 48h before each train
-- so a late brigade cannot move the order after voting closes.
CREATE TABLE priority_snapshots (
    intent_id  BIGINT NOT NULL REFERENCES intents(id),
    train      TEXT NOT NULL,
    inputs     JSONB NOT NULL,
    breakdown  JSONB NOT NULL,
    version    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (intent_id, train)
);

-- ---------------------------------------------------------------------------
-- 4. Append-only.
-- ---------------------------------------------------------------------------
-- gate_results was editable, which made the gate record the one part of the pipeline a bug or
-- an operator could rewrite after the fact. Evidence is only worth as much as its immutability.
CREATE TRIGGER gate_results_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON gate_results
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

CREATE TRIGGER evidence_runs_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON evidence_runs
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER test_results_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON test_results
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER acceptance_links_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON acceptance_links
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER mutant_results_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON mutant_results
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER pool_sponsors_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON pool_sponsors
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER pool_recusals_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON pool_recusals
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
