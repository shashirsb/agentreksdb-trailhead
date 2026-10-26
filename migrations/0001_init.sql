-- Trailhead schema. Two tables are append-only by trigger: `events` (the public ledger) and
-- `credit_entries` (the credit ledger). Nothing in either can be updated or deleted.

CREATE TABLE users (
    id                  BIGSERIAL PRIMARY KEY,
    github_id           BIGINT UNIQUE,
    login               TEXT NOT NULL UNIQUE,      -- display only; identity is github_id
    account_created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_org_domain TEXT,
    is_governor         BOOLEAN NOT NULL DEFAULT false,
    rep_points          BIGINT NOT NULL DEFAULT 0,
    banned_until        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,           -- sha256 of the cookie value; the raw token is never stored
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE intents (
    id            BIGSERIAL PRIMARY KEY,
    title         TEXT NOT NULL,
    area          TEXT NOT NULL,
    author_id     BIGINT NOT NULL REFERENCES users(id),
    intent        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'draft',
    stage         INT  NOT NULL DEFAULT 2,
    stake_credits BIGINT NOT NULL,
    change_type   TEXT,
    risk          TEXT,
    spec          JSONB NOT NULL DEFAULT '{}'::jsonb,
    train         TEXT,
    holds         INT  NOT NULL DEFAULT 0,  -- trains spent on hold
    hold_from     TEXT,                     -- status to return to when the next train starts
    branch        TEXT,
    pr_number     BIGINT,
    commit_sha    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT status_ok CHECK (status IN ('draft','submitted','guardrails','held','generating','gates',
                                           'review','flagged','merged','on_hold','rejected'))
);
CREATE INDEX intents_status ON intents(status);
CREATE INDEX intents_train ON intents(train);

CREATE TABLE intent_messages (
    id         BIGSERIAL PRIMARY KEY,
    intent_id  BIGINT NOT NULL REFERENCES intents(id),
    role       TEXT NOT NULL CHECK (role IN ('user','ai')),
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX intent_messages_intent ON intent_messages(intent_id, id);

CREATE TABLE votes (
    user_id    BIGINT NOT NULL REFERENCES users(id),
    intent_id  BIGINT NOT NULL REFERENCES intents(id),
    quarter    TEXT NOT NULL,
    points     BIGINT NOT NULL CHECK (points > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, intent_id, quarter)
);

CREATE TABLE gate_results (
    id         BIGSERIAL PRIMARY KEY,
    intent_id  BIGINT NOT NULL REFERENCES intents(id),
    gate       TEXT NOT NULL,
    check_name TEXT,                       -- the GitHub check run, when the gate has several
    verdict    TEXT NOT NULL CHECK (verdict IN ('pass','warn','block','pending')),
    detail     TEXT NOT NULL DEFAULT '',
    head_sha   TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX gate_results_intent ON gate_results(intent_id, gate, id);

CREATE TABLE decisions (
    id         BIGSERIAL PRIMARY KEY,
    intent_id  BIGINT NOT NULL REFERENCES intents(id),
    train      TEXT NOT NULL,
    decision   TEXT NOT NULL CHECK (decision IN ('merge','hold','reject')),
    reason     TEXT NOT NULL CHECK (length(reason) > 0),
    governor   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE bundles (
    intent_id    BIGINT PRIMARY KEY REFERENCES intents(id),
    base         TEXT NOT NULL,
    patch        BYTEA NOT NULL,
    patch_sha256 TEXT NOT NULL,
    message      TEXT NOT NULL,
    provenance   JSONB NOT NULL,
    ledger_seq   BIGINT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
    id          BIGSERIAL PRIMARY KEY,
    kind        TEXT NOT NULL,
    intent_id   BIGINT REFERENCES intents(id),
    state       TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','done','failed')),
    attempts    INT NOT NULL DEFAULT 0,
    run_after   TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at   TIMESTAMPTZ,
    last_error  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX jobs_ready ON jobs(state, run_after);

CREATE TABLE checkpoints (
    seq        BIGINT PRIMARY KEY,
    head       TEXT NOT NULL,
    signature  TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The public ledger.
CREATE TABLE events (
    seq        BIGINT PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL,
    kind       TEXT NOT NULL,
    intent_id  BIGINT,
    actor      TEXT NOT NULL,
    payload    JSONB NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE
);
CREATE INDEX events_intent ON events(intent_id, seq);

-- The credit ledger.
CREATE TABLE credit_entries (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id),
    kind       TEXT NOT NULL CHECK (kind IN ('grant','purchase','spend','stake_hold','stake_refund','stake_burn')),
    credits    BIGINT NOT NULL CHECK (credits >= 0),
    intent_id  BIGINT REFERENCES intents(id),
    memo       TEXT NOT NULL DEFAULT '',
    period     TEXT,                          -- 'YYYY-MM' for monthly grants (one per month)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX credit_entries_user ON credit_entries(user_id, id);
CREATE UNIQUE INDEX credit_grant_once ON credit_entries(user_id, period) WHERE kind = 'grant';

CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;

CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON events
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER credits_append_only BEFORE UPDATE OR DELETE ON credit_entries
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER credits_no_truncate BEFORE TRUNCATE ON credit_entries
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
