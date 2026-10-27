-- 0006 — make a ledger payload removable without breaking the chain.
--
-- docs/TRANSPARENCY.md has always promised that a payload can be taken out — a leaked secret,
-- personal data someone is entitled to have erased, illegal content — and that "the chain still
-- verifies". Until now it could not: the hash was computed over the payload itself, so removing
-- one broke that event's hash and every hash after it. The policy said one thing and the
-- arithmetic said another, and the arithmetic wins.
--
-- From here, new events commit to `sha256(salt || canonical(payload))` instead of to the payload.
-- Removing a payload deletes the payload and its salt and keeps the commitment, so the chain
-- still verifies for everyone while the content is genuinely gone. The salt is what makes the
-- removal real: most payloads are short and guessable (a verdict, an amount), and an unsalted
-- hash of a small value can simply be reversed by hashing the candidates.
--
-- Existing events are NOT rehashed. Rewriting history to adopt a better scheme would invalidate
-- every checkpoint anyone has pinned, which is the one thing this ledger exists to prevent. Each
-- event records the version it was written under and is verified under those rules, so the chain
-- is a v1 prefix followed by a v2 suffix and both check out.

ALTER TABLE events ADD COLUMN hash_version   SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE events ADD COLUMN payload_commit TEXT;
ALTER TABLE events ADD COLUMN payload_salt   TEXT;

-- New rows default to 2; the rows already written keep the 1 the DEFAULT above gave them.
ALTER TABLE events ALTER COLUMN hash_version SET DEFAULT 2;

-- A v2 event with no commitment commits to nothing, and a v1 event with one would be ambiguous
-- about what its hash covers. Neither is allowed to exist.
ALTER TABLE events ADD CONSTRAINT events_hash_version_shape CHECK (
    (hash_version = 1 AND payload_commit IS NULL AND payload_salt IS NULL)
    OR
    (hash_version = 2 AND payload_commit IS NOT NULL)
);

COMMENT ON COLUMN events.payload_salt IS
    'Per-event random salt. Published while the payload is; deleted when the payload is removed, '
    'which is what stops a short payload being recovered by hashing guesses.';

-- Removing a payload is a deliberate, recorded act, never an UPDATE somebody runs by hand: the
-- append-only trigger blocks those, and this function is the only way past it. It writes the
-- tombstone, drops the salt, and leaves the commitment, so `trailhead ledger verify` still
-- passes. The removal is itself appended to the ledger by the caller, so the fact that something
-- was removed, when, and on whose authority is public even though the content is not.
CREATE OR REPLACE FUNCTION remove_event_payload(p_seq BIGINT, p_reason TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE v SMALLINT;
BEGIN
    SELECT hash_version INTO v FROM events WHERE seq = p_seq;
    IF v IS NULL THEN
        RAISE EXCEPTION 'no such event: %', p_seq;
    END IF;
    IF v <> 2 THEN
        RAISE EXCEPTION
            'event % was written under hash version %, which hashes the payload inline. '
            'Removing it would break every hash after it. Only v2 payloads can be removed.',
            p_seq, v;
    END IF;
    IF p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'a removal needs a public reason';
    END IF;

    ALTER TABLE events DISABLE TRIGGER events_append_only;
    UPDATE events
       SET payload = jsonb_build_object('removed', true, 'reason', p_reason),
           payload_salt = NULL
     WHERE seq = p_seq;
    ALTER TABLE events ENABLE TRIGGER events_append_only;
END $$;
