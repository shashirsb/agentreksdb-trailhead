-- 0008 — organisation keys.
--
-- An admin mints a key in settings and hands it to staff, who redeem it to have their inference
-- billed to the employer. It can be revoked at any moment, which is the only control that really
-- matters: a secret shared with a whole engineering team is a secret that will end up in a chat
-- log, a screenshot and eventually a public repository.
--
-- So the key is treated as the leaky credential it is. Only `key_hash` is stored — a database
-- dump, a backup or a stray query result yields nothing anyone can redeem, for the same reason
-- nobody stores passwords. `prefix` exists so an admin can tell two keys apart in a list without
-- the database ever holding enough to rebuild one.
--
-- Redeeming makes the redeemer a MEMBER rather than granting anonymous spending. That keeps every
-- bill attached to one named person, and puts them inside the employer's voting cluster. A key
-- that funded people while leaving their votes looking independent would be a cleaner way to buy
-- the queue than sponsor pools ever were.

CREATE TABLE org_keys (
    id           BIGSERIAL PRIMARY KEY,
    org_id       BIGINT NOT NULL REFERENCES orgs(id),
    -- What the admin calls it, e.g. "platform team, 2026".
    label        TEXT NOT NULL,
    -- Marker plus the first few random characters. Safe to display; useless to an attacker.
    prefix       TEXT NOT NULL,
    -- SHA-256 of the full secret. The secret itself is shown once, at creation, and never again.
    key_hash     TEXT NOT NULL,
    created_by   BIGINT NOT NULL REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ,
    revoked_by   BIGINT REFERENCES users(id),
    last_used_at TIMESTAMPTZ,
    uses         BIGINT NOT NULL DEFAULT 0 CHECK (uses >= 0),
    -- NULL means no limit. A cap turns a leak into a bounded one.
    max_uses     BIGINT CHECK (max_uses IS NULL OR max_uses > 0),
    -- NULL means it never expires on its own.
    expires_at   TIMESTAMPTZ
);

-- Redemption looks a key up by hash, so this index is both the uniqueness guarantee and the
-- lookup path. Two keys can never collide.
CREATE UNIQUE INDEX org_keys_hash ON org_keys (key_hash);
CREATE INDEX org_keys_org ON org_keys (org_id, id);

COMMENT ON COLUMN org_keys.key_hash IS
    'SHA-256 of the secret. A plain hash rather than a password hash on purpose: the secret is 32 '
    'bytes of machine randomness, so there is no dictionary to attack and a slow hash would only '
    'make every redemption slower.';

-- Who redeemed which key, kept separately so revoking or deleting a key never erases the record
-- of who joined through it. An organisation's membership has to stay explicable after the fact.
CREATE TABLE org_key_redemptions (
    key_id      BIGINT NOT NULL REFERENCES org_keys(id),
    user_id     BIGINT NOT NULL REFERENCES users(id),
    redeemed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (key_id, user_id)
);
