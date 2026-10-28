-- 0009 — invitations gate contributing, not signing up.
--
-- Anyone may create an account, read every intent, follow a release and vote. Two things need an
-- invitation: requesting a feature, and having work land in a release train.
--
-- The gate is on those two ACTIONS rather than on the account. Gating signup would have been one
-- check in the OAuth callback and would have been wrong twice over: it would have gated reading and
-- voting, which have to stay public in a project built on public intent, and it would have locked
-- out the staff of a paying organisation, who must be able to sign in before they can redeem the
-- key that bills their employer.
--
-- An invitation names a GitHub login and only that account can redeem it, so it is not a secret and
-- a leaked one is useless to whoever finds it. That is the opposite of an organisation key (0008),
-- which is handed to a whole team and therefore has to be hashed, capped and revocable. Different
-- distribution, different threat, different design.

CREATE TABLE invites (
    id              BIGSERIAL PRIMARY KEY,
    -- Normalised by core::invite::normalize_login: lowercase, no leading '@'. Stored rather than
    -- referenced because the invitee usually has no account here yet.
    login           TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('requester', 'developer', 'org_admin')),
    issued_by       BIGINT NOT NULL REFERENCES users(id),
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Why this person; shown in the public invitation list so admissions are explicable.
    note            TEXT NOT NULL DEFAULT '',
    accepted_at     TIMESTAMPTZ,
    accepted_user   BIGINT REFERENCES users(id),
    revoked_at      TIMESTAMPTZ,
    revoked_by      BIGINT REFERENCES users(id),
    revoked_reason  TEXT,
    -- Acceptance has to name the account that accepted, and cannot be half-recorded.
    CONSTRAINT invites_accept_shape CHECK ((accepted_at IS NULL) = (accepted_user IS NULL)),
    CONSTRAINT invites_revoke_shape CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

-- One LIVE invitation per login. A second invitation may be issued only once the first has been
-- revoked, so two stewards cannot each spend a quota slot on the same person and so the quota
-- cannot be sidestepped by inviting one login repeatedly.
--
-- Deliberately scoped to unaccepted-and-unrevoked rather than to the login alone: an accepted
-- invitation must not block a later, different invitation (a requester promoted to developer), and
-- a revoked one must not block a reinstatement.
CREATE UNIQUE INDEX invites_one_live_per_login
    ON invites (login)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX invites_issuer ON invites (issued_by, id);
CREATE INDEX invites_login ON invites (login);

COMMENT ON TABLE invites IS
    'Invitations to contribute. Signing up needs none of these; opening an intent or landing work '
    'in a release does. Bound to a GitHub login, so an invitation is not a secret.';

-- What a given account is actually allowed to do, computed rather than stored, so that revoking an
-- invitation takes effect immediately and cannot drift out of step with a cached flag on `users`.
--
-- Revocation is honoured after acceptance on purpose: admitting someone is reversible. An
-- organisation key grants the right to request features for as long as the holder remains a member
-- of an organisation, which is itself revocable by deleting the key or the membership.
CREATE VIEW user_rights AS
SELECT u.id AS user_id,
       u.login,
       u.is_governor,
       -- A governor may do everything; this is what lets the first invitation exist at all.
       (u.is_governor
         OR EXISTS (SELECT 1 FROM invites i
                     WHERE i.accepted_user = u.id AND i.revoked_at IS NULL)
         OR EXISTS (SELECT 1 FROM org_members m
                     WHERE m.user_id = u.id)) AS may_request_features,
       -- Holding an invitation is what permits release work; which kind is provenance, not policy.
       -- Narrowing this to `AND i.kind = 'developer'` is the one-line change if developers should
       -- ever be a stricter class than requesters — `core::invite::may_develop` says the same.
       (u.is_governor
         OR EXISTS (SELECT 1 FROM invites i
                     WHERE i.accepted_user = u.id AND i.revoked_at IS NULL)
         OR EXISTS (SELECT 1 FROM org_members m
                     WHERE m.user_id = u.id)) AS may_develop,
       (u.is_governor
         OR EXISTS (SELECT 1 FROM invites i
                     WHERE i.accepted_user = u.id AND i.revoked_at IS NULL
                       AND i.kind = 'org_admin')) AS may_create_org
FROM users u;

COMMENT ON VIEW user_rights IS
    'Derived, never stored: revoking an invitation must take effect at once rather than when some '
    'cached flag is next rewritten. Public, so anyone can check who may contribute and why.';
