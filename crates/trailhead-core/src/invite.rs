//! Invitation-gated contribution.
//!
//! Signing up is open. Anyone may create an account, read every intent and follow a release — that
//! openness is the point of a project whose premise is public intent. Voting is open in the sense
//! that matters here, namely that it needs no invitation; it does still carry its own older rules
//! (`Tier::Visitor` cannot vote, and `credits::VOTE_MIN_ACCOUNT_DAYS` applies), which exist to stop
//! fresh accounts swinging the leaderboard and are untouched by anything in this module.
//!
//! Two things are not open, and need an invitation bound to the GitHub login that holds it:
//!
//!   * requesting a feature — opening an intent, which spends inference and occupies the queue;
//!   * working on a release — having generated work land in a train.
//!
//! WHY THE GATE IS HERE AND NOT AT THE DOOR
//! Gating signup would have been easier to write: one chokepoint in the OAuth callback. It would
//! also have gated reading and voting, which are the parts that have to stay public, and it would
//! have broken organisations outright — an employee of a paying employer could not have signed in
//! to redeem their key. Gating the two privileged ACTIONS instead leaves the front door open and
//! puts the check where the cost actually is.
//!
//! WHY LOGIN-BOUND RATHER THAN A CODE
//! An invitation names a GitHub login, and only that account can redeem it, so a leaked invitation
//! is worth nothing to whoever finds it and does not need to be kept secret. This is the opposite
//! choice from an organisation key — deliberately. A key is handed to a whole team, so it must be a
//! bearer token, which is why it is hashed, capped and revocable. An invitation goes to one named
//! person, so binding it is free and removes leakage from the threat model entirely.
//!
//! WHY A QUOTA BY TIER AND NOT BY POINTS
//! Tiers come only from merged work that stayed merged (`reputation::tier`). Points accumulate; a
//! tier has to be earned and can be lost. `Builder` needs five retained intents and two accepted
//! reviews, a real cost to anyone manufacturing accounts. A `Contributor` — one merged intent —
//! deliberately gets nothing: if a single merge bought the power to admit colleagues, the sybil
//! defences elsewhere would be decoration.
//!
//! The quota counts LIVE invitations, not lifetime ones. A lifetime budget would eventually stall
//! the project; a live budget is a rate limit that recycles as people actually join, and it bounds
//! how much one compromised account can do before anybody looks.

use serde::{Deserialize, Serialize};

use crate::reputation::Tier;

/// What an invitation entitles its holder to do. Ordered from least to most, but deliberately not
/// `Ord`: these are capability sets, and `Developer >= OrgAdmin` is not a question with an answer.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum InviteKind {
    /// May request features. This is what an organisation's staff get: the employer pays for the
    /// inference its people spend, and buys no part in writing the release.
    Requester,
    /// May request features and have work land in a release train.
    Developer,
    /// May request features and bring exactly one organisation into existence.
    OrgAdmin,
}

impl InviteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InviteKind::Requester => "requester",
            InviteKind::Developer => "developer",
            InviteKind::OrgAdmin => "org_admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "requester" => Some(InviteKind::Requester),
            "developer" => Some(InviteKind::Developer),
            "org_admin" => Some(InviteKind::OrgAdmin),
            _ => None,
        }
    }

    /// Every invitation carries the right to open an intent; that is the baseline the gate exists
    /// to grant. Reading and voting need no invitation and never consult this.
    pub fn may_request_features(self) -> bool {
        true
    }

    /// Whether generated work from this holder may enter a release train.
    ///
    /// Every kind may, today. The two gated activities — requesting a feature and working on a
    /// release — are gated by holding an invitation at all, not by holding a particular one, and
    /// that is deliberate: an organisation's staff have to be able to submit, or the credits their
    /// employer bought would pay for inference that could never land anywhere.
    ///
    /// The distinction is kept as a recorded `kind` because it is useful provenance and costs
    /// nothing, and because the enforcement point is live: tightening this to
    /// `matches!(self, InviteKind::Developer)` and narrowing the `may_develop` column in
    /// `user_rights` is the whole change, with the gate in `submit` already calling it. A
    /// capability that nothing checks is the failure mode this project has already had once, so the
    /// column is wired to a real check now rather than left as a promise.
    pub fn may_develop(self) -> bool {
        true
    }

    /// Only an invited organisation admin may create an organisation. Everything downstream —
    /// buying credits, minting keys, admitting staff — is already gated by `orgs` membership, so
    /// this single check is what makes organisations invitation-only.
    pub fn may_create_org(self) -> bool {
        matches!(self, InviteKind::OrgAdmin)
    }
}

/// How many LIVE (issued, not yet accepted, not revoked) invitations this tier may hold at once.
/// `None` means unlimited, which only a governor gets.
pub fn invite_quota(tier: Tier) -> Option<i64> {
    match tier {
        Tier::Governor => None,
        Tier::Steward => Some(10),
        Tier::Builder => Some(3),
        // One merged intent is too cheap to buy the power to admit other people.
        Tier::Contributor | Tier::Visitor => Some(0),
    }
}

/// Whether this tier may issue this kind of invitation at all.
///
/// Organisation admissions stay with the governor. An organisation is a funded, voting bloc, and
/// `credits::org_vote_weight` can only discount a bloc the project can see — so who may create one
/// is not a decision to spread across everyone who has merged five patches. Developer invitations
/// are likewise governor-only: admitting someone who can write a release is a larger act than
/// admitting someone who can ask for a feature, and the people who vote on the result should not
/// also be quietly choosing who produces it.
pub fn may_issue(tier: Tier, kind: InviteKind) -> bool {
    match kind {
        InviteKind::OrgAdmin | InviteKind::Developer => tier == Tier::Governor,
        InviteKind::Requester => invite_quota(tier).map(|q| q > 0).unwrap_or(true),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IssueError {
    /// This tier may not issue this kind of invitation.
    NotPermitted,
    /// Already holding as many live invitations as the tier allows.
    QuotaExhausted { quota: i64 },
    /// Someone already holds a live invitation for this login.
    AlreadyInvited,
    /// Not a syntactically possible GitHub login.
    BadLogin,
}

/// GitHub logins are case-insensitive, up to 39 characters, alphanumerics and single hyphens.
/// Normalising at the edge means the uniqueness index and every lookup agree, so `Alice` cannot be
/// invited a second time as `alice`.
pub fn normalize_login(raw: &str) -> Result<String, IssueError> {
    let s = raw.trim().trim_start_matches('@');
    let ok = !s.is_empty()
        && s.len() <= 39
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--");
    if ok {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(IssueError::BadLogin)
    }
}

/// The whole issuing decision, with no database in it so every branch is testable.
pub fn may_issue_now(
    tier: Tier,
    kind: InviteKind,
    live_held: i64,
    target_already_invited: bool,
) -> Result<(), IssueError> {
    if !may_issue(tier, kind) {
        return Err(IssueError::NotPermitted);
    }
    if target_already_invited {
        return Err(IssueError::AlreadyInvited);
    }
    if let Some(q) = invite_quota(tier) {
        if live_held >= q {
            return Err(IssueError::QuotaExhausted { quota: q });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_TIER: [Tier; 5] = [
        Tier::Visitor,
        Tier::Contributor,
        Tier::Builder,
        Tier::Steward,
        Tier::Governor,
    ];

    #[test]
    fn signing_up_is_not_gated_so_every_invitation_can_request_features() {
        for k in [
            InviteKind::Requester,
            InviteKind::Developer,
            InviteKind::OrgAdmin,
        ] {
            assert!(k.may_request_features());
        }
    }

    // Holding an invitation is what permits release work; which kind is provenance, not policy.
    // An organisation's staff must be able to submit or their employer's credits buy nothing.
    #[test]
    fn any_invitation_permits_release_work() {
        for k in [
            InviteKind::Requester,
            InviteKind::Developer,
            InviteKind::OrgAdmin,
        ] {
            assert!(k.may_develop(), "{k:?} must be able to submit");
        }
    }

    // Redeeming an employer's key makes someone staff, never an admin who could buy credits or
    // mint keys on the organisation's behalf. Paying for inference buys no say over the employer.
    #[test]
    fn org_admin_is_the_only_kind_that_creates_an_organisation() {
        assert!(InviteKind::OrgAdmin.may_create_org());
        assert!(!InviteKind::Requester.may_create_org());
        assert!(!InviteKind::Developer.may_create_org());
    }

    #[test]
    fn only_earned_tiers_may_invite_a_requester() {
        assert!(!may_issue(Tier::Visitor, InviteKind::Requester));
        assert!(!may_issue(Tier::Contributor, InviteKind::Requester));
        assert!(may_issue(Tier::Builder, InviteKind::Requester));
        assert!(may_issue(Tier::Steward, InviteKind::Requester));
        assert!(may_issue(Tier::Governor, InviteKind::Requester));
    }

    #[test]
    fn developers_and_organisations_are_admitted_only_by_the_governor() {
        for t in EVERY_TIER.into_iter().filter(|t| *t != Tier::Governor) {
            for k in [InviteKind::Developer, InviteKind::OrgAdmin] {
                assert!(!may_issue(t, k), "{t:?} must not issue {k:?}");
            }
        }
        assert!(may_issue(Tier::Governor, InviteKind::Developer));
        assert!(may_issue(Tier::Governor, InviteKind::OrgAdmin));
    }

    #[test]
    fn quota_is_enforced_and_the_governor_has_none() {
        assert_eq!(
            may_issue_now(Tier::Builder, InviteKind::Requester, 3, false),
            Err(IssueError::QuotaExhausted { quota: 3 })
        );
        assert!(may_issue_now(Tier::Builder, InviteKind::Requester, 2, false).is_ok());
        assert!(may_issue_now(Tier::Governor, InviteKind::Developer, 10_000, false).is_ok());
    }

    #[test]
    fn a_live_invitation_blocks_a_second_one() {
        assert_eq!(
            may_issue_now(Tier::Governor, InviteKind::Developer, 0, true),
            Err(IssueError::AlreadyInvited)
        );
    }

    #[test]
    fn permission_is_checked_before_quota() {
        // A visitor at zero held invitations must read as NotPermitted, never as a spare slot.
        assert_eq!(
            may_issue_now(Tier::Visitor, InviteKind::Requester, 0, false),
            Err(IssueError::NotPermitted)
        );
    }

    #[test]
    fn logins_normalise_case_and_at_signs() {
        assert_eq!(normalize_login("  @Alice  ").unwrap(), "alice");
        assert_eq!(normalize_login("a-b-c").unwrap(), "a-b-c");
        assert_eq!(normalize_login(&"a".repeat(39)).unwrap().len(), 39);
    }

    #[test]
    fn impossible_logins_are_refused() {
        for bad in [
            "",
            "   ",
            "-lead",
            "trail-",
            "do--uble",
            "has space",
            "semi;colon",
            "slash/es",
            "emoji\u{1f600}",
            "'; DROP TABLE users--",
        ] {
            assert_eq!(
                normalize_login(bad),
                Err(IssueError::BadLogin),
                "{bad:?} must be refused"
            );
        }
        assert_eq!(normalize_login(&"a".repeat(40)), Err(IssueError::BadLogin));
    }

    #[test]
    fn kinds_round_trip_through_their_database_spelling() {
        for k in [
            InviteKind::Requester,
            InviteKind::Developer,
            InviteKind::OrgAdmin,
        ] {
            assert_eq!(InviteKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(InviteKind::parse("governor"), None);
        assert_eq!(InviteKind::parse(""), None);
    }
}
