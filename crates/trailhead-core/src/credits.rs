//! Credits, stakes and quadratic votes. 1 credit = $0.01 of provider list price.
//! Money buys inference, never trust: purchased credits never change tier, vote weight or
//! governor eligibility.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Credits per US dollar of provider list price.
pub const CREDITS_PER_USD: i64 = 100;
/// Paid credits are sold at 1.5x cost (blocks from $150), 1.3x for blocks from $5,000.
pub const PAID_MARKUP_PCT: i64 = 150;
pub const VOLUME_MARKUP_PCT: i64 = 130;
pub const VOLUME_BLOCK_USD: i64 = 5_000;
pub const MIN_BLOCK_USD: i64 = 150;

/// Quadratic voting budget per account per quarter.
pub const VOTE_BUDGET: i64 = 100;
/// No single account may hold more than this share (percent) of an intent's vote mass.
pub const VOTE_CAP_PCT: i64 = 20;
/// Minimum account age (days) to vote.
pub const VOTE_MIN_ACCOUNT_DAYS: i64 = 30;
/// Most points one account can put on one intent (10 points cost the whole quarterly budget).
pub const VOTE_MAX_POINTS: i64 = 10;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// Monthly free allowance from the account's tier.
    Grant,
    /// Paid credits.
    Purchase,
    /// Inference spent on generation, review or test runs.
    Spend,
    /// Stake moved out of the spendable balance while an intent is open.
    StakeHold,
    /// Stake returned on merge or good-faith decline.
    StakeRefund,
    /// Stake burned on spam; it funds the community inference pool.
    StakeBurn,
    /// The community pool covering a shortfall, so its books balance like any other account.
    CommunitySpend,
    /// Credits an organisation bought so its own members can pay for inference.
    ///
    /// This is NOT the sponsor pool that was removed in 0004, and the difference is the whole
    /// point. A pool named a FEATURE and paid for it, which tied money to a queue position and
    /// needed disclosure, recusal and auditing to stay honest. An organisation balance names
    /// PEOPLE: its members draw on it to run their own intents, exactly as they would draw on
    /// their personal balance. There is no API that points organisation money at an intent
    /// somebody else wrote, and no term in the score that any amount of it can reach.
    OrgPurchase,
    /// A member spent the organisation's credits on their own intent's inference.
    OrgSpend,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::Grant => "grant",
            EntryKind::Purchase => "purchase",
            EntryKind::Spend => "spend",
            EntryKind::StakeHold => "stake_hold",
            EntryKind::StakeRefund => "stake_refund",
            EntryKind::StakeBurn => "stake_burn",
            EntryKind::CommunitySpend => "community_spend",
            EntryKind::OrgPurchase => "org_purchase",
            EntryKind::OrgSpend => "org_spend",
        }
    }
    pub fn parse(s: &str) -> Option<EntryKind> {
        Some(match s {
            "grant" => EntryKind::Grant,
            "purchase" => EntryKind::Purchase,
            "spend" => EntryKind::Spend,
            "stake_hold" => EntryKind::StakeHold,
            "stake_refund" => EntryKind::StakeRefund,
            "stake_burn" => EntryKind::StakeBurn,
            "community_spend" => EntryKind::CommunitySpend,
            "org_purchase" => EntryKind::OrgPurchase,
            "org_spend" => EntryKind::OrgSpend,
            _ => return None,
        })
    }
    /// Sign applied to the stored (always positive) amount when computing a spendable balance.
    /// A burn is zero here because the stake already left the balance at hold time.
    pub fn sign(self) -> i64 {
        match self {
            EntryKind::Grant | EntryKind::Purchase | EntryKind::StakeRefund => 1,
            EntryKind::Spend | EntryKind::StakeHold => -1,
            // These move money inside the community or an organisation account, never a
            // person's spendable balance. A member spending the organisation's credits leaves
            // their own balance untouched, which is the point of the organisation paying.
            EntryKind::StakeBurn
            | EntryKind::CommunitySpend
            | EntryKind::OrgPurchase
            | EntryKind::OrgSpend => 0,
        }
    }
}

/// Spendable balance from ledger entries `(kind, positive amount)`.
pub fn balance<'a>(entries: impl IntoIterator<Item = &'a (EntryKind, i64)>) -> i64 {
    entries.into_iter().map(|(k, c)| k.sign() * c).sum()
}

/// Minimum stake by change type, in credits ($5 / $25 / $100).
pub fn min_stake(change_type: &str) -> i64 {
    match change_type {
        "protocol" => 10_000,
        "feature" | "perf" | "refactor" => 2_500,
        _ => 500,
    }
}

/// Price in US cents for buying `credits` paid credits.
pub fn purchase_price_cents(credits: i64) -> i64 {
    let cost_cents = credits; // 1 credit = 1 cent at list price
    let pct = if credits >= VOLUME_BLOCK_USD * CREDITS_PER_USD {
        VOLUME_MARKUP_PCT
    } else {
        PAID_MARKUP_PCT
    };
    (cost_cents * pct + 99) / 100
}

/// Cost of `points` quadratic votes.
pub fn vote_cost(points: i64) -> i64 {
    points * points
}

#[derive(Debug, PartialEq, Eq)]
pub enum VoteError {
    NotPositive,
    OverBudget { cost: i64, left: i64 },
    OverCap,
}

/// Check a vote. `spent` = quadratic cost already used this quarter on other intents;
/// `others_total` = all other accounts' points on this intent.
pub fn check_vote(points: i64, spent: i64, others_total: i64) -> Result<i64, VoteError> {
    if points <= 0 {
        return Err(VoteError::NotPositive);
    }
    if points > VOTE_MAX_POINTS {
        return Err(VoteError::OverBudget {
            cost: i64::MAX,
            left: VOTE_BUDGET - spent,
        });
    }
    let cost = vote_cost(points);
    let left = VOTE_BUDGET - spent;
    if cost > left {
        return Err(VoteError::OverBudget { cost, left });
    }
    // Cap only applies once there is a crowd: a single early voter is not "capture".
    let total = others_total + points;
    if others_total >= 20 && points * 100 > VOTE_CAP_PCT * total {
        return Err(VoteError::OverCap);
    }
    Ok(left - cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_counts_holds_and_refunds_once() {
        let e = vec![
            (EntryKind::Grant, 500),
            (EntryKind::StakeHold, 500),
            (EntryKind::Spend, 0),
            (EntryKind::StakeRefund, 500),
        ];
        assert_eq!(balance(&e), 500);
        let burned = vec![
            (EntryKind::Grant, 500),
            (EntryKind::StakeHold, 500),
            (EntryKind::StakeBurn, 500),
        ];
        assert_eq!(balance(&burned), 0);
    }

    #[test]
    fn pricing() {
        assert_eq!(purchase_price_cents(15_000), 22_500); // $150 of inference costs $225
        assert_eq!(purchase_price_cents(500_000), 650_000); // volume block at 1.3x
    }

    #[test]
    fn quadratic_votes() {
        assert_eq!(check_vote(5, 0, 0), Ok(75));
        assert!(check_vote(4_294_967_296, 0, 0).is_err()); // would wrap to cost 0 without the cap
        assert_eq!(
            check_vote(10, 1, 0),
            Err(VoteError::OverBudget {
                cost: 100,
                left: 99
            })
        );
        assert_eq!(check_vote(6, 0, 20), Err(VoteError::OverCap)); // 6/26 = 23%
        assert_eq!(check_vote(5, 0, 20), Ok(75)); // 5/25 = 20%
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Organisation accounts: buying inference for your own people
// ──────────────────────────────────────────────────────────────────────────────
//
// An organisation buys credits so its employees can run intents without paying personally. The
// money buys compute for a person. It does not buy anything for a feature.
//
// That sentence is the whole design, and it is what separates this from the sponsor pools that
// were built and then deleted in migration 0004. A pool named a feature and funded it. However
// carefully the rules were written — no priority, no vote weight, no merge rights — the money
// was still attached to a queue item, so keeping the promise true needed disclosure, recusal,
// refunds and an audit of every pool, and each of those was somewhere it could quietly stop
// being true. An organisation balance is attached to its members instead. There is no call that
// points it at an intent somebody else wrote, so there is nothing to disclose or recuse from.
//
// The one real risk this does introduce is votes, not money: an organisation with fifty staff is
// fifty accounts that may all back the same intent. That is why `org_vote_weight` exists, and why
// formalising membership is a net gain for the ranking — a link the project can see is a cluster
// it can discount, where fifty unaffiliated-looking accounts are not.

/// How a single run's cost is split across the accounts that can pay for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Funding {
    /// Paid by the author's organisation, if they belong to one with a balance.
    pub from_org: i64,
    /// Paid from the author's own credits.
    pub from_author: i64,
    /// Covered by the community pool because neither of the above could.
    pub from_community: i64,
}

/// Decide who pays for one run.
///
/// The organisation pays first when the author belongs to one, because paying for its people's
/// inference is the only reason it bought the credits. The author's own balance is next, and the
/// community pool covers whatever is left so a run is never abandoned half-finished over money.
///
/// `org_balance` is zero when the author belongs to no organisation, which collapses this to the
/// behaviour that existed before organisations did.
pub fn split_funding(cost: i64, org_balance: i64, author_balance: i64) -> Funding {
    let owed = cost.max(0);
    let from_org = owed.min(org_balance.max(0));
    let rest = owed - from_org;
    let from_author = rest.min(author_balance.max(0));
    Funding {
        from_org,
        from_author,
        from_community: rest - from_author,
    }
}

/// The share of an organisation's combined vote on one intent that counts.
///
/// Colleagues backing their employer's priority is not fraud, and it is not independent support
/// either. Counting every one of fifty staff votes at face value would let the largest payroll
/// set the queue, which is the outcome dropping sponsor pools was meant to prevent — arriving by
/// a different road.
///
/// So an organisation's votes on a single intent count in full up to `free`, and at a square-root
/// rate beyond it: the tenth colleague adds far less than the second, and the fiftieth barely
/// moves it, while a genuinely broad coalition inside a large company still outweighs a handful.
/// Returns the weighted points, never more than were cast.
pub fn org_vote_weight(points_from_org: i64, free: i64) -> f64 {
    let p = points_from_org.max(0) as f64;
    let f = free.max(0) as f64;
    if p <= f {
        return p;
    }
    f + (p - f).sqrt()
}

/// The default number of colleagues whose votes count at face value before the discount bites.
/// Three is a team agreeing, not a company voting.
pub const ORG_VOTE_FREE_POINTS: i64 = 3;

#[cfg(test)]
mod org_tests {
    use super::*;

    #[test]
    fn the_organisation_pays_first_when_it_can() {
        let f = split_funding(100, 1000, 500);
        assert_eq!(
            f,
            Funding {
                from_org: 100,
                from_author: 0,
                from_community: 0
            }
        );
    }

    #[test]
    fn the_author_covers_what_the_organisation_cannot() {
        let f = split_funding(100, 30, 500);
        assert_eq!(
            f,
            Funding {
                from_org: 30,
                from_author: 70,
                from_community: 0
            }
        );
    }

    /// Someone with no employer behind them is funded exactly as before organisations existed.
    #[test]
    fn an_unaffiliated_author_is_unaffected() {
        let f = split_funding(100, 0, 40);
        assert_eq!(
            f,
            Funding {
                from_org: 0,
                from_author: 40,
                from_community: 60
            }
        );
    }

    #[test]
    fn the_community_pool_is_the_last_resort() {
        let f = split_funding(100, 0, 0);
        assert_eq!(f.from_community, 100);
    }

    #[test]
    fn every_split_adds_up_to_the_cost_and_never_goes_negative() {
        for cost in [0, 1, 7, 100, 999] {
            for org in [-5, 0, 3, 100] {
                for author in [-5, 0, 11, 100] {
                    let f = split_funding(cost, org, author);
                    assert_eq!(f.from_org + f.from_author + f.from_community, cost.max(0));
                    assert!(f.from_org >= 0 && f.from_author >= 0 && f.from_community >= 0);
                }
            }
        }
    }

    #[test]
    fn a_small_team_agreeing_counts_in_full() {
        assert_eq!(org_vote_weight(3, ORG_VOTE_FREE_POINTS), 3.0);
        assert_eq!(org_vote_weight(1, ORG_VOTE_FREE_POINTS), 1.0);
        assert_eq!(org_vote_weight(0, ORG_VOTE_FREE_POINTS), 0.0);
    }

    /// The point of the curve: a large payroll cannot simply outvote the community.
    #[test]
    fn a_large_payroll_cannot_buy_the_queue_with_headcount() {
        let fifty = org_vote_weight(50, ORG_VOTE_FREE_POINTS);
        assert!(fifty < 11.0, "fifty colleagues weighed {fifty}");
        // Ten independent voters must still outweigh fifty colleagues of one employer.
        assert!(10.0 > fifty);
    }

    #[test]
    fn the_weight_never_exceeds_the_votes_actually_cast() {
        for p in 0..200 {
            assert!(org_vote_weight(p, ORG_VOTE_FREE_POINTS) <= p as f64 + 1e-9);
        }
    }

    #[test]
    fn the_weight_only_ever_grows_with_more_support() {
        let mut last = -1.0;
        for p in 0..100 {
            let w = org_vote_weight(p, ORG_VOTE_FREE_POINTS);
            assert!(w >= last, "weight fell at {p}");
            last = w;
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Organisation keys
// ──────────────────────────────────────────────────────────────────────────────
//
// An admin mints a key in settings and hands it to staff, who redeem it to have their inference
// billed to the employer. It is revocable at any moment, which is the only control that genuinely
// matters: a secret shared with a whole engineering team is a secret that will end up in a chat
// log, a screenshot and eventually a public repository.
//
// So it is treated as the leaky credential it is:
//
//   * Only a hash is stored. A database dump, a backup or a stray query result yields nothing a
//     thief can redeem, which is the same reason nobody stores passwords.
//   * It carries a fixed, greppable prefix. Secret scanners find a credential by its shape, so
//     one that looks like nothing in particular is one nobody will ever catch in a diff. This
//     project runs gitleaks over every change; `gates/semgrep` now knows this shape too.
//   * Redeeming makes the redeemer a MEMBER rather than granting anonymous spend. That keeps one
//     bill tied to one named person, and — just as importantly — puts them inside the employer's
//     voting cluster. A key that funded people while leaving their votes looking independent
//     would be a cleaner way to buy the queue than sponsor pools ever were.
//
// What a leaked key costs is bounded: strangers can join the organisation and spend its credits,
// which shows up by name on the organisation's public page, and the admin revokes it. What it
// cannot do is reach a feature, because membership confers no power over any intent.

/// The prefix every organisation key carries. Deliberately distinctive so a secret scanner, a
/// reviewer skimming a diff, or a search of a chat log will find it.
pub const ORG_KEY_PREFIX: &str = "trailhead_org_";
/// Random bytes behind the prefix. 32 bytes is far beyond guessing.
pub const ORG_KEY_BYTES: usize = 32;

/// A freshly minted key: the secret to show the admin exactly once, and what to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOrgKey {
    /// The full secret. Shown once at creation and never recoverable afterwards.
    pub secret: String,
    /// The leading characters, safe to store and display so a key can be told apart from another.
    pub prefix: String,
    /// What the database keeps.
    pub hash: String,
}

/// Hash a key for storage and lookup.
///
/// A plain SHA-256 rather than a password hash on purpose: this is 32 bytes of machine-generated
/// randomness, not a human-chosen password, so there is no dictionary to attack and nothing for a
/// slow hash to defend. A slow hash here would only make every redemption slower.
pub fn org_key_hash(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret.trim().as_bytes());
    hex::encode(h.finalize())
}

/// The displayable prefix of a key: the fixed marker plus the first 6 random characters. Enough
/// to tell two keys apart in a list, far too little to reconstruct one.
pub fn org_key_display_prefix(secret: &str) -> String {
    let s = secret.trim();
    let take = ORG_KEY_PREFIX.len() + 6;
    s.chars().take(take).collect()
}

/// Mint a key from the operating system's random source.
pub fn new_org_key() -> NewOrgKey {
    use rand::RngCore;
    let mut b = [0u8; ORG_KEY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let secret = format!("{ORG_KEY_PREFIX}{}", hex::encode(b));
    NewOrgKey {
        prefix: org_key_display_prefix(&secret),
        hash: org_key_hash(&secret),
        secret,
    }
}

/// Why a key was refused. Each is reported to the person redeeming it, because "that did not
/// work" sends them to an admin who cannot tell either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgKeyError {
    /// Not even the right shape, so it was never a key from here.
    Malformed,
    /// Right shape, no such key, or it was revoked.
    Unknown,
    Revoked,
    Expired,
    /// The admin capped how many people may redeem it, and that many have.
    Exhausted,
}

impl OrgKeyError {
    pub fn code(self) -> &'static str {
        match self {
            OrgKeyError::Malformed => "key_malformed",
            OrgKeyError::Unknown => "key_unknown",
            OrgKeyError::Revoked => "key_revoked",
            OrgKeyError::Expired => "key_expired",
            OrgKeyError::Exhausted => "key_exhausted",
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            OrgKeyError::Malformed => {
                "That does not look like an organisation key. They begin with trailhead_org_."
            }
            OrgKeyError::Unknown => {
                "That key does not exist. Ask your administrator for a new one."
            }
            OrgKeyError::Revoked => {
                "That key has been revoked. Ask your administrator for a new one."
            }
            OrgKeyError::Expired => "That key has expired. Ask your administrator for a new one.",
            OrgKeyError::Exhausted => {
                "That key has already been used the maximum number of times. Ask for a new one."
            }
        }
    }
}

/// Check the shape before touching the database, so a stray paste never becomes a query.
pub fn parse_org_key(input: &str) -> Result<String, OrgKeyError> {
    let s = input.trim();
    if !s.starts_with(ORG_KEY_PREFIX) {
        return Err(OrgKeyError::Malformed);
    }
    let body = &s[ORG_KEY_PREFIX.len()..];
    if body.len() != ORG_KEY_BYTES * 2 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OrgKeyError::Malformed);
    }
    Ok(org_key_hash(s))
}

/// Everything about a stored key that decides whether it may still be redeemed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OrgKeyState {
    pub revoked: bool,
    pub expired: bool,
    pub uses: i64,
    /// `None` means no limit.
    pub max_uses: Option<i64>,
}

/// Decide whether a key that exists may be redeemed once more.
pub fn org_key_usable(k: OrgKeyState) -> Result<(), OrgKeyError> {
    if k.revoked {
        return Err(OrgKeyError::Revoked);
    }
    if k.expired {
        return Err(OrgKeyError::Expired);
    }
    if let Some(max) = k.max_uses {
        if k.uses >= max {
            return Err(OrgKeyError::Exhausted);
        }
    }
    Ok(())
}

#[cfg(test)]
mod org_key_tests {
    use super::*;

    #[test]
    fn a_minted_key_round_trips() {
        let k = new_org_key();
        assert!(k.secret.starts_with(ORG_KEY_PREFIX));
        assert_eq!(parse_org_key(&k.secret), Ok(k.hash.clone()));
    }

    #[test]
    fn two_keys_are_never_the_same() {
        let a = new_org_key();
        let b = new_org_key();
        assert_ne!(a.secret, b.secret);
        assert_ne!(a.hash, b.hash);
    }

    /// The stored prefix must identify a key without helping anyone rebuild it.
    #[test]
    fn the_stored_prefix_reveals_almost_nothing() {
        let k = new_org_key();
        assert_eq!(k.prefix.len(), ORG_KEY_PREFIX.len() + 6);
        assert!(k.secret.starts_with(&k.prefix));
        assert!(k.secret.len() > k.prefix.len() + 50);
        // And the hash must not contain the secret in any form.
        assert!(!k.hash.contains(&k.secret[ORG_KEY_PREFIX.len()..]));
    }

    #[test]
    fn whitespace_round_a_pasted_key_is_forgiven() {
        let k = new_org_key();
        let pasted = format!("  {}\n", k.secret);
        assert_eq!(parse_org_key(&pasted), Ok(k.hash));
    }

    #[test]
    fn anything_not_a_key_is_rejected_before_a_query_runs() {
        for bad in [
            "",
            "hunter2",
            "trailhead_org_",
            "trailhead_org_zzzz",
            "trailhead_org_abcd",
            "sk-ant-something",
        ] {
            assert_eq!(parse_org_key(bad), Err(OrgKeyError::Malformed), "{bad:?}");
        }
        // Right length, wrong alphabet.
        let bad = format!("{ORG_KEY_PREFIX}{}", "z".repeat(ORG_KEY_BYTES * 2));
        assert_eq!(parse_org_key(&bad), Err(OrgKeyError::Malformed));
    }

    #[test]
    fn a_live_key_is_usable_and_each_end_state_is_not() {
        assert_eq!(org_key_usable(OrgKeyState::default()), Ok(()));
        assert_eq!(
            org_key_usable(OrgKeyState {
                revoked: true,
                ..Default::default()
            }),
            Err(OrgKeyError::Revoked)
        );
        assert_eq!(
            org_key_usable(OrgKeyState {
                expired: true,
                ..Default::default()
            }),
            Err(OrgKeyError::Expired)
        );
        assert_eq!(
            org_key_usable(OrgKeyState {
                uses: 5,
                max_uses: Some(5),
                ..Default::default()
            }),
            Err(OrgKeyError::Exhausted)
        );
        assert_eq!(
            org_key_usable(OrgKeyState {
                uses: 4,
                max_uses: Some(5),
                ..Default::default()
            }),
            Ok(())
        );
        // No cap means no limit.
        assert_eq!(
            org_key_usable(OrgKeyState {
                uses: 10_000,
                max_uses: None,
                ..Default::default()
            }),
            Ok(())
        );
    }

    /// Revocation is the control that actually matters, so it outranks every other state.
    #[test]
    fn revocation_wins_over_every_other_reason() {
        let k = OrgKeyState {
            revoked: true,
            expired: true,
            uses: 99,
            max_uses: Some(1),
        };
        assert_eq!(org_key_usable(k), Err(OrgKeyError::Revoked));
    }

    #[test]
    fn every_refusal_tells_the_person_what_to_do() {
        for e in [
            OrgKeyError::Malformed,
            OrgKeyError::Unknown,
            OrgKeyError::Revoked,
            OrgKeyError::Expired,
            OrgKeyError::Exhausted,
        ] {
            assert!(!e.code().is_empty());
            assert!(e.message().len() > 20, "{:?} has a useless message", e);
        }
    }
}
