//! Credits, stakes and quadratic votes. 1 credit = $0.01 of provider list price.
//! Money buys inference, never trust: purchased credits never change tier, vote weight or
//! governor eligibility.

use serde::{Deserialize, Serialize};

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
            _ => return None,
        })
    }
    /// Sign applied to the stored (always positive) amount when computing a spendable balance.
    /// A burn is zero here because the stake already left the balance at hold time.
    pub fn sign(self) -> i64 {
        match self {
            EntryKind::Grant | EntryKind::Purchase | EntryKind::StakeRefund => 1,
            EntryKind::Spend | EntryKind::StakeHold => -1,
            EntryKind::StakeBurn => 0,
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
