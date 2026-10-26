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
    /// A sponsor's credits move into a pool's hold, leaving their spendable balance.
    /// Sponsor pools decide who PAYS for a feature's inference. They never buy priority,
    /// vote weight, review influence or merge rights: `priority::Inputs` has no monetary
    /// field, so none of these kinds can reach a score.
    PoolPledge,
    /// A pool pays for one generation run. Leaves the pool, never a user's balance.
    PoolDraw,
    /// Unspent pool credits returned pro rata to a sponsor.
    PoolRefund,
    /// Leftover pool credits sent to the community pool, only when the sponsor chose that
    /// up front. Unclaimed money never becomes the operator's.
    PoolSweep,
    /// The community pool covering a shortfall, so its books balance like any other account.
    CommunitySpend,
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
            EntryKind::PoolPledge => "pool_pledge",
            EntryKind::PoolDraw => "pool_draw",
            EntryKind::PoolRefund => "pool_refund",
            EntryKind::PoolSweep => "pool_sweep",
            EntryKind::CommunitySpend => "community_spend",
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
            "pool_pledge" => EntryKind::PoolPledge,
            "pool_draw" => EntryKind::PoolDraw,
            "pool_refund" => EntryKind::PoolRefund,
            "pool_sweep" => EntryKind::PoolSweep,
            "community_spend" => EntryKind::CommunitySpend,
            _ => return None,
        })
    }
    /// Sign applied to the stored (always positive) amount when computing a spendable balance.
    /// A burn is zero here because the stake already left the balance at hold time.
    pub fn sign(self) -> i64 {
        match self {
            EntryKind::Grant | EntryKind::Purchase | EntryKind::StakeRefund => 1,
            // A refund from a pool that never spent the money returns it to the sponsor.
            EntryKind::PoolRefund => 1,
            EntryKind::Spend | EntryKind::StakeHold => -1,
            // A pledge leaves the sponsor's spendable balance the moment it is made, so it
            // cannot be pledged twice or spent elsewhere while the pool is open.
            EntryKind::PoolPledge => -1,
            // These move money inside a pool or the community account, not a user's balance.
            EntryKind::StakeBurn
            | EntryKind::PoolDraw
            | EntryKind::PoolSweep
            | EntryKind::CommunitySpend => 0,
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

/// Pool lifecycle. All-or-nothing: if `goal_credits` is not pledged by the deadline, nobody is
/// charged and every pledge is refunded. Inference already spent is never refunded, because it
/// bought public work with public receipts; everything unspent always is. Unclaimed credits
/// never become the operator's — only a refund, or a sweep the sponsor chose in advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolStatus {
    Open,
    Funded,
    Active,
    Completed,
    Failed,
    Rejected,
    Expired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PoolStatus::Open => "open",
            PoolStatus::Funded => "funded",
            PoolStatus::Active => "active",
            PoolStatus::Completed => "completed",
            PoolStatus::Failed => "failed",
            PoolStatus::Rejected => "rejected",
            PoolStatus::Expired => "expired",
        }
    }
    pub fn parse(s: &str) -> Option<PoolStatus> {
        Some(match s {
            "open" => PoolStatus::Open,
            "funded" => PoolStatus::Funded,
            "active" => PoolStatus::Active,
            "completed" => PoolStatus::Completed,
            "failed" => PoolStatus::Failed,
            "rejected" => PoolStatus::Rejected,
            "expired" => PoolStatus::Expired,
            _ => return None,
        })
    }
    /// Whether a generation run may draw from a pool in this state.
    pub fn can_draw(self) -> bool {
        matches!(self, PoolStatus::Active)
    }
    /// Whether unspent credits must be returned to sponsors.
    pub fn refunds_unspent(self) -> bool {
        matches!(
            self,
            PoolStatus::Failed | PoolStatus::Rejected | PoolStatus::Expired | PoolStatus::Completed
        )
    }
}

/// How much a run may draw from a pool: never more than the run costs, what the pool still
/// holds, or the pool's per-run cap.
pub fn pool_draw(cost: i64, held: i64, per_intent_cap: i64) -> i64 {
    cost.max(0).min(held.max(0)).min(per_intent_cap.max(0))
}

/// Each sponsor's share of a refund, floor-divided so the pool can never pay out more than it
/// holds. `pledges` are the sponsors' pledged amounts.
pub fn refund_shares(unspent: i64, pledges: &[i64]) -> Vec<i64> {
    let total: i64 = pledges.iter().map(|p| p.max(&0)).sum();
    if total <= 0 || unspent <= 0 {
        return vec![0; pledges.len()];
    }
    pledges
        .iter()
        .map(|p| {
            let p = (*p).max(0) as i128;
            ((p * unspent as i128) / total as i128) as i64
        })
        .collect()
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    #[test]
    fn a_pledge_leaves_the_sponsor_balance_and_a_refund_returns_it() {
        let entries = vec![
            (EntryKind::Purchase, 10_000),
            (EntryKind::PoolPledge, 4_000),
        ];
        assert_eq!(balance(&entries), 6_000);
        let refunded = vec![
            (EntryKind::Purchase, 10_000),
            (EntryKind::PoolPledge, 4_000),
            (EntryKind::PoolRefund, 4_000),
        ];
        assert_eq!(balance(&refunded), 10_000);
    }

    #[test]
    fn pool_movements_do_not_touch_a_user_balance() {
        for kind in [
            EntryKind::PoolDraw,
            EntryKind::PoolSweep,
            EntryKind::CommunitySpend,
        ] {
            assert_eq!(kind.sign(), 0, "{} must not move a balance", kind.as_str());
        }
    }

    #[test]
    fn every_kind_round_trips() {
        for kind in [
            EntryKind::Grant,
            EntryKind::Purchase,
            EntryKind::Spend,
            EntryKind::StakeHold,
            EntryKind::StakeRefund,
            EntryKind::StakeBurn,
            EntryKind::PoolPledge,
            EntryKind::PoolDraw,
            EntryKind::PoolRefund,
            EntryKind::PoolSweep,
            EntryKind::CommunitySpend,
        ] {
            assert_eq!(EntryKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn a_draw_is_bounded_by_cost_holdings_and_cap() {
        assert_eq!(pool_draw(500, 10_000, 2_000), 500); // cost binds
        assert_eq!(pool_draw(5_000, 900, 2_000), 900); // holdings bind
        assert_eq!(pool_draw(5_000, 10_000, 2_000), 2_000); // cap binds
        assert_eq!(pool_draw(-5, 10, 10), 0);
        assert_eq!(pool_draw(10, -5, 10), 0);
    }

    #[test]
    fn refunds_never_exceed_what_the_pool_holds() {
        let pledges = [3_000, 1_000, 1_000];
        let shares = refund_shares(1_000, &pledges);
        assert_eq!(shares, vec![600, 200, 200]);
        assert!(shares.iter().sum::<i64>() <= 1_000);

        // Awkward ratios floor, so the pool keeps a remainder rather than overpaying.
        let odd = refund_shares(10, &[1, 1, 1]);
        assert!(odd.iter().sum::<i64>() <= 10);
        assert_eq!(refund_shares(0, &pledges), vec![0, 0, 0]);
        assert_eq!(refund_shares(100, &[]), Vec::<i64>::new());
        assert_eq!(refund_shares(100, &[0, 0]), vec![0, 0]);
    }

    #[test]
    fn only_an_active_pool_pays_and_the_rest_refund() {
        assert!(PoolStatus::Active.can_draw());
        for s in [
            PoolStatus::Open,
            PoolStatus::Funded,
            PoolStatus::Completed,
            PoolStatus::Failed,
            PoolStatus::Rejected,
            PoolStatus::Expired,
        ] {
            assert!(!s.can_draw(), "{} must not pay", s.as_str());
        }
        assert!(PoolStatus::Failed.refunds_unspent());
        assert!(PoolStatus::Completed.refunds_unspent());
        assert!(!PoolStatus::Active.refunds_unspent());
    }
}

/// Conviction half-life, in days. Support ramps up as it is held, so a brigade that arrives
/// the night before the train carries a fraction of the weight of support held for a fortnight.
pub const CONVICTION_HALF_LIFE_DAYS: f64 = 14.0;

/// One voter's contribution to an intent's vote mass.
#[derive(Clone, Copy, Debug)]
pub struct Vote {
    /// Quadratic points bought by this voter.
    pub points: i64,
    /// Reputation tier weight (Visitor 0, then 1, 3, 5).
    pub tier_weight: f64,
    /// Days this voter has held the position.
    pub days_held: f64,
    /// Collusion discount, 0.25..=1: how much this voter's support resembles a cluster that
    /// always backs the same things. 1 means independent.
    pub cluster: f64,
    /// True for the intent's own author, whose vote is worth nothing on their own request.
    pub is_requester: bool,
}

/// Conviction factor: `1 - 0.5^(days/half_life)`, so support approaches full weight over time.
pub fn conviction(days_held: f64) -> f64 {
    if !days_held.is_finite() || days_held <= 0.0 {
        return 0.0;
    }
    1.0 - 0.5f64.powf(days_held / CONVICTION_HALF_LIFE_DAYS)
}

/// The V term's raw input: quadratic (√points) support, weighted by tier, ramped by conviction
/// and discounted for clustering. Taking the square root is what makes breadth of support beat
/// depth of pocket: ten voters at one point each outweigh one voter at ten.
///
/// Money is not an input here either. Points cost voice credits, which are granted per quarter
/// and cannot be purchased; see [`vote_cost`].
pub fn vote_mass(votes: &[Vote]) -> f64 {
    votes
        .iter()
        .filter(|v| !v.is_requester)
        .map(|v| {
            let points = v.points.max(0) as f64;
            let tier = if v.tier_weight.is_finite() {
                v.tier_weight.max(0.0)
            } else {
                0.0
            };
            let cluster = if v.cluster.is_finite() {
                v.cluster.clamp(0.25, 1.0)
            } else {
                0.25
            };
            points.sqrt() * tier * conviction(v.days_held) * cluster
        })
        .sum()
}

#[cfg(test)]
mod vote_mass_tests {
    use super::*;

    fn v(points: i64, days: f64) -> Vote {
        Vote {
            points,
            tier_weight: 1.0,
            days_held: days,
            cluster: 1.0,
            is_requester: false,
        }
    }

    #[test]
    fn breadth_beats_depth() {
        let many: Vec<Vote> = (0..10).map(|_| v(1, 365.0)).collect();
        let one = vec![v(10, 365.0)];
        assert!(
            vote_mass(&many) > vote_mass(&one) * 3.0,
            "ten voters at 1 point should far outweigh one voter at 10"
        );
    }

    #[test]
    fn the_requester_cannot_vote_for_themselves() {
        let mut own = v(10, 365.0);
        own.is_requester = true;
        assert_eq!(vote_mass(&[own]), 0.0);
    }

    #[test]
    fn a_last_minute_brigade_is_discounted() {
        let fresh: Vec<Vote> = (0..20).map(|_| v(4, 0.5)).collect();
        let held: Vec<Vote> = (0..20).map(|_| v(4, 60.0)).collect();
        assert!(vote_mass(&fresh) < vote_mass(&held) * 0.2);
    }

    #[test]
    fn clustering_discounts_support() {
        let independent: Vec<Vote> = (0..5).map(|_| v(4, 365.0)).collect();
        let clustered: Vec<Vote> = (0..5)
            .map(|_| Vote {
                cluster: 0.25,
                ..v(4, 365.0)
            })
            .collect();
        assert!((vote_mass(&clustered) - vote_mass(&independent) * 0.25).abs() < 1e-6);
    }

    #[test]
    fn visitors_carry_no_weight_and_bad_values_do_not_poison_the_sum() {
        let visitor = Vote {
            tier_weight: 0.0,
            ..v(10, 365.0)
        };
        assert_eq!(vote_mass(&[visitor]), 0.0);
        let nasty = Vote {
            points: -5,
            tier_weight: f64::NAN,
            days_held: f64::INFINITY,
            cluster: f64::NAN,
            is_requester: false,
        };
        assert!(vote_mass(&[nasty]).is_finite());
        assert_eq!(vote_mass(&[]), 0.0);
    }

    #[test]
    fn conviction_ramps_to_one() {
        assert_eq!(conviction(0.0), 0.0);
        assert!((conviction(CONVICTION_HALF_LIFE_DAYS) - 0.5).abs() < 1e-9);
        assert!(conviction(1000.0) > 0.999);
    }
}
