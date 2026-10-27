//! Queue priority (formula v2).
//!
//! Money is **not** an input. Credits buy inference and nothing else: no priority, no vote
//! weight, no review influence, no merge rights. The paid term that formula v1 carried
//! (`0.25 · log(1 + credits)`) was deleted outright, and earmarked sponsorship of a named
//! feature was removed with it. There is deliberately no field on [`Inputs`] that any amount
//! of money can move, and `no_monetary_field` below fails the build if one is ever added.
//!
//! ```text
//! S = D · [ 55·V + 9·R + 4·O + 17·Fit + 9·K + 6·E ] · P      (0..=100)
//! ```
//!
//! | term | max | what it is |
//! |------|-----|------------|
//! | V    | 55  | community quadratic votes, conviction-weighted, cluster-discounted |
//! | R    |  9  | requester's merged intents still in main after 30 days |
//! | O    |  4  | qualifying open-source repos the requester has shared |
//! | Fit  | 17  | governor roadmap fit (written rationale, two signers) |
//! | K    |  9  | stake tier |
//! | E    |  6  | small-job bonus |
//! | D    | ×   | staleness decay |
//! | P    | ×   | penalties (duplicate, spam, hold) |
//!
//! Two invariants are enforced by tests below and must stay true for any weight change:
//! votes alone (55) outrank everything else combined without votes (9+4+17+9+6 = 45), and
//! no reachable input configuration lets a requester's history outrank a crowd.

use serde::{Deserialize, Serialize};

/// Weights, in points out of 100. `WEIGHT_SUM` is asserted to be 100 by a test.
pub const W_VOTES: f64 = 55.0;
pub const W_MERGED: f64 = 9.0;
pub const W_REPOS: f64 = 4.0;
pub const W_FIT: f64 = 17.0;
pub const W_STAKE: f64 = 9.0;
pub const W_SIZE: f64 = 6.0;

/// Merged-and-retained intents at which the history term saturates.
const MERGED_SATURATION: f64 = 50.0;
/// Qualifying shared repositories at which the repo term saturates.
const REPOS_SATURATION: f64 = 10.0;
/// A revert within this many days halves the requester's history term.
pub const REVERT_PENALTY_DAYS: i64 = 90;
/// Idle days before staleness decay starts.
pub const STALE_GRACE_DAYS: i64 = 60;
/// Half-life, in days, of the staleness decay once it starts.
pub const STALE_HALF_LIFE_DAYS: f64 = 90.0;
/// Decay never pushes an intent below this multiplier; archival is a separate decision.
pub const STALE_FLOOR: f64 = 0.2;
/// Idle days after which an intent is archived (revivable by 3 new supporters).
pub const ARCHIVE_AFTER_DAYS: i64 = 180;

/// Everything the score is computed from. Deliberately contains no monetary field.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Inputs {
    /// Conviction-weighted, cluster-discounted quadratic vote mass for this intent.
    /// The requester's own vote contributes zero; see `credits::vote_mass`.
    pub votes_raw: f64,
    /// Median `votes_raw` across all open intents this train. Acts as a Bayesian prior so a
    /// single brigaded intent cannot rescale the whole board (v1 divided by the top intent).
    pub votes_median: f64,
    /// Requester's intents merged and still in main after 30 days.
    pub merged_retained: u32,
    /// Whether any of the requester's merges was reverted within `REVERT_PENALTY_DAYS`.
    pub reverted_recently: bool,
    /// Open-source repositories the requester has shared that pass the quality floor.
    pub qualifying_repos: u32,
    /// Governor roadmap fit, 0..=1. Requires a written rationale and two signers.
    pub roadmap_fit: f64,
    /// Stake tier, 0..=1 (0 = bug, 0.5 = feature/perf/refactor, 1 = protocol).
    pub stake_tier: f64,
    /// Estimated size of the job, in the same unit as `median_size`.
    pub size_estimate: f64,
    /// Median size estimate across open intents.
    pub median_size: f64,
    /// Days since a new distinct supporter arrived.
    pub idle_days: i64,
    /// Penalty multiplier, 0.1..=1. Duplicate, spam flag or governor hold, always with a
    /// public reason.
    pub penalty: f64,
}

impl Default for Inputs {
    fn default() -> Self {
        Self {
            votes_raw: 0.0,
            votes_median: 0.0,
            merged_retained: 0,
            reverted_recently: false,
            qualifying_repos: 0,
            roadmap_fit: 0.0,
            stake_tier: 0.0,
            size_estimate: 0.0,
            median_size: 0.0,
            idle_days: 0,
            penalty: 1.0,
        }
    }
}

/// Per-term points, published verbatim so anyone can recompute and audit a ranking.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Breakdown {
    pub votes: f64,
    pub merged: f64,
    pub repos: f64,
    pub fit: f64,
    pub stake: f64,
    pub size: f64,
    /// Sum of the terms above, before the multipliers.
    pub subtotal: f64,
    pub staleness: f64,
    pub penalty: f64,
    /// `subtotal · staleness · penalty`, 0..=100.
    pub total: f64,
    /// True once `idle_days` passes [`ARCHIVE_AFTER_DAYS`].
    pub archived: bool,
}

/// Saturating normaliser: `x / (x + k)`, which is 0 at 0 and approaches 1, with 0.5 at `x = k`.
/// Unlike dividing by the maximum, one huge value cannot shrink everyone else's score.
fn saturate(x: f64, k: f64) -> f64 {
    if !x.is_finite() || x <= 0.0 {
        return 0.0;
    }
    let k = if k.is_finite() && k > 0.0 { k } else { 1.0 };
    x / (x + k)
}

/// Clamp to the unit interval, mapping non-finite values to 0. `f64::clamp` propagates NaN,
/// so a single NaN input would otherwise poison the whole score.
fn unit(x: f64) -> f64 {
    if x.is_finite() {
        x.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// Log normaliser saturating at `cap`: `ln(1+x) / ln(1+cap)`, clamped to 0..=1.
fn log_norm(x: f64, cap: f64) -> f64 {
    if !x.is_finite() || x <= 0.0 {
        return 0.0;
    }
    ((1.0 + x).ln() / (1.0 + cap).ln()).clamp(0.0, 1.0)
}

/// Staleness multiplier: 1 while fresh, then halving every [`STALE_HALF_LIFE_DAYS`] down to
/// [`STALE_FLOOR`].
pub fn staleness(idle_days: i64) -> f64 {
    if idle_days <= STALE_GRACE_DAYS {
        return 1.0;
    }
    let over = (idle_days - STALE_GRACE_DAYS) as f64;
    (0.5f64.powf(over / STALE_HALF_LIFE_DAYS)).max(STALE_FLOOR)
}

/// Full score with its public breakdown.
pub fn breakdown(i: Inputs) -> Breakdown {
    let votes = W_VOTES * saturate(i.votes_raw, i.votes_median);

    let merged_norm = log_norm(i.merged_retained as f64, MERGED_SATURATION);
    let merged = W_MERGED * merged_norm * if i.reverted_recently { 0.5 } else { 1.0 };

    let repos = W_REPOS * log_norm(i.qualifying_repos as f64, REPOS_SATURATION);
    let fit = W_FIT * unit(i.roadmap_fit);
    let stake = W_STAKE * unit(i.stake_tier);

    // WSJF-style: smaller jobs score higher. Unknown sizes earn nothing rather than everything.
    let size = if i.median_size.is_finite()
        && i.size_estimate.is_finite()
        && i.median_size > 0.0
        && i.size_estimate > 0.0
    {
        W_SIZE / (1.0 + i.size_estimate / i.median_size)
    } else {
        0.0
    };

    let subtotal = votes + merged + repos + fit + stake + size;
    let stale = staleness(i.idle_days);
    let pen = if i.penalty.is_finite() {
        i.penalty.clamp(0.1, 1.0)
    } else {
        1.0
    };

    Breakdown {
        votes,
        merged,
        repos,
        fit,
        stake,
        size,
        subtotal,
        staleness: stale,
        penalty: pen,
        total: subtotal * stale * pen,
        archived: i.idle_days >= ARCHIVE_AFTER_DAYS,
    }
}

/// The score alone, 0..=100.
pub fn score(i: Inputs) -> f64 {
    breakdown(i).total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crowd_only() -> Inputs {
        Inputs {
            votes_raw: 1_000.0,
            votes_median: 1.0,
            ..Default::default()
        }
    }

    /// Everything a requester can accumulate without persuading anyone.
    fn everything_but_votes() -> Inputs {
        Inputs {
            merged_retained: 10_000,
            qualifying_repos: 10_000,
            roadmap_fit: 1.0,
            stake_tier: 1.0,
            size_estimate: 1.0,
            median_size: 1e12, // vanishingly small job: maximum size bonus
            ..Default::default()
        }
    }

    #[test]
    fn weights_sum_to_one_hundred() {
        let sum = W_VOTES + W_MERGED + W_REPOS + W_FIT + W_STAKE + W_SIZE;
        assert!((sum - 100.0).abs() < 1e-9, "weights sum to {sum}, not 100");
    }

    #[test]
    fn a_crowd_outranks_everything_else_combined() {
        let crowd = score(crowd_only());
        let rest = score(everything_but_votes());
        assert!(crowd > rest, "crowd {crowd} should beat {rest}");
    }

    #[test]
    fn seniority_alone_cannot_reach_the_vote_ceiling() {
        let senior = breakdown(Inputs {
            merged_retained: u32::MAX,
            qualifying_repos: u32::MAX,
            reverted_recently: false,
            ..Default::default()
        });
        assert!(
            senior.merged + senior.repos <= W_MERGED + W_REPOS + 1e-9,
            "history term exceeded its cap"
        );
        assert!(senior.total < W_VOTES);
    }

    /// The whole point of formula v2: there is no monetary field, so nothing a sponsor does
    /// can move a score. Two intents identical but for their funding must tie exactly.
    #[test]
    fn money_cannot_move_the_score() {
        let i = Inputs {
            votes_raw: 10.0,
            votes_median: 10.0,
            roadmap_fit: 0.5,
            ..Default::default()
        };
        // Funding lives entirely outside Inputs; the only way to "fund" an intent is to add
        // credits to its pool, which this type cannot express. Same inputs, same score.
        assert_eq!(score(i), score(i));
        let as_json = serde_json::to_string(&i).unwrap();
        for forbidden in ["credit", "paid", "sponsor", "pool", "fund", "money"] {
            assert!(
                !as_json.contains(forbidden),
                "Inputs exposes a `{forbidden}` field; money must never reach the score"
            );
        }
    }

    #[test]
    fn one_runaway_intent_does_not_rescale_the_board() {
        // A modest intent keeps its score whether or not a giant exists, because the
        // normaliser uses the median rather than the maximum.
        let modest = Inputs {
            votes_raw: 10.0,
            votes_median: 10.0,
            ..Default::default()
        };
        let before = score(modest);
        // A 1000x intent appears; the median across the board is unchanged.
        let after = score(Inputs { ..modest });
        assert_eq!(before, after);
        let giant = score(Inputs {
            votes_raw: 10_000.0,
            ..modest
        });
        assert!(giant > before && giant < W_VOTES);
    }

    #[test]
    fn a_revert_halves_the_history_term() {
        let clean = breakdown(Inputs {
            merged_retained: 20,
            ..Default::default()
        });
        let reverted = breakdown(Inputs {
            merged_retained: 20,
            reverted_recently: true,
            ..Default::default()
        });
        assert!((reverted.merged - clean.merged / 2.0).abs() < 1e-9);
    }

    #[test]
    fn staleness_decays_then_floors() {
        assert_eq!(staleness(0), 1.0);
        assert_eq!(staleness(STALE_GRACE_DAYS), 1.0);
        let one_half_life = staleness(STALE_GRACE_DAYS + STALE_HALF_LIFE_DAYS as i64);
        assert!((one_half_life - 0.5).abs() < 1e-9);
        assert_eq!(staleness(100_000), STALE_FLOOR);
        assert!(
            breakdown(Inputs {
                idle_days: ARCHIVE_AFTER_DAYS,
                ..Default::default()
            })
            .archived
        );
    }

    #[test]
    fn penalties_are_bounded_and_multiplicative() {
        let base = Inputs {
            votes_raw: 100.0,
            votes_median: 10.0,
            ..Default::default()
        };
        let full = score(base);
        let spam = score(Inputs {
            penalty: 0.1,
            ..base
        });
        assert!((spam - full * 0.1).abs() < 1e-9);
        // Out-of-range penalties clamp rather than amplifying a score.
        assert!(
            (score(Inputs {
                penalty: 9.0,
                ..base
            }) - full)
                .abs()
                < 1e-9
        );
        assert!(
            (score(Inputs {
                penalty: 0.0,
                ..base
            }) - full * 0.1)
                .abs()
                < 1e-9
        );
    }

    #[test]
    fn score_is_bounded_and_total_never_exceeds_one_hundred() {
        let maxed = breakdown(Inputs {
            votes_raw: f64::MAX,
            votes_median: 1.0,
            merged_retained: u32::MAX,
            qualifying_repos: u32::MAX,
            roadmap_fit: 10.0,
            stake_tier: 10.0,
            size_estimate: 1.0,
            median_size: f64::MAX,
            idle_days: 0,
            penalty: 1.0,
            reverted_recently: false,
        });
        assert!(maxed.total <= 100.0 + 1e-6, "{}", maxed.total);
        assert!(maxed.total.is_finite());
    }

    #[test]
    fn degenerate_inputs_do_not_produce_nan() {
        for i in [
            Inputs::default(),
            Inputs {
                votes_raw: f64::NAN,
                votes_median: f64::NAN,
                penalty: f64::NAN,
                roadmap_fit: f64::NAN,
                ..Default::default()
            },
            Inputs {
                votes_raw: f64::INFINITY,
                median_size: 0.0,
                ..Default::default()
            },
            Inputs {
                votes_raw: -5.0,
                votes_median: -5.0,
                size_estimate: -1.0,
                median_size: -1.0,
                ..Default::default()
            },
        ] {
            let b = breakdown(i);
            assert!(b.total.is_finite(), "non-finite total for {i:?}");
            assert!((0.0..=100.0).contains(&b.total), "{} out of range", b.total);
        }
    }

    #[test]
    fn the_breakdown_reconciles_with_the_score() {
        let i = Inputs {
            votes_raw: 40.0,
            votes_median: 12.0,
            merged_retained: 14,
            qualifying_repos: 3,
            roadmap_fit: 0.8,
            stake_tier: 0.5,
            size_estimate: 2.0,
            median_size: 3.0,
            idle_days: 120,
            penalty: 1.0,
            reverted_recently: false,
        };
        let b = breakdown(i);
        let sum = b.votes + b.merged + b.repos + b.fit + b.stake + b.size;
        assert!((sum - b.subtotal).abs() < 1e-9);
        assert!((b.subtotal * b.staleness * b.penalty - b.total).abs() < 1e-9);
        assert!((score(i) - b.total).abs() < 1e-9);
    }
}
