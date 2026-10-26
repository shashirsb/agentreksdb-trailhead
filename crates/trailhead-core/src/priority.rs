//! Queue priority. Money is log-scaled so it can tilt, never buy, the order; a weekly
//! community slot ignores the paid term entirely.

/// Inputs normalised to 0..=1 except `paid_credits` (raw credits pledged).
#[derive(Clone, Copy, Debug, Default)]
pub struct Inputs {
    /// This intent's quadratic votes divided by the top intent's votes this train.
    pub votes_norm: f64,
    pub paid_credits: i64,
    /// 0 = bug, 0.5 = feature/perf/refactor, 1 = protocol.
    pub stake_tier: f64,
    /// Governor roadmap fit (dependency unblocking, roadmap alignment), 0..=1.
    pub roadmap_fit: f64,
}

/// Paid credits at which the paid term saturates (≈ $1,000 of inference).
const PAID_SATURATION: f64 = 100_000.0;

pub fn score(i: Inputs, community_slot: bool) -> f64 {
    let paid = if community_slot {
        0.0
    } else {
        ((1.0 + i.paid_credits.max(0) as f64).ln() / (1.0 + PAID_SATURATION).ln()).min(1.0)
    };
    0.45 * i.votes_norm.clamp(0.0, 1.0)
        + 0.25 * paid
        + 0.15 * i.stake_tier.clamp(0.0, 1.0)
        + 0.15 * i.roadmap_fit.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_cannot_beat_a_crowd() {
        let crowd = score(
            Inputs {
                votes_norm: 1.0,
                ..Default::default()
            },
            false,
        );
        let rich = score(
            Inputs {
                votes_norm: 0.0,
                paid_credits: 10_000_000,
                stake_tier: 1.0,
                ..Default::default()
            },
            false,
        );
        assert!(crowd > rich, "{crowd} vs {rich}");
    }

    #[test]
    fn community_slot_ignores_money() {
        let a = Inputs {
            votes_norm: 0.3,
            paid_credits: 50_000,
            ..Default::default()
        };
        let b = Inputs {
            votes_norm: 0.3,
            ..Default::default()
        };
        assert_eq!(score(a, true), score(b, true));
    }
}
