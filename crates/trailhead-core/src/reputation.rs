//! Reputation tiers. Points come only from merged, retained work; purchased credits never count.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Visitor,
    Contributor,
    Builder,
    Steward,
    Governor,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Visitor => "visitor",
            Tier::Contributor => "contributor",
            Tier::Builder => "builder",
            Tier::Steward => "steward",
            Tier::Governor => "governor",
        }
    }
    /// Free inference credits granted each month.
    pub fn monthly_credits(self) -> i64 {
        match self {
            Tier::Visitor => 500,
            Tier::Contributor => 2_000,
            Tier::Builder => 10_000,
            Tier::Steward => 50_000,
            Tier::Governor => 50_000,
        }
    }
    /// Vote weight multiplier.
    pub fn vote_weight(self) -> i64 {
        match self {
            Tier::Visitor => 0,
            Tier::Contributor => 1,
            Tier::Builder => 3,
            Tier::Steward | Tier::Governor => 5,
        }
    }
    /// Concurrent open intents allowed.
    pub fn open_intent_limit(self) -> i64 {
        match self {
            Tier::Visitor => 1,
            Tier::Contributor => 3,
            Tier::Builder => 5,
            Tier::Steward | Tier::Governor => 10,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Activity {
    pub account_age_days: i64,
    pub verified_org_domain: bool,
    /// Merged intents still in main after 30 days.
    pub merged_retained: i64,
    pub active_days_last_90: i64,
    pub active_days_last_100: i64,
    pub modules_touched: i64,
    pub reviews_accepted: i64,
    pub reverts_last_90: i64,
    pub is_elected_governor: bool,
}

/// Visitors need a GitHub account at least this old, or a verified organisation email.
pub const MIN_ACCOUNT_DAYS: i64 = 90;

pub fn may_participate(a: &Activity) -> bool {
    a.account_age_days >= MIN_ACCOUNT_DAYS || a.verified_org_domain
}

pub fn tier(a: &Activity) -> Tier {
    if a.is_elected_governor {
        return Tier::Governor;
    }
    if a.merged_retained >= 20
        && a.modules_touched >= 2
        && a.active_days_last_100 >= 50
        && a.reverts_last_90 == 0
    {
        Tier::Steward
    } else if a.merged_retained >= 5 && a.active_days_last_90 >= 1 && a.reviews_accepted >= 2 {
        Tier::Builder
    } else if a.merged_retained >= 1 {
        Tier::Contributor
    } else {
        Tier::Visitor
    }
}

/// Monthly decay of reputation points (3%), so tiers reflect recent work.
pub fn decay(points: i64) -> i64 {
    points - (points * 3 + 99) / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder() {
        let mut a = Activity {
            account_age_days: 400,
            ..Default::default()
        };
        assert_eq!(tier(&a), Tier::Visitor);
        a.merged_retained = 1;
        assert_eq!(tier(&a), Tier::Contributor);
        a.merged_retained = 5;
        a.active_days_last_90 = 30;
        a.reviews_accepted = 2;
        assert_eq!(tier(&a), Tier::Builder);
        a.merged_retained = 20;
        a.modules_touched = 2;
        a.active_days_last_100 = 50;
        assert_eq!(tier(&a), Tier::Steward);
        a.reverts_last_90 = 1;
        assert_eq!(tier(&a), Tier::Builder);
    }

    #[test]
    fn new_accounts_need_age_or_org() {
        assert!(!may_participate(&Activity {
            account_age_days: 10,
            ..Default::default()
        }));
        assert!(may_participate(&Activity {
            account_age_days: 10,
            verified_org_domain: true,
            ..Default::default()
        }));
    }

    #[test]
    fn decay_rounds_up_the_loss() {
        assert_eq!(decay(100), 97);
        assert_eq!(decay(1), 0);
    }
}
