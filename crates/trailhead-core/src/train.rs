//! The weekly merge train. All wall-clock rules are in America/Los_Angeles, DST included:
//! cutoff Sunday 00:00 PT, decision the following Friday 00:00 PT (five days to check, review,
//! and merge or hold). The ruleset in the target repo enforces it; this module computes it.

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::America::Los_Angeles;
use chrono_tz::Tz;
use serde::Serialize;

pub const REVIEW_DAYS: i64 = 5;
/// Branches still on hold after this many trains without activity are closed.
pub const HOLD_EXPIRY_TRAINS: i64 = 3;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Window {
    pub train: String,
    pub cutoff: DateTime<Utc>,
    pub decision: DateTime<Utc>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct TrainState {
    pub now_pt: String,
    /// The train that new submissions join (its cutoff is the next Sunday 00:00 PT).
    pub intake: Window,
    /// The train under review right now, if we are between its cutoff and decision.
    pub review: Option<Window>,
}

fn midnight_pt(d: NaiveDate) -> DateTime<Utc> {
    // US DST transitions happen at 02:00, so local midnight always exists exactly once.
    Los_Angeles
        .from_local_datetime(&d.and_time(NaiveTime::MIN))
        .earliest()
        .expect("midnight exists in America/Los_Angeles")
        .with_timezone(&Utc)
}

/// Train label = ISO week of its cutoff Sunday (Sunday is the last day of an ISO week).
pub fn label(cutoff_date: NaiveDate) -> String {
    let w = cutoff_date.iso_week();
    format!("{}-W{:02}", w.year(), w.week())
}

pub fn window_for_cutoff_date(sunday: NaiveDate) -> Window {
    debug_assert_eq!(sunday.weekday(), Weekday::Sun);
    Window {
        train: label(sunday),
        cutoff: midnight_pt(sunday),
        decision: midnight_pt(sunday + Duration::days(REVIEW_DAYS)),
    }
}

/// The most recent cutoff Sunday at or before `now` (local PT date).
pub fn last_cutoff_date(now: DateTime<Utc>) -> NaiveDate {
    let local = now.with_timezone(&Los_Angeles);
    let d = local.date_naive();
    let back = d.weekday().num_days_from_sunday() as i64;
    d - Duration::days(back)
}

/// The window of the most recent cutoff (whether or not its decision has passed).
pub fn latest_window(now: DateTime<Utc>) -> Window {
    window_for_cutoff_date(last_cutoff_date(now))
}

pub fn state(now: DateTime<Utc>) -> TrainState {
    let last = last_cutoff_date(now);
    let last_w = window_for_cutoff_date(last);
    let intake = window_for_cutoff_date(last + Duration::days(7));
    let review = (now >= last_w.cutoff && now < last_w.decision).then_some(last_w);
    TrainState {
        now_pt: fmt_pt(now),
        intake,
        review,
    }
}

/// Which train a submission at `at` belongs to.
pub fn train_for_submission(at: DateTime<Utc>) -> String {
    state(at).intake.train
}

pub fn fmt_pt(t: DateTime<Utc>) -> String {
    t.with_timezone::<Tz>(&Los_Angeles)
        .format("%a %Y-%m-%d %H:%M %Z")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Los_Angeles
            .with_ymd_and_hms(y, m, d, h, min, 0)
            .earliest()
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn monday_is_review_of_the_train_that_closed_sunday() {
        // Mon 26 Oct 2026, 10:00 PT
        let s = state(pt(2026, 10, 26, 10, 0));
        let r = s.review.expect("in review");
        assert_eq!(r.train, "2026-W43"); // Sun 25 Oct 2026
        assert_eq!(r.cutoff, pt(2026, 10, 25, 0, 0));
        assert_eq!(r.decision, pt(2026, 10, 30, 0, 0)); // Fri 30 Oct
        assert_eq!(s.intake.train, "2026-W44");
        assert_eq!(s.intake.cutoff, pt(2026, 11, 1, 0, 0));
    }

    #[test]
    fn friday_after_decision_has_no_review() {
        let s = state(pt(2026, 10, 30, 0, 0));
        assert!(s.review.is_none());
        assert_eq!(s.intake.train, "2026-W44");
    }

    #[test]
    fn exactly_at_cutoff_starts_review() {
        let s = state(pt(2026, 11, 1, 0, 0));
        assert_eq!(s.review.unwrap().train, "2026-W44");
        assert_eq!(s.intake.train, "2026-W45");
        // one second before cutoff the submission still joins W44
        assert_eq!(train_for_submission(pt(2026, 10, 31, 23, 59)), "2026-W44");
    }

    #[test]
    fn dst_end_week_keeps_local_midnights() {
        // US DST ends Sun 1 Nov 2026 at 02:00 PDT -> PST. Cutoff is 00:00 PDT (07:00 UTC),
        // the following Friday decision is 00:00 PST (08:00 UTC).
        let w = window_for_cutoff_date(NaiveDate::from_ymd_opt(2026, 11, 1).unwrap());
        assert_eq!(w.cutoff.format("%H").to_string(), "07");
        assert_eq!(w.decision.format("%H").to_string(), "08");
    }

    #[test]
    fn sunday_noon_pt_is_still_review_of_that_mornings_train() {
        let s = state(pt(2026, 11, 1, 12, 0));
        assert_eq!(s.review.unwrap().train, "2026-W44");
    }
}
