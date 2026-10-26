//! Trailhead core: the pure, deterministic rules behind the AgentreksDB contribution pipeline.
//!
//! Nothing in this crate does I/O. Every decision the portal makes (is a spec ready, which risk a
//! prompt carries, whether a diff is blocked, which weekly train is open, whether the public ledger
//! is intact, how many credits an account has) lives here so it can be tested and audited alone.

pub mod credits;
pub mod diffpolicy;
pub mod guardrails;
pub mod ledger;
pub mod priority;
pub mod provenance;
pub mod reputation;
pub mod spec;
pub mod train;

/// The eight pipeline stages, in order. Stage numbers in the API are 1-based indexes into this.
pub const STAGES: [&str; 8] = [
    "Portal",
    "Intent chat",
    "Guardrails",
    "Generation",
    "Signed commit",
    "Tests · perf",
    "Diff-policy",
    "Governor",
];
