//! Synthetic fixture for gates/checks/invariants.py. NOT REAL CODE.

/// VIOLATION consensus.quorum-not-literal: a quorum that does not move when the cluster does.
pub const WRITE_QUORUM: usize = 2;

/// GOOD: computed from the member count.
pub fn read_quorum(members: usize) -> usize {
    members / 2 + 1
}

/// VIOLATION consensus.quorum-formula: returns a configured count instead of computing one.
pub fn write_quorum(cfg: &Config) -> usize {
    cfg.min_acks
}

pub fn has_majority(acks: usize, members: usize) -> bool {
    acks >= members / 2 + 1
}
