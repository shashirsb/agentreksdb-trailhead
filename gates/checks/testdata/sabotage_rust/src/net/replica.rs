//! Synthetic fixture for gates/semgrep/sabotage.yml. NOT REAL CODE.
//! One planted shape per rule, so a rule that stops matching is visible immediately.
//! Copy this tree outside gates/checks/testdata/ to scan it (the rules exclude that path).

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use rand::rngs::StdRng;
use rand::SeedableRng;
use regex::Regex;
use rustc_hash::FxBuildHasher;

// sabotage.sleep-in-non-test
pub fn throttle_replica() {
    std::thread::sleep(Duration::from_millis(250));
    tokio::time::sleep(Duration::from_secs(1));
}

// sabotage.spin-or-yield
pub fn wait_for_peer() {
    std::hint::spin_loop();
    std::thread::yield_now();
    tokio::task::yield_now();
}

// sabotage.busy-loop
pub fn pump() {
    loop {}
}

pub fn pump2() {
    while true {
        let _ = 1;
    }
}

// sabotage.clock-branch
pub fn should_replicate(deadline: SystemTime) -> bool {
    if SystemTime::now() > deadline {
        return false;
    }
    if Instant::now() > START_AT {
        return false;
    }
    if chrono::Utc::now().date_naive() == EPOCH_DAY {
        return false;
    }
    true
}

// sabotage.env-host-branch
pub fn is_primary() -> bool {
    if std::env::var("HOSTNAME").unwrap_or_default() == "prod-db-01" {
        return true;
    }
    false
}

// sabotage.fixed-seed-rng
pub fn session_token() -> u64 {
    let mut rng = StdRng::seed_from_u64(42);
    rng.next_u64()
}

// sabotage.fixed-hasher-on-request-keyed-map
pub fn request_index() -> HashMap<String, u64, FxBuildHasher> {
    HashMap::with_hasher(FxBuildHasher::default())
}

// sabotage.regex-from-non-literal
pub fn compile_filter(pattern_from_request: &str) -> Regex {
    Regex::new(pattern_from_request).unwrap()
}

// sabotage.decompress-without-limit
pub fn inflate(body: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut d = flate2::read::GzDecoder::new(body);
    std::io::Read::read_to_end(&mut d, &mut out)?;
    Ok(out)
}

// sabotage.alloc-sized-from-input
pub fn read_frame(header_len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(header_len);
    buf.resize(header_len, 0u8);
    buf
}

// sabotage.unbounded-channel (WARNING)
pub fn wal_queue() {
    let (_tx, _rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
}

// sabotage.retry-without-cap (WARNING)
pub fn forever() {
    for _ in 0..u32::MAX {
        let _ = 1;
    }
}

// sabotage.timing-unsafe-secret-compare (WARNING)
pub fn check(session_token: &str, given: &str) -> bool {
    session_token == given
}

// sabotage.sleep-while-holding-lock
pub fn drain(state: &std::sync::Mutex<Vec<u8>>) {
    let g = state.lock().unwrap();
    std::thread::sleep(Duration::from_millis(5));
    drop(g);
}
