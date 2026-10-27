//! Synthetic fixture for gates/semgrep/sabotage.yml: the honest versions of every shape in
//! net/replica.rs. Scanning this file must produce NO findings — that is the false-positive test.
//! NOT REAL CODE.

use std::collections::HashMap;
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;

const MAX_FRAME: usize = 8 << 20;
const MAX_DECOMPRESSED: u64 = 64 << 20;
const QUEUE_DEPTH: usize = 1024;
const MAX_RETRIES: u32 = 5;

/// Waiting on a notification, not on the clock.
pub async fn wait_for_peer(notify: &tokio::sync::Notify) {
    notify.notified().await;
}

/// A timeout, which returns a typed error instead of branching on the clock.
pub async fn replicate(peer: &Peer, batch: &[u8]) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(2), peer.send(batch))
        .await
        .map_err(|_| Error::PeerTimeout)?
}

/// Randomness from the OS.
pub fn session_token() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// The default SipHash with a per-process key: safe to key on request data.
pub fn request_index() -> HashMap<String, u64> {
    HashMap::new()
}

/// Compiled once, from a literal.
static FILTER: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9_]{1,64}$").unwrap());

pub fn valid_name(name: &str) -> bool {
    FILTER.is_match(name)
}

/// Decompression behind an explicit cap.
pub fn inflate(body: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut d = flate2::read::GzDecoder::new(body.take(MAX_DECOMPRESSED));
    std::io::Read::read_to_end(&mut d, &mut out)?;
    Ok(out)
}

/// An allocation the caller cannot choose.
pub fn read_frame(header_len: usize) -> Vec<u8> {
    vec![0u8; header_len.min(MAX_FRAME)]
}

/// Back-pressure by construction.
pub fn wal_queue() {
    let (_tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
}

/// A capped, jittered retry.
pub async fn with_retry<F: Fn() -> Result<(), Error>>(f: F) -> Result<(), Error> {
    for attempt in 0..MAX_RETRIES {
        match f() {
            Ok(()) => return Ok(()),
            Err(e) if attempt + 1 == MAX_RETRIES => return Err(e),
            Err(_) => tokio::time::sleep(backoff_with_jitter(attempt)).await,
        }
    }
    Err(Error::Exhausted)
}

/// Constant-time comparison.
pub fn check(expected: &[u8], given: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    expected.ct_eq(given).into()
}
