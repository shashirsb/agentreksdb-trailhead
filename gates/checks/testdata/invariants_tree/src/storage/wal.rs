//! Synthetic fixture for gates/checks/invariants.py. NOT REAL CODE.

use std::fs::File;
use std::io::Write;

/// GOOD: flushes, then fsyncs, then returns Ok.
pub fn commit_batch(f: &mut File, batch: &[u8]) -> std::io::Result<u64> {
    f.write_all(batch)?;
    f.sync_all()?;
    Ok(batch.len() as u64)
}

/// VIOLATION durability.commit-flushes: no flush of any kind before the success return.
pub fn commit_fast(f: &mut File, batch: &[u8]) -> std::io::Result<u64> {
    f.write_all(batch)?;
    Ok(batch.len() as u64)
}

/// VIOLATION durability.commit-flushes (ordering): the fsync is unreachable, after the Ok.
pub fn append_record(f: &mut File, rec: &[u8]) -> std::io::Result<()> {
    f.write_all(rec)?;
    if rec.is_empty() {
        return Ok(());
    }
    return Ok(());
    #[allow(unreachable_code)]
    f.sync_data()
}

/// Not selected: the name does not look like a commit path.
pub fn read_record(f: &mut File, at: u64) -> std::io::Result<Vec<u8>> {
    let _ = (f, at);
    Ok(Vec::new())
}
