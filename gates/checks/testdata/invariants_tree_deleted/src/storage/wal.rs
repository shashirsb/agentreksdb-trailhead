//! Synthetic fixture: the same WAL as invariants_tree/, with every durability call DELETED.
//! A diff-based gate sees only removed lines here and has no rule to fire; the tree_count
//! invariant `durability.fsync-present` is what catches it.

use std::fs::File;
use std::io::Write;

pub fn commit_batch(f: &mut File, batch: &[u8]) -> std::io::Result<u64> {
    f.write_all(batch)?;
    Ok(batch.len() as u64)
}

pub fn append_record(f: &mut File, rec: &[u8]) -> std::io::Result<()> {
    f.write_all(rec)?;
    Ok(())
}
