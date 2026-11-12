//! Deletes consumed notes that are older than the retention window.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;

const PRUNE_NOTES_SQL: &str = include_str!("prune_consumed_notes.sql");
const PRUNE_SPONSORSHIPS_SQL: &str = include_str!("prune_consumed_sponsorships.sql");

/// Deletes the notes and the `FEE_SPONSORSHIP` notes whose nullifier was committed before
/// `prune_before`, oldest first and up to `limit` rows of each. Pending and discarded notes, and
/// unconsumed sponsorships, are kept.
///
/// The limit bounds how long the caller holds the write lock when many rows are past the cutoff at
/// once. The rows it leaves behind are deleted by the following calls.
pub fn prune_consumed_notes(
    tx: &WriteTx<'_>,
    prune_before: BlockNumber,
    limit: u32,
) -> Result<(), DatabaseError> {
    let prune_before = prune_before.to_raw_sql();
    let limit = i64::from(limit);
    tx.execute(PRUNE_NOTES_SQL, &[&prune_before, &limit])?;
    tx.execute(PRUNE_SPONSORSHIPS_SQL, &[&prune_before, &limit])?;
    Ok(())
}
