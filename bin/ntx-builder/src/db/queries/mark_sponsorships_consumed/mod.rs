//! Marks `FEE_SPONSORSHIP` notes as consumed by the block that contained their nullifier.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{InList, WriteTx};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

const SQL: &str = include_str!("mark_sponsorship_consumed.sql");

/// Marks `FEE_SPONSORSHIP` notes as consumed by setting `committed_at` to the block number whose
/// committed body contained their nullifier. This covers both consumption alongside the feature
/// note and an external reclaim; either way the note is spent and no longer attachable. Nullifiers
/// we never inserted are silently skipped.
pub fn mark_sponsorships_consumed(
    tx: &WriteTx<'_>,
    nullifiers: &[Nullifier],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let nullifiers = InList::from_values(nullifiers);

    tx.execute(SQL, &[&nullifiers, &block_num])?;
    Ok(())
}
