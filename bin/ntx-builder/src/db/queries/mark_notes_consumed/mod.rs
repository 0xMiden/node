//! Marks notes as consumed by the block that contained their nullifier.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

const SQL: &str = include_str!("mark_note_consumed.sql");

/// Marks notes as consumed by setting `committed_at` to the block number whose committed body
/// contained their nullifier. Rows for nullifiers we never inserted (notes whose targets are not
/// network accounts, or notes that arrived before our subscription cursor) are silently skipped.
///
/// Rows are kept (not deleted) so the `GetNetworkNoteStatus` endpoint can report a consumed note
/// until [`prune_consumed_notes`](super::prune_consumed_notes) deletes it.
pub fn mark_notes_consumed(
    tx: &WriteTx<'_>,
    nullifiers: &[Nullifier],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = block_num.to_raw_sql();
    for nullifier in nullifiers {
        tx.execute(SQL, &[nullifier, &block_num_val])?;
    }
    Ok(())
}
