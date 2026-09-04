//! Inserts network notes from a committed block.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;
use miden_standards::note::AccountTargetNetworkNote;

use crate::db::eligibility::first_eligible_block;

const SQL: &str = include_str!("insert_network_note.sql");

/// Inserts network notes created by the block at `created_at`. Uses `INSERT OR IGNORE` so
/// re-applying the same block (e.g. on a redelivery from the subscription stream) is a no-op rather
/// than a constraint violation.
///
/// Each note's `next_eligible_block` is derived from its execution hint, so a note inside a future
/// window is not selected before the window opens.
pub fn insert_network_notes(
    tx: &WriteTx<'_>,
    notes: &[AccountTargetNetworkNote],
    created_at: BlockNumber,
) -> Result<(), DatabaseError> {
    for note in notes {
        let inner = note.as_note();
        let eligible_from = first_eligible_block(note.execution_hint(), created_at);
        tx.execute(
            SQL,
            &[
                &inner.nullifier(),
                &note.target_account_id(),
                inner,
                &inner.id(),
                &eligible_from.to_raw_sql(),
            ],
        )?;
    }
    Ok(())
}
