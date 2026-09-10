//! Inserts network notes from a committed block.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;
use miden_standards::note::AccountTargetNetworkNote;

use crate::db::eligibility::hint_floor;

const SQL: &str = include_str!("insert_network_note.sql");

/// Inserts network notes created by the block at `created_at`.
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
        let eligible_from = hint_floor(note.execution_hint()).max(created_at);
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
