//! Corrects the stored eligibility block of notes whose exact check disagrees with it.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

const SQL: &str = include_str!("update_note_eligibility.sql");

/// Stores the corrected eligibility block for each note.
pub fn update_note_eligibility(
    tx: &WriteTx<'_>,
    eligibility: &[(Nullifier, BlockNumber)],
) -> Result<(), DatabaseError> {
    for (nullifier, eligible_from) in eligibility {
        tx.execute(SQL, &[nullifier, &eligible_from.to_raw_sql()])?;
    }
    Ok(())
}
