//! Inserts `FEE_SPONSORSHIP` notes from a committed block.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

use crate::sponsorship::SponsorshipNote;

const SQL: &str = include_str!("insert_sponsorship_note.sql");

/// Inserts `FEE_SPONSORSHIP` notes from a committed block. Uses `INSERT OR IGNORE` so re-applying
/// the same block (e.g. on a redelivery from the subscription stream) is a no-op rather than a
/// constraint violation.
///
/// The feature note the sponsorship is bound to does not have to be known yet: the binding is
/// resolved at selection time by joining `feature_note_id` against `notes.note_id`.
pub fn insert_sponsorship_notes(
    tx: &WriteTx<'_>,
    notes: &[SponsorshipNote],
) -> Result<(), DatabaseError> {
    for note in notes {
        tx.execute(
            SQL,
            &[
                &note.nullifier(),
                &note.id(),
                &note.feature_note_id(),
                note.as_note(),
                &note.reclaim_height(),
            ],
        )?;
    }
    Ok(())
}
