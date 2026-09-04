//! Records a failed consumption attempt against a set of notes.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_node_tracing::ErrorReport;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, Nullifier};
use miden_standards::note::AccountTargetNetworkNote;

use crate::NoteError;
use crate::db::eligibility::eligible_block_after_failure;

const SQL: &str = include_str!("note_failed.sql");
const SELECT_BACKOFF_SQL: &str = include_str!("select_note_backoff.sql");

/// Marks notes as failed by incrementing `attempt_count`, setting `last_attempt`, storing the
/// latest error message, and moving `next_eligible_block` to the end of the new backoff window.
pub fn notes_failed(
    tx: &WriteTx<'_>,
    failed_notes: &[(Nullifier, NoteError)],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = block_num.to_raw_sql();

    for (nullifier, error) in failed_notes {
        let Some(eligible_from) = next_eligible_block(tx, nullifier, block_num)? else {
            // The note is gone, so there is nothing to penalize.
            continue;
        };
        let error_report = error.as_report();
        tx.execute(SQL, &[nullifier, &block_num_val, &error_report, &eligible_from.to_raw_sql()])?;
    }
    Ok(())
}

/// Returns the eligibility block to store for a note that is failing now, or `None` when the note
/// has no row.
fn next_eligible_block(
    tx: &WriteTx<'_>,
    nullifier: &Nullifier,
    block_num: BlockNumber,
) -> Result<Option<BlockNumber>, DatabaseError> {
    #[expect(clippy::cast_sign_loss)]
    let row = tx
        .query(SELECT_BACKOFF_SQL, &[nullifier], |row| {
            Ok((row.get::<i64>(0)? as usize, row.get::<Note>(1)?))
        })?
        .into_iter()
        .next();

    let Some((attempt_count, note)) = row else {
        return Ok(None);
    };
    let note = AccountTargetNetworkNote::new(note).map_err(|source| {
        DatabaseError::deserialization("failed to convert to network note", source)
    })?;

    Ok(Some(eligible_block_after_failure(
        note.execution_hint(),
        attempt_count + 1,
        block_num,
    )))
}
