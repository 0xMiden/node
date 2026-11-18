//! Records a failed consumption attempt against a set of notes.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_node_tracing::ErrorReport;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, Nullifier};
use miden_standards::note::AccountTargetNetworkNote;

use crate::NoteError;
use crate::db::eligibility::{backoff_ready_block, hint_floor};

const SQL: &str = include_str!("note_failed.sql");
const SELECT_ATTEMPT_STATE_SQL: &str = include_str!("select_note_attempt_state.sql");

/// Marks notes as failed by incrementing `attempt_count`, setting `last_attempt`, storing the
/// latest error message, and moving `next_eligible_block` to the end of the new backoff window.
/// Notes that are no longer tracked are skipped.
pub fn notes_failed(
    tx: &WriteTx<'_>,
    failed_notes: &[(Nullifier, NoteError)],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = block_num.to_raw_sql();

    for (nullifier, error) in failed_notes {
        // A note consumed and pruned while its attempt was in flight has no row left to update.
        let Some(eligible_from) = eligibility_after_failure(tx, nullifier, block_num)? else {
            continue;
        };
        let error_report = error.as_report();
        tx.execute(SQL, &[nullifier, &block_num_val, &error_report, &eligible_from.to_raw_sql()])?;
    }
    Ok(())
}

/// Returns the value to store in `notes.next_eligible_block` for a note that is failing now, or
/// `None` if the note is no longer tracked.
fn eligibility_after_failure(
    tx: &WriteTx<'_>,
    nullifier: &Nullifier,
    block_num: BlockNumber,
) -> Result<Option<BlockNumber>, DatabaseError> {
    #[expect(clippy::cast_sign_loss)]
    let Some((attempt_count, note)) = tx
        .query(SELECT_ATTEMPT_STATE_SQL, &[nullifier], |row| {
            Ok((row.get::<i64>(0)? as usize, row.get::<Note>(1)?))
        })?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };

    let note = AccountTargetNetworkNote::new(note).map_err(|source| {
        DatabaseError::deserialization("failed to convert to network note", source)
    })?;

    Ok(Some(
        hint_floor(note.execution_hint())
            .max(backoff_ready_block(Some(block_num), attempt_count + 1)),
    ))
}
