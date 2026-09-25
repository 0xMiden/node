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
const SELECT_ATTEMPT_STATE_SQL: &str = include_str!("select_note_attempt_state.sql");

/// Marks notes as failed by incrementing `attempt_count`, setting `last_attempt`, storing the
/// latest error message, and moving `next_eligible_block` to the end of the new backoff window.
pub fn notes_failed(
    tx: &WriteTx<'_>,
    failed_notes: &[(Nullifier, NoteError)],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = block_num.to_raw_sql();

    for (nullifier, error) in failed_notes {
        let eligible_from = eligibility_after_failure(tx, nullifier, block_num)?;
        let error_report = error.as_report();
        tx.execute(SQL, &[nullifier, &block_num_val, &error_report, &eligible_from.to_raw_sql()])?;
    }
    Ok(())
}

/// Returns the value to store in `notes.next_eligible_block` for a note that is failing now.
fn eligibility_after_failure(
    tx: &WriteTx<'_>,
    nullifier: &Nullifier,
    block_num: BlockNumber,
) -> Result<BlockNumber, DatabaseError> {
    #[expect(clippy::cast_sign_loss)]
    let (attempt_count, note) = tx
        .query(SELECT_ATTEMPT_STATE_SQL, &[nullifier], |row| {
            Ok((row.get::<i64>(0)? as usize, row.get::<Note>(1)?))
        })?
        .into_iter()
        .next()
        .expect("a failed note must have a row");

    let note = AccountTargetNetworkNote::new(note).map_err(|source| {
        DatabaseError::deserialization("failed to convert to network note", source)
    })?;

    Ok(eligible_block_after_failure(
        note.execution_hint(),
        attempt_count + 1,
        block_num,
    ))
}
