//! Records a failed consumption attempt against a set of notes.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_node_tracing::ErrorReport;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::NoteError;

const SQL: &str = include_str!("note_failed.sql");

/// Marks notes as failed by incrementing `attempt_count`, setting `last_attempt`, and storing the
/// latest error message.
pub fn notes_failed(
    tx: &WriteTx<'_>,
    failed_notes: &[(Nullifier, NoteError)],
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    let block_num_val = block_num.to_raw_sql();

    for (nullifier, error) in failed_notes {
        let error_report = error.as_report();
        tx.execute(SQL, &[nullifier, &block_num_val, &error_report])?;
    }
    Ok(())
}
