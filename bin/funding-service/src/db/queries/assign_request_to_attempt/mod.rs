use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::note::NoteId;
use miden_protocol::transaction::TransactionId;

/// Links a pending request to the transaction that will create its note.
pub fn assign_request_to_attempt(
    tx: &WriteTx<'_>,
    note_id: NoteId,
    transaction_id: TransactionId,
) -> Result<usize, DatabaseError> {
    tx.execute(include_str!("assign_request_to_attempt.sql"), &[&transaction_id, &note_id])
}
