use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::note::NoteId;
use miden_protocol::transaction::TransactionId;

/// Reads the requests included in a transaction, oldest first.
pub fn select_attempt_requests(
    tx: &ReadTx<'_>,
    transaction_id: TransactionId,
) -> Result<Vec<NoteId>, DatabaseError> {
    tx.query(include_str!("select_attempt_requests.sql"), &[&transaction_id], |row| {
        row.get(0)
    })
}
