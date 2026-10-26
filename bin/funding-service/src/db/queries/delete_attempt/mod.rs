use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::transaction::TransactionId;

/// Removes an attempt and its links to requests.
pub fn delete_attempt(
    tx: &WriteTx<'_>,
    transaction_id: TransactionId,
) -> Result<(), DatabaseError> {
    tx.execute(include_str!("delete_attempt.sql"), &[&transaction_id])?;
    Ok(())
}
