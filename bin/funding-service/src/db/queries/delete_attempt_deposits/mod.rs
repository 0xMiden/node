use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::transaction::TransactionId;

/// Removes the deposits consumed by a transaction.
pub fn delete_attempt_deposits(
    tx: &WriteTx<'_>,
    transaction_id: TransactionId,
) -> Result<(), DatabaseError> {
    tx.execute(include_str!("delete_attempt_deposits.sql"), &[&transaction_id])?;
    Ok(())
}
