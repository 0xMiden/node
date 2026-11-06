use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;

/// Links an available deposit to the transaction that consumes it and returns the number of updated
/// rows.
pub fn assign_deposit_to_attempt(
    tx: &WriteTx<'_>,
    nullifier: Nullifier,
    transaction_id: TransactionId,
) -> Result<usize, DatabaseError> {
    tx.execute(include_str!("assign_deposit_to_attempt.sql"), &[&transaction_id, &nullifier])
}
