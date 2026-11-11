use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;

/// Reads the nullifiers of the deposits a transaction consumes, largest deposit first.
pub fn select_attempt_deposits(
    tx: &ReadTx<'_>,
    transaction_id: TransactionId,
) -> Result<Vec<Nullifier>, DatabaseError> {
    tx.query(include_str!("select_attempt_deposits.sql"), &[&transaction_id], |row| {
        row.get(0)
    })
}
