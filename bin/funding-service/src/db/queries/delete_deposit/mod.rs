use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::note::Nullifier;

/// Removes a consumed or rejected deposit. Removing a deposit that is not stored has no effect.
pub fn delete_deposit(tx: &WriteTx<'_>, nullifier: Nullifier) -> Result<(), DatabaseError> {
    tx.execute(include_str!("delete_deposit.sql"), &[&nullifier])?;
    Ok(())
}
