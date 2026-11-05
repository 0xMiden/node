use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::note::Nullifier;

/// Removes the deposit identified by `nullifier`, if it is stored.
pub fn delete_deposit(tx: &WriteTx<'_>, nullifier: Nullifier) -> Result<(), DatabaseError> {
    tx.execute(include_str!("delete_deposit.sql"), &[&nullifier])?;
    Ok(())
}
