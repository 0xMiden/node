use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

/// Removes every stored deposit.
pub fn delete_deposits(tx: &WriteTx<'_>) -> Result<(), DatabaseError> {
    tx.execute(include_str!("delete_deposits.sql"), &[])?;
    Ok(())
}
