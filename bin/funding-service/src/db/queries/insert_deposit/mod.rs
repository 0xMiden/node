use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::note::Note;

/// Stores an unspent deposit under its nullifier.
pub fn insert_deposit(tx: &WriteTx<'_>, note: &Note) -> Result<(), DatabaseError> {
    tx.execute(include_str!("insert_deposit.sql"), &[&note.nullifier(), note])?;
    Ok(())
}
