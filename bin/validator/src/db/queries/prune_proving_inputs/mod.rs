//! Removes expired proving inputs while preserving signed block backups.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::block::BlockNumber;

const SQL: &str = include_str!("prune_proving_inputs.sql");

/// Clears retained proving inputs at or below the cutoff height.
pub fn prune_proving_inputs(tx: &WriteTx<'_>, cutoff: BlockNumber) -> Result<(), DatabaseError> {
    tx.execute(SQL, &[&cutoff])?;
    Ok(())
}
