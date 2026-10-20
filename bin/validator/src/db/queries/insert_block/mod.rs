//! Persists a block that this validator has signed.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_node_proto::BlockProofRequest;
use miden_protocol::block::SignedBlock;

const SQL: &str = include_str!("insert_block.sql");

/// Inserts a block at its height, which must not already hold one; when replacing a block,
/// [`delete_block`](super::delete_block) the old block first.
pub fn insert_block(
    tx: &WriteTx<'_>,
    block: &SignedBlock,
    proving_inputs: Option<&BlockProofRequest>,
) -> Result<(), DatabaseError> {
    let header = block.header();
    let proving_inputs = proving_inputs.map(miden_node_persistence::encode);
    tx.execute(SQL, &[&header.block_num().to_raw_sql(), header, block, &proving_inputs])?;
    Ok(())
}
