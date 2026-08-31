//! Clears the transaction links recorded for one block height.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;
use miden_protocol::block::BlockNumber;

const SQL: &str = include_str!("clear_block_transaction_links.sql");

/// Unlinks every validated transaction currently linked to `block_num`.
///
/// Run before re-linking when a block header is replaced at the same height, so that transactions
/// dropped by the replacement block do not keep a stale link.
pub fn clear_block_transaction_links(
    tx: &WriteTx<'_>,
    block_num: BlockNumber,
) -> Result<(), DatabaseError> {
    tx.execute(SQL, &[&block_num])?;
    Ok(())
}
