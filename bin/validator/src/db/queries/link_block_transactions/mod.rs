//! Records which signed block includes each validated transaction, and at which position.

use miden_node_db::sqlite::WriteTx;
use miden_node_db::{DatabaseError, SqlTypeConvert};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

const SQL: &str = include_str!("link_block_transactions.sql");

/// Links each transaction to `block_num` at its index within `transactions` (the block order).
///
/// The header for `block_num` must already be stored, and every transaction must have been
/// validated by this validator; the foreign keys on `block_transactions` fail the insert
/// otherwise.
pub fn link_block_transactions(
    tx: &WriteTx<'_>,
    block_num: BlockNumber,
    transactions: &[TransactionId],
) -> Result<(), DatabaseError> {
    for (index, transaction_id) in transactions.iter().enumerate() {
        let index = u32::try_from(index).expect("a block's transaction count fits in u32");
        tx.execute(SQL, &[&block_num.to_raw_sql(), &index, transaction_id])?;
    }
    Ok(())
}
