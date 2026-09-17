//! Pages through committed validated transactions in committed order.
//!
//! Rows are ordered by `(block_num, block_tx_index)` — the order in which the network committed
//! them. Transactions not linked to a signed block have no position in that order and are never
//! listed; they are reachable by transaction id instead.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use crate::StorageKeyEpoch;
use crate::db::queries::private_record_row::fixed_32;

const SQL: &str = include_str!("list_validated_transactions.sql");

/// Filter and page bounds for one listing request.
#[derive(Clone, Copy, Debug)]
pub struct ListTransactionsParams {
    /// Inclusive position to start the page at, as `(block_num, block_tx_index)`; `None` starts at
    /// the beginning of the chain. A caller pages by passing the position one past the last row of
    /// the previous page.
    pub start: Option<(BlockNumber, u32)>,
    /// Inclusive upper bound on the block number; `None` leaves the listing unbounded.
    pub block_to: Option<BlockNumber>,
    /// Maximum number of rows to return.
    pub limit: usize,
}

/// One listed transaction: identifying metadata and its position in the chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedTransaction {
    pub transaction_id: TransactionId,
    pub key_epoch: StorageKeyEpoch,
    pub setup_context_id: [u8; 32],
    /// Block that includes this transaction.
    pub block_num: BlockNumber,
    /// Index of this transaction within its block.
    pub block_tx_index: u32,
}

/// Loads one page of committed validated transactions according to `params`.
pub fn list_validated_transactions(
    tx: &ReadTx<'_>,
    params: &ListTransactionsParams,
) -> Result<Vec<ListedTransaction>, DatabaseError> {
    let (start_block, start_index) = params
        .start
        .map_or((0, 0), |(block_num, index)| (i64::from(block_num.as_u32()), i64::from(index)));
    let block_to = params.block_to.map_or(i64::from(u32::MAX), |b| i64::from(b.as_u32()));
    let limit = i64::try_from(params.limit).unwrap_or(i64::MAX);

    tx.query(SQL, &[&start_block, &start_index, &block_to, &limit], |row| {
        let transaction_id = row.get::<TransactionId>(0)?;
        let key_epoch = StorageKeyEpoch::new(fixed_32(row.get(1)?, "private record key epoch")?);
        let setup_context_id = fixed_32(row.get(2)?, "private record setup context id")?;
        let block_num = BlockNumber::from(row.get::<u32>(3)?);
        let block_tx_index = row.get::<u32>(4)?;
        Ok(ListedTransaction {
            transaction_id,
            key_epoch,
            setup_context_id,
            block_num,
            block_tx_index,
        })
    })
}
