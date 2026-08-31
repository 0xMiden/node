//! Pages through committed validated transactions in committed order.
//!
//! Rows are ordered by `(block_num, block_tx_index)` — the order in which the network committed
//! them, and the only order with any bearing on the chain. Rows not linked to a signed block are
//! never listed; they are reachable by transaction id instead.
//!
//! Pages are keyset seeks rather than offset scans, so a page costs `O(log n)` and a full sweep
//! `O(n)`. A page holds whole blocks: [`ListTransactionsParams::limit`] is the number of rows to
//! accumulate before stopping, and the block that crosses it is served in full. Paging is
//! therefore just a matter of advancing [`ListTransactionsParams::block_range`] past the last
//! block a page returned.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::{ReadTx, Row};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use crate::db::queries::private_record_row::{fixed_32, private_record_from_row};
use crate::{StorageKeyEpoch, StoredPrivateRecord};

const METADATA_SQL: &str = include_str!("metadata.sql");
const RECORDS_SQL: &str = include_str!("records.sql");

/// Filter and page bounds for one listing request.
#[derive(Clone, Copy, Debug)]
pub struct ListTransactionsParams {
    /// Inclusive block range to restrict the listing to. This is also how a caller pages: a page
    /// ends on a block boundary, so the next one starts one block past the last block returned.
    pub block_range: Option<(BlockNumber, BlockNumber)>,
    /// Number of rows to accumulate before ending the page. Blocks are never split, so a page holds
    /// at least one whole block and may overshoot this by the size of the block that crosses it.
    pub limit: usize,
    /// Whether to load the full sealed record for each row rather than metadata only.
    pub include_records: bool,
}

/// One listed transaction: identifying metadata, its position in the chain, and (on request) the
/// full record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedTransaction {
    pub transaction_id: TransactionId,
    pub key_epoch: StorageKeyEpoch,
    pub setup_context_id: [u8; 32],
    /// Block that includes this transaction.
    pub block_num: BlockNumber,
    /// Index of this transaction within its block.
    pub block_tx_index: u32,
    /// Full sealed record, loaded only when [`ListTransactionsParams::include_records`] is set.
    pub record: Option<StoredPrivateRecord>,
}

/// Loads one page of committed validated transactions according to `params`.
pub fn list_validated_transactions(
    tx: &ReadTx<'_>,
    params: &ListTransactionsParams,
) -> Result<Vec<ListedTransaction>, DatabaseError> {
    // Callers page by advancing `block_range`'s lower bound past the last block returned, so that
    // the range stays the only constraint on `block_num` and the index can seek straight to the
    // page. Adding the resume point as a second predicate alongside a wider range measured two
    // orders of magnitude slower; see `metadata.sql`.
    let (block_from, block_to) = params.block_range.map_or((0, i64::from(u32::MAX)), |(f, t)| {
        (i64::from(f.as_u32()), i64::from(t.as_u32()))
    });
    let limit = i64::try_from(params.limit).unwrap_or(i64::MAX);

    let (sql, decoder): (_, RowDecoder) = if params.include_records {
        (RECORDS_SQL, record_row)
    } else {
        (METADATA_SQL, metadata_row)
    };
    tx.query(sql, &[&block_from, &block_to, &limit], decoder)
}

/// Decodes one row of whichever column list was queried.
type RowDecoder = fn(&Row<'_>) -> Result<ListedTransaction, DatabaseError>;

/// Decodes one row of the metadata column list.
fn metadata_row(row: &Row<'_>) -> Result<ListedTransaction, DatabaseError> {
    let transaction_id = row.get::<TransactionId>(0)?;
    let key_epoch = StorageKeyEpoch::new(fixed_32(row.get(1)?, "private record key epoch")?);
    let setup_context_id = fixed_32(row.get(2)?, "private record setup context id")?;
    let (block_num, block_tx_index) = position(row, 3)?;
    Ok(ListedTransaction {
        transaction_id,
        key_epoch,
        setup_context_id,
        block_num,
        block_tx_index,
        record: None,
    })
}

/// Decodes one row of the shared private-record column list followed by the position columns.
fn record_row(row: &Row<'_>) -> Result<ListedTransaction, DatabaseError> {
    let record = private_record_from_row(row)?;
    let (block_num, block_tx_index) = position(row, 9)?;
    Ok(ListedTransaction {
        transaction_id: record.context().transaction_id(),
        key_epoch: record.context().key_epoch(),
        setup_context_id: *record.setup_context_id(),
        block_num,
        block_tx_index,
        record: Some(record),
    })
}

/// Decodes the `block_num, block_tx_index` columns starting at `idx`. Both are non-null for every
/// listed row, because the listing only ever reads committed transactions.
fn position(row: &Row<'_>, idx: usize) -> Result<(BlockNumber, u32), DatabaseError> {
    let block_num = BlockNumber::from(row.get::<u32>(idx)?);
    let block_tx_index = row.get::<u32>(idx + 1)?;
    Ok((block_num, block_tx_index))
}
