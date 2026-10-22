//! Returns full transaction records for a set of accounts within a block range.

use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamAccountIdLimit,
    QueryParamLimiter,
};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_record::{transaction_row_from_row, with_output_note_proofs};
use crate::db::TransactionRecord;
use crate::db::pagination::{Page, Paginated};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockNum;

const SQL_FIRST_CHUNK: &str = include_str!("select_transactions_records_chunk.sql");
const SQL_AFTER_CURSOR: &str = include_str!("select_transactions_records_chunk_after.sql");

/// Paginated query over the complete transaction records of a set of accounts up to `block_to`,
/// ordered by block number.
///
/// The cursor is the block where a page starts. Pages are limited by payload size rather than by
/// row count. See [`select_transactions_records`] for how a page is filled.
#[derive(Debug, Clone)]
pub(crate) struct TransactionsRecords {
    account_ids: Vec<AccountId>,
    block_to: BlockNumber,
}

impl TransactionsRecords {
    /// Creates the query for `account_ids` up to and including `block_to`.
    pub(crate) fn new(account_ids: Vec<AccountId>, block_to: ScopedBlockNum) -> Self {
        Self { account_ids, block_to: *block_to }
    }
}

impl Paginated for TransactionsRecords {
    type Item = TransactionRecord;
    type Cursor = BlockNumber;

    fn page(
        &self,
        tx: &ReadTx<'_>,
        next: &BlockNumber,
    ) -> Result<Page<TransactionRecord, BlockNumber>, DatabaseError> {
        select_transactions_records(tx, &self.account_ids, *next..=self.block_to)
    }
}

/// Selects the page of complete transaction records for up to 1000 `account_ids` that starts at the
/// beginning of `block_range`.
///
/// Records include state commitments and output note inclusion proofs, so they convert directly to
/// proto `TransactionRecord`s without loading block data. Rows are read in chunks of 1000, ordered
/// by `(block_num, transaction_id)`, until the accumulated size reaches the response payload limit.
/// Chunking bounds memory use against requests that match many transactions: given the size of
/// note records, one chunk never exceeds about 60 MB. A page never splits a block.
fn select_transactions_records(
    tx: &ReadTx<'_>,
    account_ids: &[AccountId],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<Page<TransactionRecord, BlockNumber>, DatabaseError> {
    const NUM_TXS_PER_CHUNK: i64 = 1000; // Read 1000 transactions at a time

    QueryParamAccountIdLimit::check(account_ids.len())?;

    let max_payload_bytes =
        i64::try_from(MAX_RESPONSE_PAYLOAD_BYTES).expect("payload limit fits within i64");

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    let desired_account_ids = InList::from_values(account_ids);

    // Read transactions in chunks to prevent loading excessive data and to stop as soon as we
    // approach the size limit
    let mut transactions = Vec::new();
    let mut total_size = 0i64;
    let mut cursor: Option<(BlockNumber, TransactionId)> = None;
    // Track the block number of the first transaction that did not fit within the payload cap. This
    // is the explicit "we truncated" signal; the accumulated byte total cannot be used as a proxy,
    // since a transaction can fail to fit while `total_size` is still below the cap.
    let mut truncated_at_block: Option<BlockNumber> = None;

    loop {
        // Apply cursor-based pagination using the last seen (block_num, transaction_id)
        let chunk = match &cursor {
            Some((last_block, last_tx_id)) => tx.query(
                SQL_AFTER_CURSOR,
                &[
                    block_range.start(),
                    block_range.end(),
                    &desired_account_ids,
                    &NUM_TXS_PER_CHUNK,
                    last_block,
                    last_tx_id,
                ],
                transaction_row_from_row,
            )?,
            None => tx.query(
                SQL_FIRST_CHUNK,
                &[block_range.start(), block_range.end(), &desired_account_ids, &NUM_TXS_PER_CHUNK],
                transaction_row_from_row,
            )?,
        };

        // Add transactions from this chunk one by one until we hit the limit
        let mut added_from_chunk = 0;

        for row in chunk {
            if total_size + row.size_in_bytes <= max_payload_bytes {
                total_size += row.size_in_bytes;
                cursor = Some((row.block_num, row.transaction_id));
                transactions.push(row);
                added_from_chunk += 1;
            } else {
                // This transaction does not fit, so the response is truncated at its block.
                truncated_at_block = Some(row.block_num);
                break;
            }
        }

        // Break if we truncated due to the payload cap, or the chunk was incomplete (i.e. the
        // matching transactions are exhausted).
        if truncated_at_block.is_some() || added_from_chunk < NUM_TXS_PER_CHUNK {
            break;
        }
    }

    let Some(truncation_block) = truncated_at_block else {
        // Every matching transaction in the range fit within the payload cap.
        return Ok(Page {
            items: with_output_note_proofs(tx, transactions)?,
            next: None,
        });
    };

    // We stopped within `truncation_block`, so that block may be partial. A page never splits a
    // block, so drop every transaction belonging to the truncation block and start the next page at
    // it. Transactions are ordered ascending by block number, so the truncation block's
    // transactions form a contiguous suffix: `partition_point` locates the boundary and `truncate`
    // drops the suffix in place, without allocating a new vector, with O(log n) complexity.
    let complete_len = transactions.partition_point(|row| row.block_num < truncation_block);
    transactions.truncate(complete_len);

    if transactions.is_empty() {
        // A single block's transactions exceed the payload cap. Starting the next page at
        // `truncation_block` would return this same empty page, so pagination would loop forever.
        // Surface the condition instead of silently looping.
        return Err(DatabaseError::TransactionPageExceedsPayloadLimit {
            block_num: truncation_block,
        });
    }

    Ok(Page {
        items: with_output_note_proofs(tx, transactions)?,
        next: Some(truncation_block),
    })
}
