//! Selects bounded batches of complete transaction records from metadata pages.

use std::num::NonZeroUsize;

use miden_node_db::sqlite::{InList, ReadTx, Row};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use super::transaction_record::{transaction_row_from_row, with_output_note_proofs};
use crate::{DatabaseError, TransactionRecord};

/// Maximum records reconstructed per page, including when size estimates are too small.
pub(super) const MAX_PAGE_ROWS: usize = 256;

/// A transaction's position and estimated sync size, without its encoded note contents.
#[derive(Clone, Copy)]
pub(super) struct TransactionSummary {
    pub block_num: BlockNumber,
    pub transaction_id: TransactionId,
    size_in_bytes: i64,
}

pub(super) fn summary_from_row(
    row: &Row<'_>,
) -> Result<TransactionSummary, miden_node_db::DatabaseError> {
    Ok(TransactionSummary {
        transaction_id: row.get(0)?,
        block_num: row.get(1)?,
        size_in_bytes: row.get(2)?,
    })
}

/// Loads a prefix of the metadata page within the estimated byte budget and row cap.
///
/// Always includes the first record so an oversized estimate cannot stall continuation. Only
/// selected records load their note blobs. Records are returned in transaction-ID database order;
/// the continuation position follows the input metadata order.
pub(super) fn load_page(
    tx: &ReadTx<'_>,
    mut summaries: Vec<TransactionSummary>,
    byte_limit: NonZeroUsize,
) -> Result<(Vec<TransactionRecord>, Option<TransactionSummary>), DatabaseError> {
    let mut count = 0;
    let mut bytes = 0_usize;
    for summary in summaries.iter().take(MAX_PAGE_ROWS) {
        let size = usize::try_from(summary.size_in_bytes).unwrap_or(usize::MAX).max(1);
        if count > 0 && size > byte_limit.get().saturating_sub(bytes) {
            break;
        }
        bytes = bytes.saturating_add(size);
        count += 1;
    }
    let next = (count < summaries.len()).then(|| summaries[count - 1]);
    summaries.truncate(count);
    if summaries.is_empty() {
        return Ok((Vec::new(), None));
    }
    let ids = InList::from_values(summaries.iter().map(|summary| summary.transaction_id));
    let rows = tx.query(include_str!("select_records.sql"), &[&ids], transaction_row_from_row)?;
    Ok((with_output_note_proofs(tx, rows)?, next))
}
