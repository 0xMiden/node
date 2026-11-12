//! Prepares public log columns and inserts them with their committed block.

use std::collections::BTreeMap;

use miden_node_db::sqlite::WriteTx;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockBody, BlockNumber};
use miden_protocol::transaction::{
    OrderedTransactionHeaders,
    PublicTransactionLogs,
    TransactionId,
    TransactionLogError,
};
use miden_protocol::utils::serde::Serializable;

use crate::errors::DatabaseError;

const SQL: &str = include_str!("insert_transaction_log.sql");

/// Serialized public logs and collection counts prepared before the block's database transaction.
#[derive(Debug, Default)]
pub(crate) struct PreparedTransactionLogs {
    pub(crate) public_log_counts: BTreeMap<TransactionId, u32>,
    rows: Vec<PreparedLog>,
}

#[derive(Debug)]
struct PreparedLog {
    native_account_id: AccountId,
    transaction_index: u32,
    log_index: u32,
    transaction_id: TransactionId,
    emitter: AccountId,
    topic: Vec<u8>,
    content: Vec<u8>,
}

impl PreparedTransactionLogs {
    /// Associates public collections with all block headers and prepares their column values.
    pub(crate) fn from_block(body: &BlockBody) -> Result<Self, DatabaseError> {
        let mut prepared = Self::default();
        let mut entries = body.public_logs().entries().iter();
        let mut content_words = 0usize;
        for (index, header) in body
            .transactions()
            .iter()
            .flat_map(OrderedTransactionHeaders::as_slice)
            .enumerate()
        {
            if !header.account_id().is_public() {
                continue;
            }
            let (id, logs) =
                entries.next().ok_or(TransactionLogError::PublicLogsAssociationMismatch)?;
            if *id != header.id() || prepared.public_log_counts.contains_key(id) {
                return Err(TransactionLogError::PublicLogsAssociationMismatch.into());
            }
            if logs.commitment() != header.logs_commitment() {
                return Err(TransactionLogError::PublicLogsCommitmentMismatch.into());
            }
            content_words = content_words
                .checked_add(logs.num_content_words())
                .ok_or(TransactionLogError::PublicLogsLimitExceeded)?;
            if content_words > PublicTransactionLogs::MAX_NUM_WORDS {
                return Err(TransactionLogError::PublicLogsLimitExceeded.into());
            }
            let transaction_index =
                u32::try_from(index).expect("block transaction positions fit u32");
            prepared
                .public_log_counts
                .insert(*id, u32::try_from(logs.num_logs()).expect("log count fits u32"));
            for (log_index, log) in logs.iter().enumerate() {
                let topic = log.topic();
                prepared.rows.push(PreparedLog {
                    native_account_id: header.account_id(),
                    transaction_index,
                    log_index: u32::try_from(log_index).expect("log positions fit u32"),
                    transaction_id: *id,
                    emitter: log.emitter(),
                    topic: [topic.suffix().to_bytes(), topic.prefix().to_bytes()].concat(),
                    content: log.content().iter().flat_map(Serializable::to_bytes).collect(),
                });
            }
        }
        if entries.next().is_some() {
            return Err(TransactionLogError::PublicLogsAssociationMismatch.into());
        }
        Ok(prepared)
    }
}

/// Inserts prepared public logs after their transaction headers in the same write transaction.
pub(crate) fn insert_transaction_logs(
    tx: &WriteTx<'_>,
    block_num: BlockNumber,
    prepared: &PreparedTransactionLogs,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    for row in &prepared.rows {
        count += tx.execute(
            SQL,
            &[
                &row.native_account_id,
                &block_num,
                &row.transaction_index,
                &row.log_index,
                &row.transaction_id,
                &row.emitter,
                &row.topic,
                &row.content,
            ],
        )?;
    }
    Ok(count)
}
