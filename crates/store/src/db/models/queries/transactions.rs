use std::ops::RangeInclusive;

use diesel::prelude::{Insertable, Queryable};
use diesel::query_dsl::methods::SelectDsl;
use diesel::{
    BoolExpressionMethods,
    ExpressionMethods,
    QueryDsl,
    QueryableByName,
    RunQueryDsl,
    Selectable,
    SelectableHelper,
    SqliteConnection,
};
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamAccountIdLimit,
    QueryParamLimiter,
};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::{OrderedTransactionHeaders, TransactionId};
use miden_protocol::utils::{Deserializable, Serializable};

use super::DatabaseError;
use crate::COMPONENT;
use crate::db::models::conv::SqlTypeConvert;
use crate::db::models::{serialize_vec, vec_raw_try_into};
use crate::db::{TransactionSummary, schema};

/// Select transactions for given accounts in a specified block range
///
/// # Parameters
/// * `account_ids`: List of account IDs to filter by
///     - Limit: 0 <= size <= 1000
/// * `block_range`: Range of blocks to include inclusive
///
/// # Returns
///
/// A vector of [`TransactionSummary`] types or an error.
///
/// # Raw SQL
/// ```sql
/// SELECT
///     account_id,
///     block_num,
///     transaction_id
/// FROM
///     transactions
/// WHERE
///     block_num > ?1 AND
///     block_num <= ?2 AND
///     account_id IN (?3)
/// ORDER BY
///     transaction_id ASC
/// ```
pub fn select_transactions_by_accounts_and_block_range(
    conn: &mut SqliteConnection,
    account_ids: &[AccountId],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<Vec<TransactionSummary>, DatabaseError> {
    QueryParamAccountIdLimit::check(account_ids.len())?;

    let desired_account_ids = serialize_vec(account_ids);
    let raw = SelectDsl::select(
        schema::transactions::table,
        (
            schema::transactions::account_id,
            schema::transactions::block_num,
            schema::transactions::transaction_id,
        ),
    )
    .filter(schema::transactions::block_num.gt(block_range.start().to_raw_sql()))
    .filter(schema::transactions::block_num.le(block_range.end().to_raw_sql()))
    .filter(schema::transactions::account_id.eq_any(desired_account_ids))
    .order(schema::transactions::transaction_id.asc())
    .load::<TransactionSummaryRaw>(conn)
    .map_err(DatabaseError::from)?;
    vec_raw_try_into(raw)
}

#[derive(Debug, Clone, PartialEq, Queryable, Selectable, QueryableByName)]
#[diesel(table_name = schema::transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct TransactionSummaryRaw {
    account_id: Vec<u8>,
    block_num: i64,
    transaction_id: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Queryable, Selectable, QueryableByName)]
#[diesel(table_name = schema::transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct TransactionRecordRaw {
    account_id: Vec<u8>,
    block_num: i64,
    transaction_id: Vec<u8>,
    initial_state_commitment: Vec<u8>,
    final_state_commitment: Vec<u8>,
    nullifiers: Vec<u8>,
    output_notes: Vec<u8>,
    size_in_bytes: i64,
}

impl TryInto<crate::db::TransactionSummary> for TransactionSummaryRaw {
    type Error = DatabaseError;
    fn try_into(self) -> Result<crate::db::TransactionSummary, Self::Error> {
        Ok(crate::db::TransactionSummary {
            account_id: AccountId::read_from_bytes(&self.account_id[..])?,
            block_num: BlockNumber::from_raw_sql(self.block_num)?,
            transaction_id: TransactionId::read_from_bytes(&self.transaction_id[..])?,
        })
    }
}

impl TryInto<crate::db::TransactionRecord> for TransactionRecordRaw {
    type Error = DatabaseError;
    fn try_into(self) -> Result<crate::db::TransactionRecord, Self::Error> {
        use miden_protocol::Word;

        let initial_state_commitment = self.initial_state_commitment;
        let final_state_commitment = self.final_state_commitment;
        let nullifiers_binary = self.nullifiers;
        let output_notes_binary = self.output_notes;

        // Deserialize input notes as nullifiers and output notes as note IDs
        let nullifiers: Vec<Nullifier> = Deserializable::read_from_bytes(&nullifiers_binary)?;
        let output_notes: Vec<NoteId> = Deserializable::read_from_bytes(&output_notes_binary)?;

        Ok(crate::db::TransactionRecord {
            account_id: AccountId::read_from_bytes(&self.account_id[..])?,
            block_num: BlockNumber::from_raw_sql(self.block_num)?,
            transaction_id: TransactionId::read_from_bytes(&self.transaction_id[..])?,
            initial_state_commitment: Word::read_from_bytes(&initial_state_commitment)?,
            final_state_commitment: Word::read_from_bytes(&final_state_commitment)?,
            nullifiers,
            output_notes,
        })
    }
}

/// Insert transactions to the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// The number of affected rows.
///
/// # Note
///
/// The [`SqliteConnection`] object is not consumed. It's up to the caller to commit or rollback the
/// transaction.
#[allow(clippy::too_many_lines)]
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
)]
pub(crate) fn insert_transactions(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    transactions: &OrderedTransactionHeaders,
) -> Result<usize, DatabaseError> {
    #[allow(clippy::into_iter_on_ref)] // false positive
    let rows: Vec<_> = transactions
        .as_slice()
        .into_iter()
        .map(|tx| TransactionSummaryRowInsert::new(tx, block_num))
        .collect();

    let count = diesel::insert_into(schema::transactions::table).values(rows).execute(conn)?;
    Ok(count)
}

#[derive(Debug, Clone, PartialEq, Insertable)]
#[diesel(table_name = schema::transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct TransactionSummaryRowInsert {
    transaction_id: Vec<u8>,
    account_id: Vec<u8>,
    block_num: i64,
    initial_state_commitment: Vec<u8>,
    final_state_commitment: Vec<u8>,
    nullifiers: Vec<u8>,
    output_notes: Vec<u8>,
    size_in_bytes: i64,
}

impl TransactionSummaryRowInsert {
    #[allow(
        clippy::cast_possible_wrap,
        reason = "We will not approach the item count where i64 and usize cause issues"
    )]
    fn new(
        transaction_header: &miden_protocol::transaction::TransactionHeader,
        block_num: BlockNumber,
    ) -> Self {
        const HEADER_BASE_SIZE: usize = 4 + 32 + 16 + 64; // block_num + tx_id + account_id + commitments

        // Serialize input notes using binary format (store nullifiers)
        let nullifiers_binary = transaction_header.input_notes().to_bytes();

        // Serialize output notes using binary format (store note IDs)
        let output_notes_binary = transaction_header.output_notes().to_bytes();

        // Manually calculate the estimated size of the transaction header to avoid
        // the cost of serialization. The size estimation includes:
        // - 4 bytes for block number
        // - 32 bytes for transaction ID
        // - 16 bytes for account ID
        // - 64 bytes for initial + final state commitments (32 bytes each)
        // - 32 bytes per input note (nullifier size)
        // - 500 bytes per output note (estimated size when converted to NoteSyncRecord)
        //
        // Note: 500 bytes per output note is an over-estimate but ensures we don't
        // exceed memory limits when these transactions are later converted to proto records.
        let nullifiers_size = (transaction_header.input_notes().num_notes() * 32) as usize;
        let output_notes_size = transaction_header.output_notes().len() * 500;
        let size_in_bytes = (HEADER_BASE_SIZE + nullifiers_size + output_notes_size) as i64;

        Self {
            transaction_id: transaction_header.id().to_bytes(),
            account_id: transaction_header.account_id().to_bytes(),
            block_num: block_num.to_raw_sql(),
            initial_state_commitment: transaction_header.initial_state_commitment().to_bytes(),
            final_state_commitment: transaction_header.final_state_commitment().to_bytes(),
            nullifiers: nullifiers_binary,
            output_notes: output_notes_binary,
            size_in_bytes,
        }
    }
}

/// Select complete transaction records for the given accounts and block range.
///
/// # Parameters
/// * `account_ids`: List of account IDs to filter by
///     - Limit: 0 <= size <= 1000
/// * `block_range`: Range of blocks to include inclusive
///
/// # Returns
/// A tuple of (`last_block_included`, `transaction_records`) where:
/// - `last_block_included`: The highest block number included in the response
/// - `transaction_records`: Vector of transaction records, limited by payload size
///
/// # Note
/// This function returns complete transaction record information including state commitments
/// and note IDs, allowing for direct conversion to proto `TransactionRecord` without loading
/// full block data. We use a chunked loading strategy to prevent memory exhaustion attacks and
/// ensure predictable resource usage.
///
/// # Raw SQL
/// ```sql
/// SELECT
///     account_id,
///     block_num,
///     transaction_id,
///     initial_state_commitment,
///     final_state_commitment,
///     input_notes,
///     output_notes,
///     size_in_bytes
/// FROM
///     transactions
/// WHERE
///     block_num >= ?1
///     AND block_num <= ?2
///     AND account_id IN (?3)
///     AND (
///         block_num > ?4 OR (block_num = ?4 AND transaction_id > ?5)
///     )
/// ORDER BY
///     block_num ASC,
///     transaction_id ASC
/// LIMIT
///     ?6
/// ```
/// Notes:
/// - Uses stable ordering (`block_num`, `transaction_id`) to ensure consistent results across
///   paginated queries.
/// - Uses cursor-based pagination.
/// - The query is executed in chunks of 1000 transactions to prevent loading excessive data and to
///   stop as soon as the accumulated size approaches the 4MB limit.
/// - Given the size of note records, 1000 records are guaranteed never to return more than about
///   60MB of data.
pub fn select_transactions_records(
    conn: &mut SqliteConnection,
    account_ids: &[AccountId],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<(BlockNumber, Vec<crate::db::TransactionRecord>), DatabaseError> {
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

    let desired_account_ids = serialize_vec(account_ids);

    // Read transactions in chunks to prevent loading excessive data and to stop
    // as soon as we approach the size limit
    let mut all_transactions = Vec::new();
    let mut total_size = 0i64;
    let mut last_block_num: Option<i64> = None;
    let mut last_transaction_id: Option<Vec<u8>> = None;

    loop {
        let mut query =
            SelectDsl::select(schema::transactions::table, TransactionRecordRaw::as_select())
                .filter(schema::transactions::block_num.ge(block_range.start().to_raw_sql()))
                .filter(schema::transactions::block_num.le(block_range.end().to_raw_sql()))
                .filter(schema::transactions::account_id.eq_any(&desired_account_ids))
                .into_boxed();

        // Apply cursor-based pagination using the last seen (block_num, transaction_id)
        if let (Some(last_block), Some(last_tx_id)) = (last_block_num, &last_transaction_id) {
            query = query.filter(
                schema::transactions::block_num
                    .gt(last_block)
                    .or(schema::transactions::block_num
                        .eq(last_block)
                        .and(schema::transactions::transaction_id.gt(last_tx_id))),
            );
        }

        let chunk = query
            .order((
                schema::transactions::block_num.asc(),
                schema::transactions::transaction_id.asc(),
            ))
            .limit(NUM_TXS_PER_CHUNK)
            .load::<TransactionRecordRaw>(conn)
            .map_err(DatabaseError::from)?;

        // Add transactions from this chunk one by one until we hit the limit
        let mut added_from_chunk = 0;
        let mut last_added_tx: Option<TransactionRecordRaw> = None;

        for tx in chunk {
            if total_size + tx.size_in_bytes <= max_payload_bytes {
                total_size += tx.size_in_bytes;
                last_added_tx = Some(tx);
                added_from_chunk += 1;
            } else {
                // Can't fit this transaction, stop here
                break;
            }
        }

        // Update cursor position only for the last transaction that was actually added
        if let Some(tx) = last_added_tx {
            last_block_num = Some(tx.block_num);
            last_transaction_id = Some(tx.transaction_id.clone());
            all_transactions.push(tx);
        }

        // Break if chunk incomplete (size limit hit or data exhausted)
        if added_from_chunk < NUM_TXS_PER_CHUNK {
            break;
        }
    }

    // Ensure block consistency: remove the last block if it's incomplete
    // (we may have stopped loading mid-block due to size constraints)
    if total_size >= max_payload_bytes {
        // SAFETY: We're guaranteed to have at least one transaction since total_size > 0
        let last_block_num = last_block_num.expect(
            "guaranteed to have processed at least one transaction when size limit is reached",
        );
        let filtered_transactions = vec_raw_try_into(
            all_transactions.into_iter().take_while(|row| row.block_num != last_block_num),
        )?;

        // SAFETY: block_num came from the database and was previously validated
        let last_included_block = BlockNumber::from_raw_sql(last_block_num.saturating_sub(1))?;
        Ok((last_included_block, filtered_transactions))
    } else {
        Ok((*block_range.end(), vec_raw_try_into(all_transactions)?))
    }
}
