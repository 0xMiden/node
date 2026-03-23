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
use miden_protocol::note::NoteHeader;
use miden_protocol::transaction::{InputNoteCommitment, OrderedTransactionHeaders, TransactionId};
use miden_protocol::utils::{Deserializable, Serializable};

use super::DatabaseError;
use crate::COMPONENT;
use crate::db::models::conv::SqlTypeConvert;
use crate::db::models::{serialize_vec, vec_raw_try_into};
use crate::db::schema;

#[derive(Debug, Clone, PartialEq, Queryable, Selectable, QueryableByName)]
#[diesel(table_name = schema::transactions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct TransactionRecordRaw {
    account_id: Vec<u8>,
    block_num: i64,
    transaction_id: Vec<u8>,
    initial_state_commitment: Vec<u8>,
    final_state_commitment: Vec<u8>,
    input_notes: Vec<u8>,
    output_notes: Vec<u8>,
    size_in_bytes: i64,
    fee: Vec<u8>,
}

impl TryInto<crate::db::TransactionRecord> for TransactionRecordRaw {
    type Error = DatabaseError;
    fn try_into(self) -> Result<crate::db::TransactionRecord, Self::Error> {
        use miden_protocol::Word;
        use miden_protocol::asset::FungibleAsset;

        let input_notes: Vec<InputNoteCommitment> =
            Deserializable::read_from_bytes(&self.input_notes)?;
        let output_notes: Vec<NoteHeader> = Deserializable::read_from_bytes(&self.output_notes)?;
        let fee = FungibleAsset::read_from_bytes(&self.fee)?;

        Ok(crate::db::TransactionRecord {
            account_id: AccountId::read_from_bytes(&self.account_id[..])?,
            block_num: BlockNumber::from_raw_sql(self.block_num)?,
            transaction_id: TransactionId::read_from_bytes(&self.transaction_id[..])?,
            initial_state_commitment: Word::read_from_bytes(&self.initial_state_commitment)?,
            final_state_commitment: Word::read_from_bytes(&self.final_state_commitment)?,
            input_notes,
            output_notes,
            fee,
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
    let rows: Vec<_> = transactions
        .as_slice()
        .iter()
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
    input_notes: Vec<u8>,
    output_notes: Vec<u8>,
    size_in_bytes: i64,
    fee: Vec<u8>,
}

impl TransactionSummaryRowInsert {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "We will not approach the item count where i64 and usize cause issues"
    )]
    fn new(
        transaction_header: &miden_protocol::transaction::TransactionHeader,
        block_num: BlockNumber,
    ) -> Self {
        const HEADER_BASE_SIZE: usize = 4 + 32 + 16 + 64; // block_num + tx_id + account_id + commitments

        // Serialize input notes as full InputNoteCommitments (nullifier + optional NoteHeader).
        let input_notes: Vec<InputNoteCommitment> =
            transaction_header.input_notes().iter().cloned().collect();
        let input_notes_binary = input_notes.to_bytes();

        // Serialize output notes as full NoteHeaders (NoteId + NoteMetadata).
        let output_notes: Vec<NoteHeader> = transaction_header.output_notes().to_vec();
        let output_notes_binary = output_notes.to_bytes();

        // Manually calculate the estimated size of the transaction header to avoid
        // the cost of serialization. The size estimation includes:
        // - 4 bytes for block number
        // - 32 bytes for transaction ID
        // - 16 bytes for account ID
        // - 64 bytes for initial + final state commitments (32 bytes each)
        // - ~64 bytes per input note (nullifier + optional NoteHeader)
        // - ~64 bytes per output note (NoteHeader = NoteId + NoteMetadata)
        let input_notes_size = (transaction_header.input_notes().num_notes() as usize) * 64;
        let output_notes_size = transaction_header.output_notes().len() * 64;
        let size_in_bytes = (HEADER_BASE_SIZE + input_notes_size + output_notes_size) as i64;

        Self {
            transaction_id: transaction_header.id().to_bytes(),
            account_id: transaction_header.account_id().to_bytes(),
            block_num: block_num.to_raw_sql(),
            initial_state_commitment: transaction_header.initial_state_commitment().to_bytes(),
            final_state_commitment: transaction_header.final_state_commitment().to_bytes(),
            input_notes: input_notes_binary,
            output_notes: output_notes_binary,
            size_in_bytes,
            fee: transaction_header.fee().to_bytes(),
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

        for tx in chunk {
            if total_size + tx.size_in_bytes <= max_payload_bytes {
                total_size += tx.size_in_bytes;
                last_block_num = Some(tx.block_num);
                last_transaction_id = Some(tx.transaction_id.clone());
                all_transactions.push(tx);
                added_from_chunk += 1;
            } else {
                // Can't fit this transaction, stop here
                break;
            }
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
        // Subtraction is safe under the assumption that genesis block (where it could fail) does
        // not have any transactions.
        let last_included_block = BlockNumber::from_raw_sql(last_block_num.saturating_sub(1))?;
        Ok((last_included_block, filtered_transactions))
    } else {
        Ok((*block_range.end(), vec_raw_try_into(all_transactions)?))
    }
}
