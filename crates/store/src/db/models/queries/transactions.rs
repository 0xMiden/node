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
    QueryParamNoteCommitmentLimit,
};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteHeader, NoteId, Nullifier};
use miden_protocol::transaction::{
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    TransactionHeader,
    TransactionId,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};

use super::{DatabaseError, select_note_ids_by_nullifier, select_note_sync_records};
use crate::COMPONENT;
use crate::db::models::conv::SqlTypeConvert;
use crate::db::models::serialize_vec;
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
        const HEADER_BASE_SIZE_BYTES: usize = 4 + 32 + 16 + 64;
        const INPUT_NOTE_COMMITMENT_SIZE_BYTES: usize = 64;
        const OUTPUT_NOTE_SYNC_RECORD_SIZE_BYTES: usize = 700;
        // Worst case, every input note resolves to a consumed-note reference (nullifier + note id)
        // in the sync response. Counting it per input keeps input-heavy transactions under the cap.
        const CONSUMED_NOTE_REF_SIZE_BYTES: usize = 64;

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
        // - ~64 bytes per input note for its possible consumed-note reference
        // - ~700 bytes per output note sync record (metadata header + inclusion proof)
        let input_notes_size = (transaction_header.input_notes().num_notes() as usize)
            * (INPUT_NOTE_COMMITMENT_SIZE_BYTES + CONSUMED_NOTE_REF_SIZE_BYTES);
        let output_notes_size =
            transaction_header.output_notes().len() * OUTPUT_NOTE_SYNC_RECORD_SIZE_BYTES;
        let size_in_bytes = (HEADER_BASE_SIZE_BYTES + input_notes_size + output_notes_size) as i64;

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
/// This function returns complete transaction record information including state commitments and
/// output note inclusion proofs, allowing for direct conversion to proto `TransactionRecord`
/// without loading full block data. We use a chunked loading strategy to prevent memory
/// exhaustion attacks and ensure predictable resource usage.
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

    // Read transactions in chunks to prevent loading excessive data and to stop as soon as we
    // approach the size limit
    let mut transactions = Vec::new();
    let mut total_size = 0i64;
    let mut last_block_num: Option<i64> = None;
    let mut last_transaction_id: Option<Vec<u8>> = None;
    // Track the block number of the first transaction that did not fit within the payload cap. This
    // is the explicit "we truncated" signal; the accumulated byte total cannot be used as a proxy,
    // since a transaction can fail to fit while `total_size` is still below the cap.
    let mut truncated_at_block: Option<i64> = None;

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
                transactions.push(tx);
                added_from_chunk += 1;
            } else {
                // This transaction does not fit, so the response is truncated at its block.
                truncated_at_block = Some(tx.block_num);
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
        return Ok((*block_range.end(), with_output_note_proofs(conn, transactions)?));
    };

    // We stopped within `truncation_block`, so that block may be partial. Block-based pagination
    // can only report fully-included blocks, so drop every transaction belonging to the truncation
    // block and report the previous block as the cursor. Transactions are ordered ascending by
    // block number, so the truncation block's transactions form a contiguous suffix:
    // `partition_point` locates the boundary and `truncate` drops the suffix in place, without
    // allocating a new vector, with O(log n) complexity.
    let complete_len = transactions.partition_point(|row| row.block_num < truncation_block);
    transactions.truncate(complete_len);

    if transactions.is_empty() {
        // A single block's transactions exceed the payload cap. Reporting `truncation_block - 1`
        // here would tell the client to resume from `truncation_block`, which can never fit, so
        // pagination would loop forever. Surface the condition instead of silently looping.
        return Err(DatabaseError::TransactionPageExceedsPayloadLimit {
            block_num: BlockNumber::from_raw_sql(truncation_block)?,
        });
    }

    // SAFETY: block_num came from the database and was previously validated. Subtraction is safe
    // under the assumption that genesis block (where it could fail) does not have any transactions.
    let last_included_block = BlockNumber::from_raw_sql(truncation_block.saturating_sub(1))?;
    Ok((last_included_block, with_output_note_proofs(conn, transactions)?))
}

fn with_output_note_proofs(
    conn: &mut SqliteConnection,
    raw_transactions: Vec<TransactionRecordRaw>,
) -> Result<Vec<crate::db::TransactionRecord>, DatabaseError> {
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;

    // Pre-deserialize output notes to collect IDs for the batch lookup.
    let mut tx_output_notes = Vec::with_capacity(raw_transactions.len());
    let mut all_note_ids: Vec<NoteId> = Vec::new();
    for raw in &raw_transactions {
        let notes: Vec<NoteHeader> = Deserializable::read_from_bytes(&raw.output_notes)?;
        all_note_ids.extend(notes.iter().map(NoteHeader::id));
        tx_output_notes.push(notes);
    }

    let mut output_notes_by_id = std::collections::BTreeMap::new();
    for chunk in all_note_ids.chunks(QueryParamNoteCommitmentLimit::LIMIT) {
        output_notes_by_id.extend(select_note_sync_records(conn, chunk)?);
    }

    // Deserialize each transaction's input notes once and reuse them below. Authenticated inputs
    // have no header and carry only a nullifier, so gather those nullifiers to look their note IDs
    // up in one batch.
    let mut tx_input_notes: Vec<Vec<InputNoteCommitment>> =
        Vec::with_capacity(raw_transactions.len());
    let mut authenticated_nullifiers: Vec<Nullifier> = Vec::new();
    for raw in &raw_transactions {
        let commitments: Vec<InputNoteCommitment> =
            Deserializable::read_from_bytes(&raw.input_notes)?;
        for commitment in &commitments {
            if commitment.header().is_none() {
                authenticated_nullifiers.push(commitment.nullifier());
            }
        }
        tx_input_notes.push(commitments);
    }

    let mut note_ids_by_nullifier = std::collections::BTreeMap::new();
    for chunk in authenticated_nullifiers.chunks(QueryParamNoteCommitmentLimit::LIMIT) {
        note_ids_by_nullifier.extend(select_note_ids_by_nullifier(conn, chunk)?);
    }

    // Deserialize remaining fields and assemble final records.
    raw_transactions
        .into_iter()
        .zip(tx_output_notes)
        .zip(tx_input_notes)
        .map(|((raw, output_notes), input_notes)| {
            let transaction_id = TransactionId::read_from_bytes(&raw.transaction_id)?;
            // Collect inclusion proofs for committed output notes. Notes not found in the `notes`
            // table were erased (created and consumed in the same batch).
            let output_note_proofs = output_notes
                .iter()
                .filter_map(|note| {
                    let key = note.id();
                    output_notes_by_id.get(&key).cloned()
                })
                .collect();

            // Build the side-channel refs. The input note commitments are left untouched, so the
            // header and its commitment stay exactly as the transaction submitted them.
            let consumed_note_refs = input_notes
                .iter()
                .filter(|commitment| commitment.header().is_none())
                .filter_map(|commitment| {
                    let nullifier = commitment.nullifier();
                    note_ids_by_nullifier.get(&nullifier).map(|note_id| (nullifier, *note_id))
                })
                .collect();

            let header = TransactionHeader::new_unchecked(
                transaction_id,
                AccountId::read_from_bytes(&raw.account_id)?,
                Word::read_from_bytes(&raw.initial_state_commitment)?,
                Word::read_from_bytes(&raw.final_state_commitment)?,
                InputNotes::new_unchecked(input_notes),
                output_notes,
                FungibleAsset::read_from_bytes(&raw.fee)?,
            );

            Ok(crate::db::TransactionRecord {
                block_num: BlockNumber::from_raw_sql(raw.block_num)?,
                header,
                output_note_proofs,
                consumed_note_refs,
            })
        })
        .collect()
}
