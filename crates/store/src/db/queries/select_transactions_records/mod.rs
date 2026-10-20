//! Returns full transaction records for a set of accounts within a block range.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use miden_node_db::sqlite::{InList, ReadTx, Row};
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteCommitmentLimit,
};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteHeader, NoteId, Nullifier};
use miden_protocol::transaction::{
    InputNoteCommitment,
    InputNotes,
    TransactionHeader,
    TransactionId,
};

use crate::db::TransactionRecord;
use crate::db::pagination::{Page, Paginated};
use crate::db::queries::{select_note_ids_by_nullifier, select_note_sync_records};
use crate::errors::DatabaseError;
use crate::state::ScopedBlockNum;

const SQL_FIRST_CHUNK: &str = include_str!("select_transactions_records_chunk.sql");
const SQL_AFTER_CURSOR: &str = include_str!("select_transactions_records_chunk_after.sql");

/// A stored transaction row. The note columns stay encoded until the rows are complete.
struct TransactionRow {
    account_id: AccountId,
    block_num: BlockNumber,
    transaction_id: TransactionId,
    initial_state_commitment: Word,
    final_state_commitment: Word,
    input_notes: Vec<u8>,
    output_notes: Vec<u8>,
    size_in_bytes: i64,
}

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

/// Maps a `SELECT account_id, block_num, transaction_id, initial_state_commitment,
/// final_state_commitment, input_notes, output_notes, size_in_bytes` row to a [`TransactionRow`].
fn transaction_row_from_row(row: &Row<'_>) -> Result<TransactionRow, miden_node_db::DatabaseError> {
    Ok(TransactionRow {
        account_id: row.get::<AccountId>(0)?,
        block_num: row.get::<BlockNumber>(1)?,
        transaction_id: row.get::<TransactionId>(2)?,
        initial_state_commitment: row.get::<Word>(3)?,
        final_state_commitment: row.get::<Word>(4)?,
        input_notes: row.get::<Vec<u8>>(5)?,
        output_notes: row.get::<Vec<u8>>(6)?,
        size_in_bytes: row.get::<i64>(7)?,
    })
}

/// Builds the transaction records, with the committed output notes and the consumed note references
/// of each transaction.
fn with_output_note_proofs(
    tx: &ReadTx<'_>,
    raw_transactions: Vec<TransactionRow>,
) -> Result<Vec<TransactionRecord>, DatabaseError> {
    // Pre-deserialize output notes to collect IDs for the batch lookup.
    let mut tx_output_notes = Vec::with_capacity(raw_transactions.len());
    let mut all_note_ids: Vec<NoteId> = Vec::new();
    for raw in &raw_transactions {
        let notes: Vec<NoteHeader> = miden_node_persistence::decode(&raw.output_notes)?;
        all_note_ids.extend(notes.iter().map(NoteHeader::id));
        tx_output_notes.push(notes);
    }

    let mut output_notes_by_id = BTreeMap::new();
    for chunk in all_note_ids.chunks(QueryParamNoteCommitmentLimit::LIMIT) {
        output_notes_by_id.extend(select_note_sync_records(tx, chunk)?);
    }

    // Deserialize each transaction's input notes once and reuse them below. Authenticated inputs
    // have no header and carry only a nullifier, so gather those nullifiers to look their note IDs
    // up in one batch.
    let mut tx_input_notes: Vec<Vec<InputNoteCommitment>> =
        Vec::with_capacity(raw_transactions.len());
    let mut authenticated_nullifiers: Vec<Nullifier> = Vec::new();
    for raw in &raw_transactions {
        let commitments: Vec<InputNoteCommitment> =
            miden_node_persistence::decode(&raw.input_notes)?;
        for commitment in &commitments {
            if commitment.header().is_none() {
                authenticated_nullifiers.push(commitment.nullifier());
            }
        }
        tx_input_notes.push(commitments);
    }

    let mut note_ids_by_nullifier = BTreeMap::new();
    for chunk in authenticated_nullifiers.chunks(QueryParamNoteCommitmentLimit::LIMIT) {
        note_ids_by_nullifier.extend(select_note_ids_by_nullifier(tx, chunk)?);
    }

    // Assemble the final records.
    raw_transactions
        .into_iter()
        .zip(tx_output_notes)
        .zip(tx_input_notes)
        .map(|((raw, output_notes), input_notes)| {
            let transaction_id = raw.transaction_id;
            // Collect inclusion proofs for committed output notes. Notes not found in the `notes`
            // table were erased (created and consumed in the same batch).
            let output_note_proofs = output_notes
                .iter()
                .filter_map(|note| output_notes_by_id.get(&note.id()).cloned())
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

            let header = TransactionHeader::new(
                raw.account_id,
                raw.initial_state_commitment,
                raw.final_state_commitment,
                InputNotes::new_unchecked(input_notes),
                output_notes,
            )
            .map_err(|err| {
                DatabaseError::DataCorrupted(format!(
                    "invalid transaction header for stored transaction {transaction_id}: {err}"
                ))
            })?;

            if header.id() != transaction_id {
                return Err(DatabaseError::DataCorrupted(format!(
                    "stored transaction ID {transaction_id} does not match reconstructed ID {}",
                    header.id()
                )));
            }

            Ok(TransactionRecord {
                block_num: raw.block_num,
                header,
                output_note_proofs,
                consumed_note_refs,
            })
        })
        .collect()
}
