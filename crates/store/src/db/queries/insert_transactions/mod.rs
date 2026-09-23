//! Inserts the transactions included in a block.

use miden_node_db::sqlite::WriteTx;
use miden_node_tracing::miden_instrument;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteHeader;
use miden_protocol::transaction::{
    InputNoteCommitment,
    OrderedTransactionHeaders,
    TransactionHeader,
};
use miden_protocol::utils::serde::Serializable;

use crate::COMPONENT;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("insert_transaction.sql");

/// Inserts the transactions included in a block.
///
/// # Returns
///
/// The number of affected rows.
#[miden_instrument(
    target = COMPONENT,
    err,
)]
pub(crate) fn insert_transactions(
    tx: &WriteTx<'_>,
    block_num: BlockNumber,
    transactions: &OrderedTransactionHeaders,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    for header in transactions.as_slice() {
        count += insert_transaction(tx, block_num, header)?;
    }
    Ok(count)
}

/// Inserts a single transaction header.
fn insert_transaction(
    tx: &WriteTx<'_>,
    block_num: BlockNumber,
    header: &TransactionHeader,
) -> Result<usize, DatabaseError> {
    // Serialize input notes as full InputNoteCommitments (nullifier + optional NoteHeader).
    let input_notes: Vec<InputNoteCommitment> = header.input_notes().iter().cloned().collect();
    let input_notes = input_notes.to_bytes();

    // Serialize output notes as full NoteHeaders (NoteId + NoteMetadata).
    let output_notes: Vec<NoteHeader> = header.output_notes().to_vec();
    let output_notes = output_notes.to_bytes();

    Ok(tx.execute(
        SQL,
        &[
            &header.id(),
            &header.account_id(),
            &block_num,
            &header.initial_state_commitment(),
            &header.final_state_commitment(),
            &input_notes,
            &output_notes,
            &estimated_sync_record_size(header),
        ],
    )?)
}

/// Estimates the size of the sync record this transaction produces.
///
/// The estimate is computed from note counts rather than by serializing the record, which would
/// cost far more than the estimate is worth. It is deliberately an over-estimate, so a response
/// assembled under the limit is always within it.
#[expect(
    clippy::cast_possible_wrap,
    reason = "We will not approach the item count where i64 and usize cause issues"
)]
fn estimated_sync_record_size(header: &TransactionHeader) -> i64 {
    // - 4 bytes for block number
    // - 32 bytes for transaction ID
    // - 16 bytes for account ID
    // - 64 bytes for initial + final state commitments (32 bytes each)
    const HEADER_BASE_SIZE_BYTES: usize = 4 + 32 + 16 + 64;
    const INPUT_NOTE_COMMITMENT_SIZE_BYTES: usize = 64;
    const OUTPUT_NOTE_SYNC_RECORD_SIZE_BYTES: usize = 700;
    // Worst case, every input note resolves to a consumed-note reference (nullifier + note id) in
    // the sync response. Counting it per input keeps input-heavy transactions under the cap.
    const CONSUMED_NOTE_REF_SIZE_BYTES: usize = 64;

    let input_notes_size = (header.input_notes().num_notes() as usize)
        * (INPUT_NOTE_COMMITMENT_SIZE_BYTES + CONSUMED_NOTE_REF_SIZE_BYTES);
    let output_notes_size = header.output_notes().len() * OUTPUT_NOTE_SYNC_RECORD_SIZE_BYTES;

    (HEADER_BASE_SIZE_BYTES + input_notes_size + output_notes_size) as i64
}
