//! Shared stored-row decoding and full transaction-record reconstruction.

use std::collections::BTreeMap;

use miden_node_db::sqlite::{ReadTx, Row};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};
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

use super::{select_note_ids_by_nullifier, select_note_sync_records};
use crate::{DatabaseError, TransactionRecord};

/// A stored transaction row. The note columns stay encoded until the rows are complete.
pub(crate) struct TransactionRow {
    pub(crate) account_id: AccountId,
    pub(crate) block_num: BlockNumber,
    pub(crate) transaction_id: TransactionId,
    initial_state_commitment: Word,
    final_state_commitment: Word,
    input_notes: Vec<u8>,
    output_notes: Vec<u8>,
    pub(crate) size_in_bytes: i64,
}

/// Maps a `SELECT account_id, block_num, transaction_id, initial_state_commitment,
/// final_state_commitment, input_notes, output_notes, size_in_bytes` row to a [`TransactionRow`].
pub(crate) fn transaction_row_from_row(
    row: &Row<'_>,
) -> Result<TransactionRow, miden_node_db::DatabaseError> {
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
pub(crate) fn with_output_note_proofs(
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
