//! Inserts the transactions included in a block.

use miden_node_db::sqlite::WriteTx;
use miden_node_tracing::instrument;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteHeader;
use miden_protocol::transaction::{
    InputNoteCommitment,
    OrderedTransactionHeaders,
    TransactionHeader,
};

use crate::errors::DatabaseError;

const SQL: &str = include_str!("insert_transaction.sql");

/// Inserts the transactions included in a block.
///
/// # Returns
///
/// The number of affected rows.
#[instrument(err)]
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
    let input_notes = miden_node_persistence::encode(&input_notes);

    // Serialize output notes as full NoteHeaders (NoteId + NoteMetadata).
    let output_notes: Vec<NoteHeader> = header.output_notes().to_vec();
    let output_notes = miden_node_persistence::encode(&output_notes);

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
            &header.logs_commitment(),
            &header.code_patch_commitment().as_word(),
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
    // Covers the block number, transaction/account IDs, four commitments and nested protobuf
    // framing, including the maximum block number.
    const HEADER_BASE_SIZE_BYTES: usize = 256;
    const INPUT_NOTE_COMMITMENT_SIZE_BYTES: usize = 192;
    const OUTPUT_NOTE_SYNC_RECORD_SIZE_BYTES: usize = 1024;
    // Worst case, every input note resolves to a consumed-note reference (nullifier + note id) in
    // the sync response. Counting it per input keeps input-heavy transactions under the cap.
    const CONSUMED_NOTE_REF_SIZE_BYTES: usize = 80;

    let input_notes_size = (header.input_notes().num_notes() as usize)
        * (INPUT_NOTE_COMMITMENT_SIZE_BYTES + CONSUMED_NOTE_REF_SIZE_BYTES);
    let output_notes_size = header.output_notes().len() * OUTPUT_NOTE_SYNC_RECORD_SIZE_BYTES;

    (HEADER_BASE_SIZE_BYTES + input_notes_size + output_notes_size) as i64
}

#[cfg(test)]
mod tests {
    use miden_node_proto::generated::miden::node::v1 as node;
    use miden_node_proto::prost::Message;
    use miden_protocol::Word;
    use miden_protocol::block::code_tree::CodePatchCommitment;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
    use miden_protocol::transaction::InputNotes;

    use super::*;

    #[test]
    fn sync_size_estimate_covers_resolved_input_notes() {
        use miden_protocol::note::Note;
        use miden_protocol::transaction::InputNoteCommitment;

        let notes: Vec<_> =
            (1_u32..=16).map(|seed| Note::mock_noop(Word::from([seed; 4]))).collect();
        let header = TransactionHeader::new(
            ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
            Word::from([1_u32; 4]),
            Word::from([2_u32; 4]),
            InputNotes::new(
                notes
                    .iter()
                    .map(|note| {
                        InputNoteCommitment::from_parts_unchecked(
                            note.nullifier(),
                            Some(*note.header()),
                        )
                    })
                    .collect(),
            )
            .unwrap(),
            vec![],
            Word::from([3_u32; 4]),
            CodePatchCommitment::from_raw(Word::from([4_u32; 4])),
        )
        .unwrap();
        let record = node::TransactionRecord {
            header: Some((&header).into()),
            block_num: u32::MAX,
            consumed_note_refs: notes
                .iter()
                .map(|note| node::ConsumedNoteRef {
                    nullifier: Some(note.nullifier().as_word().into()),
                    note_id: Some((&note.id()).into()),
                })
                .collect(),
            ..Default::default()
        };
        assert!(
            estimated_sync_record_size(&header) >= i64::try_from(record.encoded_len()).unwrap(),
            "estimate {} is smaller than encoded length {}",
            estimated_sync_record_size(&header),
            record.encoded_len()
        );
    }

    #[test]
    fn sync_size_estimate_covers_fixed_fields_and_protobuf_framing() {
        let header = TransactionHeader::new(
            ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
            Word::from([1_u32; 4]),
            Word::from([2_u32; 4]),
            InputNotes::default(),
            vec![],
            Word::from([3_u32; 4]),
            CodePatchCommitment::from_raw(Word::from([4_u32; 4])),
        )
        .unwrap();
        let record = node::TransactionRecord {
            header: Some((&header).into()),
            block_num: u32::MAX,
            ..Default::default()
        };
        assert!(
            estimated_sync_record_size(&header) >= i64::try_from(record.encoded_len()).unwrap(),
            "estimate {} is smaller than encoded length {}",
            estimated_sync_record_size(&header),
            record.encoded_len()
        );
    }
}
