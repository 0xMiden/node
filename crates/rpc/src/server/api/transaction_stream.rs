//! Whole-record transport bound for the protocol and protobuf versions pinned by Cargo.lock.

use miden_node_proto::generated as proto;
use miden_node_proto::prost::Message;
use miden_node_store::TransactionRecord;
use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::note::NoteAttachments;
use miden_protocol::{BLOCK_NOTE_TREE_DEPTH, MAX_INPUT_NOTES_PER_TX, MAX_OUTPUT_NOTES_PER_TX};

// Includes six bytes per nested field (tag plus worst-case u32 length), 34-byte Words, 40-byte
// account IDs, metadata with four packed schemes, and sparse paths with 16 siblings. An input
// commitment plus its optional consumed-note reference fits 320 bytes. An output header plus its
// optional inclusion proof fits 1024 bytes. 512 bytes cover fixed fields and six bytes cover the
// endpoint wrapper.
const ENCODED_UPPER_BOUND: usize =
    512 + MAX_INPUT_NOTES_PER_TX * 320 + MAX_OUTPUT_NOTES_PER_TX * 1024 + 6;
const _: () = assert!(NoteAttachments::MAX_COUNT == 4 && BLOCK_NOTE_TREE_DEPTH == 16);
const _: () = assert!(ENCODED_UPPER_BOUND < MAX_RESPONSE_PAYLOAD_BYTES);

pub(super) fn encode(
    record: TransactionRecord,
) -> tonic::Result<proto::miden::node::v1::TransactionRecord> {
    if record.header.input_notes().iter().count() > MAX_INPUT_NOTES_PER_TX
        || record.header.output_notes().len() > MAX_OUTPUT_NOTES_PER_TX
        || record.output_note_proofs.len() > MAX_OUTPUT_NOTES_PER_TX
        || record.consumed_note_refs.len() > MAX_INPUT_NOTES_PER_TX
        || record
            .output_note_proofs
            .iter()
            .any(|proof| proof.inclusion_path.depth() > BLOCK_NOTE_TREE_DEPTH)
    {
        return Err(super::error_codes::internal_error(
            "stored transaction exceeds protocol record limits",
        ));
    }
    let record = super::sync_transactions::transaction_record_to_proto(record);
    if record.encoded_len().saturating_add(6) > MAX_RESPONSE_PAYLOAD_BYTES {
        return Err(super::error_codes::internal_error(
            "stored transaction exceeds the stream message limit",
        ));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use miden_node_proto::prost::Message;
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    use miden_protocol::block::{BlockNoteIndex, BlockNumber};
    use miden_protocol::crypto::merkle::SparseMerklePath;
    use miden_protocol::note::{
        NoteAttachment,
        NoteAttachmentScheme,
        NoteAttachments,
        NoteDetailsCommitment,
        NoteHeader,
        NoteId,
        NoteMetadata,
        NoteType,
        Nullifier,
        PartialNoteMetadata,
    };
    use miden_protocol::transaction::{InputNoteCommitment, InputNotes, TransactionHeader};
    use miden_protocol::{Felt, Word};

    use super::*;

    fn maximum_record(authenticated: bool) -> TransactionRecord {
        let word = Word::from([Felt::MAX; 4]);
        let account = AccountId::dummy(
            [255; 15],
            AccountIdVersion::Version1,
            AccountType::Public,
            AssetCallbackFlag::Disabled,
        );
        let attachments = NoteAttachments::new(
            (0..4)
                .map(|n| {
                    NoteAttachment::with_word(
                        NoteAttachmentScheme::new(NoteAttachmentScheme::MAX.as_u16() - n).unwrap(),
                        word,
                    )
                })
                .collect(),
        )
        .unwrap();
        let metadata = NoteMetadata::new(
            PartialNoteMetadata::new(account, NoteType::Public).with_tag(u32::MAX.into()),
            &attachments,
        );
        let inputs: Vec<_> = (0..MAX_INPUT_NOTES_PER_TX)
            .map(|index| {
                let index = u32::try_from(index).unwrap();
                let nullifier = Nullifier::from_raw(Word::from([index, 1, 0, 0]));
                let header = (!authenticated).then(|| {
                    NoteHeader::new(
                        NoteDetailsCommitment::from_raw(Word::from([index, 2, 0, 0])),
                        metadata,
                    )
                });
                InputNoteCommitment::from_parts_unchecked(nullifier, header)
            })
            .collect();
        let consumed_note_refs = if authenticated {
            inputs
                .iter()
                .map(|input| (input.nullifier(), NoteId::from_raw(input.nullifier().as_word())))
                .collect()
        } else {
            vec![]
        };
        let outputs: Vec<_> = (0..MAX_OUTPUT_NOTES_PER_TX)
            .map(|index| {
                NoteHeader::new(
                    NoteDetailsCommitment::from_raw(Word::from([
                        u32::try_from(index).unwrap(),
                        3,
                        0,
                        0,
                    ])),
                    metadata,
                )
            })
            .collect();
        let output_note_proofs = outputs
            .iter()
            .enumerate()
            .map(|(index, header)| miden_node_store::NoteSyncRecord {
                block_num: BlockNumber::from(u32::MAX),
                note_index: BlockNoteIndex::new(miden_protocol::MAX_BATCHES_PER_BLOCK - 1, index)
                    .unwrap(),
                note_id: header.id(),
                metadata,
                attachments: attachments.clone(),
                inclusion_path: SparseMerklePath::from_parts(
                    0,
                    vec![word; usize::from(BLOCK_NOTE_TREE_DEPTH)],
                )
                .unwrap(),
            })
            .collect();
        let header =
            TransactionHeader::new(account, word, word, InputNotes::new(inputs).unwrap(), outputs)
                .unwrap();
        TransactionRecord {
            block_num: BlockNumber::from(u32::MAX),
            header,
            output_note_proofs,
            consumed_note_refs,
        }
    }

    #[test]
    fn maximum_whole_transaction_records_fit_the_derived_transport_bound() {
        for authenticated in [false, true] {
            let record = encode(maximum_record(authenticated)).unwrap();
            let wrapper =
                proto::miden::node::v1::GetTransactionsByIdResponse { transaction: Some(record) };
            assert!(wrapper.encoded_len() <= ENCODED_UPPER_BOUND);
            assert!(wrapper.encoded_len() < MAX_RESPONSE_PAYLOAD_BYTES);
        }
    }

    #[test]
    fn out_of_protocol_records_fail_instead_of_exceeding_the_message_contract() {
        let mut record = maximum_record(true);
        record.consumed_note_refs.push(record.consumed_note_refs[0]);
        assert_eq!(encode(record).unwrap_err().code(), tonic::Code::Internal);
        let mut record = maximum_record(false);
        record.output_note_proofs[0].inclusion_path =
            SparseMerklePath::from_parts(0, vec![Word::empty(); 17]).unwrap();
        assert_eq!(encode(record).unwrap_err().code(), tonic::Code::Internal);
    }
}
