use miden_node_proto::decode::read_block_range;
use miden_node_proto::generated as proto;
use miden_node_store::{NoteSyncError, NoteSyncRecord};
use miden_node_utils::limiter::QueryParamNoteTagLimit;
use miden_node_utils::tracing::{miden_instrument, miden_span_record};
use tonic::Status;
use tracing::debug;

use super::{RpcInvalidBlockRange, RpcService, check, invalid_block_range_to_status};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::SyncNotes for RpcService {
    type Input = proto::rpc::SyncNotesRequest;
    type Output = proto::rpc::SyncNotesResponse;

    fn decode(request: proto::rpc::SyncNotesRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::SyncNotesResponse> {
        Ok(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "sync_notes",
        err,
    )]
    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        tracing::trace!(target: LOG_TARGET, ?request);

        let range = read_block_range::<Status>(request.block_range, "SyncNotesRequest")?;

        miden_span_record!(block_range.from = range.block_from, block_range.to = range.block_to,);

        debug!(target: LOG_TARGET, "Syncing notes");

        check::<QueryParamNoteTagLimit>(request.note_tags.len())?;

        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let (chain_tip, (results, last_block_checked)) = self
            .state
            .with_view(async |view| {
                view.sync_notes(request.note_tags, block_range)
                    .await
                    .map(|notes| (view.tip(), notes))
                    .map_err(note_sync_error_to_status)
            })
            .await?;
        let blocks = results
            .into_iter()
            .map(|(state, mmr_proof)| proto::rpc::sync_notes_response::NoteSyncBlock {
                block_header: Some(state.block_header.into()),
                mmr_path: Some(mmr_proof.merkle_path().clone().into()),
                notes: state.notes.into_iter().map(note_sync_record_to_proto).collect(),
            })
            .collect();

        Ok(proto::rpc::SyncNotesResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_checked.as_u32(),
            }),
            blocks,
        })
    }
}

// HELPERS
// ================================================================================================

fn note_sync_record_to_proto(note: NoteSyncRecord) -> proto::note::NoteSyncRecord {
    let attachments = note
        .attachments
        .iter()
        .map(|attachment| {
            let payload = if attachment.num_words() == 1 {
                proto::note::note_sync_attachment::Payload::Value(
                    attachment.content().as_words()[0].into(),
                )
            } else {
                proto::note::note_sync_attachment::Payload::Commitment(
                    attachment.to_commitment().into(),
                )
            };

            proto::note::NoteSyncAttachment {
                scheme: attachment.attachment_scheme().as_u16().into(),
                payload: Some(payload),
            }
        })
        .collect();
    let metadata = Some(proto::note::NoteSyncMetadata {
        sender: Some(note.metadata.sender().into()),
        note_type: proto::note::NoteType::from(note.metadata.note_type()) as i32,
        tag: note.metadata.tag().as_u32(),
        attachments,
    });
    let inclusion_proof = Some(proto::note::NoteInclusionInBlockProof {
        note_id: Some((&note.note_id).into()),
        block_num: note.block_num.as_u32(),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    });
    proto::note::NoteSyncRecord { metadata, inclusion_proof }
}

fn note_sync_error_to_status(err: NoteSyncError) -> Status {
    let message = err.to_string();
    match err {
        NoteSyncError::DatabaseError(err) => super::database_error_to_status(&err),
        NoteSyncError::InvalidBlockRange(_)
        | NoteSyncError::RangeBeyondTip(_)
        | NoteSyncError::DeserializationFailed(_) => Status::invalid_argument(message),
        NoteSyncError::UnderlyingDatabaseError(_)
        | NoteSyncError::EmptyBlockHeadersTable
        | NoteSyncError::MmrError(_) => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    use miden_protocol::block::{BlockNoteIndex, BlockNumber};
    use miden_protocol::crypto::merkle::SparseMerklePath;
    use miden_protocol::note::{
        NoteAttachment,
        NoteAttachmentScheme,
        NoteAttachments,
        NoteId,
        NoteMetadata,
        NoteTag,
        NoteType,
        PartialNoteMetadata,
    };
    use miden_protocol::{Hasher, Word};

    use super::*;

    #[test]
    fn sync_note_encodes_attachment_values_and_commitments() {
        let single_word = Word::from([1, 2, 3, 4u32]);
        let single_word_scheme = NoteAttachmentScheme::new(42).unwrap();
        let multi_word_scheme = NoteAttachmentScheme::new(100).unwrap();
        let multi_word_attachment = NoteAttachment::with_words(
            multi_word_scheme,
            vec![Word::from([5, 6, 7, 8u32]), Word::from([9, 10, 11, 12u32])],
        )
        .unwrap();
        let multi_word_commitment = multi_word_attachment.to_commitment();
        let attachments = NoteAttachments::new(vec![
            NoteAttachment::with_word(single_word_scheme, single_word),
            multi_word_attachment,
        ])
        .unwrap();

        let sender = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version1,
            AccountType::Public,
            AssetCallbackFlag::Disabled,
        );
        let metadata = NoteMetadata::new(
            PartialNoteMetadata::new(sender, NoteType::Private).with_tag(NoteTag::from(7u32)),
            &attachments,
        );
        let record = NoteSyncRecord {
            block_num: BlockNumber::from(3),
            note_index: BlockNoteIndex::new(0, 1).unwrap(),
            note_id: NoteId::from_raw(Word::from([13, 14, 15, 16u32])),
            metadata,
            attachments: attachments.clone(),
            inclusion_path: SparseMerklePath::default(),
        };

        let proto_record = note_sync_record_to_proto(record);
        let proto_metadata = proto_record.metadata.unwrap();
        assert_eq!(proto_metadata.sender, Some(sender.into()));
        assert_eq!(proto_metadata.note_type, proto::note::NoteType::Private as i32);
        assert_eq!(proto_metadata.tag, 7);
        assert_eq!(proto_metadata.attachments.len(), 2);

        let first = &proto_metadata.attachments[0];
        assert_eq!(first.scheme, u32::from(single_word_scheme.as_u16()));
        assert_eq!(
            first.payload,
            Some(proto::note::note_sync_attachment::Payload::Value(single_word.into()))
        );

        let second = &proto_metadata.attachments[1];
        assert_eq!(second.scheme, u32::from(multi_word_scheme.as_u16()));
        assert_eq!(
            second.payload,
            Some(proto::note::note_sync_attachment::Payload::Commitment(
                multi_word_commitment.into()
            ))
        );

        let attachment_commitments: Vec<Word> = proto_metadata
            .attachments
            .iter()
            .map(|attachment| match attachment.payload.as_ref().unwrap() {
                proto::note::note_sync_attachment::Payload::Value(value) => {
                    let value = Word::try_from(value).unwrap();
                    Hasher::hash_elements(value.as_elements())
                },
                proto::note::note_sync_attachment::Payload::Commitment(commitment) => {
                    Word::try_from(commitment).unwrap()
                },
            })
            .collect();
        let commitment_elements: Vec<_> =
            attachment_commitments.iter().flat_map(Word::as_elements).copied().collect();
        assert_eq!(Hasher::hash_elements(&commitment_elements), attachments.to_commitment());
    }

    #[test]
    fn sync_note_without_attachments_encodes_an_empty_list() {
        let attachments = NoteAttachments::empty();
        let sender = AccountId::dummy(
            [2; 15],
            AccountIdVersion::Version1,
            AccountType::Public,
            AssetCallbackFlag::Disabled,
        );
        let record = NoteSyncRecord {
            block_num: BlockNumber::from(1),
            note_index: BlockNoteIndex::new(0, 0).unwrap(),
            note_id: NoteId::from_raw(Word::from([1, 1, 1, 1u32])),
            metadata: NoteMetadata::new(
                PartialNoteMetadata::new(sender, NoteType::Public),
                &attachments,
            ),
            attachments,
            inclusion_path: SparseMerklePath::default(),
        };

        let proto_record = note_sync_record_to_proto(record);
        assert!(proto_record.metadata.unwrap().attachments.is_empty());
    }
}
