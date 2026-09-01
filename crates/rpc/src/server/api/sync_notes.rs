use miden_node_proto::decode::read_block_range;
use miden_node_proto::generated as proto;
use miden_node_store::{NoteSyncError, NoteSyncRecord};
use miden_node_tracing::{debug, miden_instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamNoteTagLimit;
use tonic::Status;

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
        let range = read_block_range::<Status>(request.block_range, "SyncNotesRequest")?;

        miden_span_record!(
            block_range.from = range.block_from,
            block_range.to = range.block_to,
            note.tags = request.note_tags.as_slice(),
            note.tag.count = request.note_tags.len()
        );

        debug!(
            target: LOG_TARGET,
            "Syncing notes",
            block_range.from = range.block_from,
            block_range.to = range.block_to,
            note.tags = request.note_tags.as_slice(),
            note.tag.count = request.note_tags.len()
        );

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

fn note_sync_record_to_proto(note: NoteSyncRecord) -> proto::rpc::NoteSyncRecord {
    let inclusion_proof = Some(proto::note::NoteInclusionProof {
        note_id: Some((&note.note_id).into()),
        block_num: Some(note.block_num.into()),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    });
    let note = Some(proto::note::Note {
        metadata: Some(note.metadata.into()),
        note_details: None,
        note_attachments: Some(note.attachments.into()),
    });
    proto::rpc::NoteSyncRecord { note, inclusion_proof }
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
    use miden_protocol::Word;
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

    use super::*;

    #[test]
    fn sync_note_encodes_canonical_metadata_and_attachments() {
        let single_word = Word::from([1, 2, 3, 4u32]);
        let single_word_scheme = NoteAttachmentScheme::new(42).unwrap();
        let multi_word_scheme = NoteAttachmentScheme::new(100).unwrap();
        let multi_word_attachment = NoteAttachment::with_words(
            multi_word_scheme,
            vec![Word::from([5, 6, 7, 8u32]), Word::from([9, 10, 11, 12u32])],
        )
        .unwrap();
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
        let proto_note = proto_record.note.unwrap();
        let decoded_metadata = NoteMetadata::try_from(proto_note.metadata.unwrap()).unwrap();
        let decoded_attachments =
            NoteAttachments::try_from(proto_note.note_attachments.unwrap()).unwrap();
        assert_eq!(decoded_metadata, metadata);
        assert_eq!(decoded_attachments, attachments);
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
        assert!(proto_record.note.unwrap().note_attachments.unwrap().attachments.is_empty());
    }
}
