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
    let attachments = note
        .attachments
        .iter()
        .map(|attachment| {
            let payload = if attachment.num_words() == 1 {
                proto::rpc::note_sync_attachment::Payload::Value(
                    attachment.content().as_words()[0].into(),
                )
            } else {
                proto::rpc::note_sync_attachment::Payload::Commitment(
                    attachment.to_commitment().into(),
                )
            };

            proto::rpc::NoteSyncAttachment {
                scheme: attachment.attachment_scheme().as_u16().into(),
                payload: Some(payload),
            }
        })
        .collect();
    let metadata = Some(proto::rpc::NoteSyncMetadata {
        sender: Some(note.metadata.sender().into()),
        version: proto::note::NoteVersion::V1 as i32,
        note_type: proto::note::NoteType::from(note.metadata.note_type()) as i32,
        tag: note.metadata.tag().as_u32(),
        attachments,
    });
    let inclusion_proof = Some(proto::note::NoteInclusionProof {
        note_id: Some((&note.note_id).into()),
        block_num: Some(note.block_num.into()),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    });
    proto::rpc::NoteSyncRecord { metadata, inclusion_proof }
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
    use miden_node_proto::prost::Message;
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    use miden_protocol::block::{BlockNoteIndex, BlockNumber, ValidatorConfig};
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
    use miden_protocol::{
        BLOCK_NOTE_TREE_DEPTH,
        Hasher,
        MAX_BATCHES_PER_BLOCK,
        MAX_OUTPUT_NOTES_PER_BATCH,
        Word,
    };

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
        let expected_metadata_commitment = metadata.to_commitment();
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
        assert_eq!(proto_metadata.version, proto::note::NoteVersion::V1 as i32);
        assert_eq!(proto_metadata.note_type, proto::note::NoteType::Private as i32);
        assert_eq!(proto_metadata.tag, 7);
        assert_eq!(proto_metadata.attachments.len(), 2);

        let first = &proto_metadata.attachments[0];
        assert_eq!(first.scheme, u32::from(single_word_scheme.as_u16()));
        assert_eq!(
            first.payload,
            Some(proto::rpc::note_sync_attachment::Payload::Value(single_word.into()))
        );

        let second = &proto_metadata.attachments[1];
        assert_eq!(second.scheme, u32::from(multi_word_scheme.as_u16()));
        assert_eq!(
            second.payload,
            Some(proto::rpc::note_sync_attachment::Payload::Commitment(
                multi_word_commitment.into()
            ))
        );

        let attachment_commitments: Vec<Word> = proto_metadata
            .attachments
            .iter()
            .map(|attachment| match attachment.payload.as_ref().unwrap() {
                proto::rpc::note_sync_attachment::Payload::Value(value) => {
                    let value = Word::try_from(value).unwrap();
                    Hasher::hash_elements(value.as_elements())
                },
                proto::rpc::note_sync_attachment::Payload::Commitment(commitment) => {
                    Word::try_from(commitment).unwrap()
                },
            })
            .collect();
        let commitment_elements: Vec<_> =
            attachment_commitments.iter().flat_map(Word::as_elements).copied().collect();
        let attachments_commitment = Hasher::hash_elements(&commitment_elements);
        assert_eq!(attachments_commitment, attachments.to_commitment());

        let mut attachment_schemes = proto_metadata
            .attachments
            .iter()
            .map(|attachment| attachment.scheme)
            .collect::<Vec<_>>();
        attachment_schemes.resize(NoteAttachments::MAX_COUNT, 0);
        let reconstructed: NoteMetadata = proto::note::NoteMetadata {
            version: proto_metadata.version,
            sender: proto_metadata.sender,
            note_type: proto_metadata.note_type,
            tag: proto_metadata.tag,
            attachment_schemes,
            attachments_commitment: Some(attachments_commitment.into()),
        }
        .try_into()
        .unwrap();
        assert_eq!(reconstructed.to_commitment(), expected_metadata_commitment);
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
        let metadata = proto_record.metadata.unwrap();
        assert!(metadata.attachments.is_empty());
        assert_eq!(metadata.version, proto::note::NoteVersion::V1 as i32);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the fixture exercises the maximum size of each response field"
    )]
    fn compact_note_sync_response_fits_pagination_size_estimates() {
        // Keep these budgets aligned with the store note sync pagination estimates.
        const RECORD_BUDGET: usize = 900;
        const BLOCK_OVERHEAD_BUDGET: usize = 1800;

        let word = Word::from([1, 2, 3, 4u32]);
        let attachments = NoteAttachments::new(
            (1..=NoteAttachments::MAX_COUNT)
                .map(|scheme| {
                    NoteAttachment::with_word(
                        NoteAttachmentScheme::new(u16::try_from(scheme).unwrap()).unwrap(),
                        word,
                    )
                })
                .collect(),
        )
        .unwrap();
        let sender = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version1,
            AccountType::Public,
            AssetCallbackFlag::Disabled,
        );
        let record = note_sync_record_to_proto(NoteSyncRecord {
            block_num: BlockNumber::from(u32::MAX),
            note_index: BlockNoteIndex::new(
                MAX_BATCHES_PER_BLOCK - 1,
                MAX_OUTPUT_NOTES_PER_BATCH - 1,
            )
            .unwrap(),
            note_id: NoteId::from_raw(word),
            metadata: NoteMetadata::new(
                PartialNoteMetadata::new(sender, NoteType::Public)
                    .with_tag(NoteTag::from(u32::MAX)),
                &attachments,
            ),
            attachments,
            inclusion_path: SparseMerklePath::from_parts(
                0,
                vec![word; usize::from(BLOCK_NOTE_TREE_DEPTH)],
            )
            .unwrap(),
        });
        assert_eq!(record.metadata.as_ref().unwrap().attachments.len(), 4);
        assert_eq!(
            record
                .inclusion_proof
                .as_ref()
                .unwrap()
                .inclusion_path
                .as_ref()
                .unwrap()
                .siblings
                .len(),
            16
        );

        let header = proto::blockchain::BlockHeader {
            version: proto::blockchain::BlockVersion::V1 as i32,
            timestamp: u32::MAX,
            block_num: Some(BlockNumber::from(u32::MAX).into()),
            prev_block_commitment: Some(word.into()),
            chain_commitment: Some(word.into()),
            account_root: Some(word.into()),
            nullifier_root: Some(word.into()),
            note_root: Some(word.into()),
            tx_commitment: Some(word.into()),
            validator_config: Some(proto::blockchain::ValidatorConfig {
                keys: vec![
                    proto::primitives::PublicKey {
                        variant: proto::primitives::PublicKeyVariant::EcdsaK256Keccak as i32,
                        encoded: vec![2; 33],
                    };
                    ValidatorConfig::MAX_VALIDATORS
                ],
                quorum: u32::try_from(ValidatorConfig::MAX_VALIDATORS).unwrap(),
            }),
            fee_parameters: Some(proto::blockchain::FeeParameters {
                verification_base_fee: u32::MAX,
            }),
            protocol_config_commitment: Some(word.into()),
            next_protocol_config: Some(proto::blockchain::NextProtocolConfig {
                effective_from: Some(BlockNumber::from(u32::MAX).into()),
                protocol_config: Some(word.into()),
            }),
        };
        let block = proto::rpc::sync_notes_response::NoteSyncBlock {
            block_header: Some(header),
            mmr_path: Some(proto::primitives::MerklePath {
                siblings: vec![word.into(); u32::BITS as usize],
            }),
            notes: Vec::new(),
        };
        let mut response = proto::rpc::SyncNotesResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: u32::MAX,
                block_num: u32::MAX,
            }),
            blocks: vec![block],
        };
        let overhead = response.encoded_len();
        assert!(overhead <= BLOCK_OVERHEAD_BUDGET, "block overhead is {overhead} bytes");

        response.blocks[0].notes.push(record);
        let record_size = response.encoded_len() - overhead;
        assert!(record_size <= RECORD_BUDGET, "compact note record adds {record_size} bytes");
        assert!(response.encoded_len() <= BLOCK_OVERHEAD_BUDGET + RECORD_BUDGET);
    }
}
