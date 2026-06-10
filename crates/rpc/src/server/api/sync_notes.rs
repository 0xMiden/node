use miden_node_proto::decode::read_block_range;
use miden_node_proto::generated as proto;
use miden_node_store::{NoteSyncError, NoteSyncRecord};
use miden_node_utils::limiter::QueryParamNoteTagLimit;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use tonic::Status;
use tracing::{Span, debug};

use super::{COMPONENT, RpcInvalidBlockRange, RpcService, check, invalid_block_range_to_status};

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

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        let range = read_block_range::<Status>(request.block_range, "SyncNotesRequest")?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);
        debug!(target: COMPONENT, ?request);

        check::<QueryParamNoteTagLimit>(request.note_tags.len())?;

        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let chain_tip = self.range_bounds_check(&block_range).await?;

        let (results, last_block_checked) = self
            .store
            .sync_notes(request.note_tags, block_range)
            .await
            .map_err(note_sync_error_to_status)?;
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
    let inclusion_proof = Some(proto::note::NoteInclusionInBlockProof {
        note_id: Some((&note.note_id).into()),
        block_num: note.block_num.as_u32(),
        note_index_in_block: note.note_index.leaf_index_value().into(),
        inclusion_path: Some(note.inclusion_path.into()),
    });
    proto::note::NoteSyncRecord {
        metadata: Some(note.metadata.into()),
        inclusion_proof,
    }
}

fn note_sync_error_to_status(err: NoteSyncError) -> Status {
    let message = err.to_string();
    match err {
        NoteSyncError::DatabaseError(err) => super::database_error_to_status(&err),
        NoteSyncError::InvalidBlockRange(_)
        | NoteSyncError::FutureBlock { .. }
        | NoteSyncError::DeserializationFailed(_) => Status::invalid_argument(message),
        NoteSyncError::UnderlyingDatabaseError(_)
        | NoteSyncError::EmptyBlockHeadersTable
        | NoteSyncError::MmrError(_) => Status::internal(message),
    }
}
