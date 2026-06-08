use miden_node_proto::decode::read_block_range;
use miden_node_proto::generated as proto;
use miden_node_utils::limiter::QueryParamNoteTagLimit;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use tonic::Status;
use tracing::{Span, debug};

use super::{
    COMPONENT,
    Finality,
    RpcInvalidBlockRange,
    RpcService,
    check,
    invalid_block_range_to_status,
    note_sync_error_to_status,
    note_sync_record_to_proto,
};

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
        let chain_tip = self.store.chain_tip(Finality::Committed).await;
        if *block_range.end() > chain_tip {
            return Err(Status::invalid_argument(format!(
                "block_to ({}) is greater than chain tip ({chain_tip})",
                block_range.end()
            )));
        }

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
