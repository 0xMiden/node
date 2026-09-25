use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument, miden_span_record};
use miden_protocol::Word;
use tonic::Request;

use super::{RpcBackend, RpcService};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::GetNetworkNoteStatus for RpcService {
    type Input = miden_protocol::note::NoteId;
    type Output = proto::rpc::GetNetworkNoteStatusResponse;

    fn decode(request: proto::rpc::GetNetworkNoteStatusRequest) -> tonic::Result<Self::Input> {
        let note_id_digest: Word = request
            .note_id
            .as_ref()
            .ok_or_else(|| tonic::Status::invalid_argument("missing note ID"))?
            .id
            .as_ref()
            .ok_or_else(|| tonic::Status::invalid_argument("missing note ID digest"))?
            .try_into()
            .map_err(|_| tonic::Status::invalid_argument("invalid note ID digest"))?;
        Ok(miden_protocol::note::NoteId::from_raw(note_id_digest))
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::GetNetworkNoteStatusResponse> {
        Ok(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "get_network_note_status",
        err,
    )]
    async fn handle(
        &self,
        request: Self::Input,
        metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        let original_accept_header = metadata.get(http::header::ACCEPT.as_str()).cloned();

        let note_id = request;
        miden_span_record!(note.id = note_id);

        debug!(
            target: LOG_TARGET,
            "Getting network note status",
            note.id = note_id
        );

        let mut forwarded_request = Request::new(proto::note::NoteId::from(note_id.as_word()));
        if let Some(accept) = original_accept_header {
            forwarded_request.metadata_mut().insert(http::header::ACCEPT.as_str(), accept);
        }

        let response = match &self.backend {
            RpcBackend::Sequencer { .. } => {
                let Some(ntx_builder) = &self.ntx_builder else {
                    return Err(tonic::Status::unavailable(
                        "Network transaction builder is not enabled",
                    ));
                };

                let response = ntx_builder
                    .clone()
                    .get_network_note_status(forwarded_request.map(|note_id| {
                        proto::ntx_builder::GetNetworkNoteStatusRequest { note_id: Some(note_id) }
                    }))
                    .await?
                    .into_inner();
                proto::rpc::GetNetworkNoteStatusResponse {
                    status: response.status,
                    last_error: response.last_error,
                    attempt_count: response.attempt_count,
                    last_attempt_block_num: response.last_attempt_block_num,
                }
            },
            RpcBackend::FullNode { source_rpc, .. } => source_rpc
                .as_ref()
                .clone()
                .get_network_note_status(forwarded_request.map(|note_id| {
                    proto::rpc::GetNetworkNoteStatusRequest { note_id: Some(note_id) }
                }))
                .await?
                .into_inner(),
        };

        Ok(response)
    }
}
