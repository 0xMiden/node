use miden_node_proto::generated as proto;
use miden_node_utils::tracing::{miden_instrument, miden_span_record};
use miden_protocol::Word;
use tonic::Request;
use tracing::debug;

use super::{RpcBackend, RpcService};
use crate::{COMPONENT, LOG_TARGET};

#[tonic::async_trait]
impl proto::server::rpc_api::GetNetworkNoteStatus for RpcService {
    type Input = miden_protocol::note::NoteId;
    type Output = proto::rpc::GetNetworkNoteStatusResponse;

    fn decode(request: proto::note::NoteId) -> tonic::Result<Self::Input> {
        let note_id_digest: Word = request
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

        tracing::trace!(target: LOG_TARGET, ?request);

        let note_id = request;
        miden_span_record!(
            note.id = %note_id,
        );

        debug!(target: LOG_TARGET, "Getting network note status");

        let mut forwarded_request = Request::new(note_id.as_word().into());
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

                ntx_builder
                    .clone()
                    .get_network_note_status(forwarded_request)
                    .await?
                    .into_inner()
            },
            RpcBackend::FullNode { source_rpc, .. } => source_rpc
                .as_ref()
                .clone()
                .get_network_note_status(forwarded_request)
                .await?
                .into_inner(),
        };

        Ok(response)
    }
}
