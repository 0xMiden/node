use miden_node_proto::generated as proto;
use miden_node_utils::tracing::{miden_instrument, miden_span_record};
use miden_protocol::Word;
use tonic::Request;
use tonic::metadata::{Ascii, MetadataValue};
use tracing::debug;

use super::{RpcMode, RpcService};
use crate::{COMPONENT, LOG_TARGET};

pub struct GetNetworkNoteStatusInput {
    request: proto::note::NoteId,
    original_accept_header: Option<MetadataValue<Ascii>>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::GetNetworkNoteStatus for RpcService {
    type Input = GetNetworkNoteStatusInput;
    type Output = proto::rpc::GetNetworkNoteStatusResponse;

    fn decode(request: proto::note::NoteId) -> tonic::Result<Self::Input> {
        Ok(GetNetworkNoteStatusInput { request, original_accept_header: None })
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::GetNetworkNoteStatusResponse> {
        Ok(output)
    }

    async fn full(&self, request: Request<proto::note::NoteId>) -> tonic::Result<Self::Output> {
        let original_accept_header = request.metadata().get(http::header::ACCEPT.as_str()).cloned();
        let mut input = Self::decode(request.into_inner())?;
        input.original_accept_header = original_accept_header;

        let output = self.handle(input).await?;
        Self::encode(output)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "get_network_note_status",
        skip_all,
        err,
    )]
    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        let GetNetworkNoteStatusInput { request, original_accept_header } = request;

        tracing::trace!(target: LOG_TARGET, ?request);

        let note_id_digest: Word = request
            .id
            .as_ref()
            .ok_or_else(|| tonic::Status::invalid_argument("missing note ID digest"))?
            .try_into()
            .map_err(|_| tonic::Status::invalid_argument("invalid note ID digest"))?;
        let note_id = miden_protocol::note::NoteId::from_raw(note_id_digest);
        miden_span_record!(
            note.id = %note_id,
        );

        debug!(target: LOG_TARGET, "Getting network note status");

        let mut forwarded_request = Request::new(request);
        if let Some(accept) = original_accept_header {
            forwarded_request.metadata_mut().insert(http::header::ACCEPT.as_str(), accept);
        }

        let response = match &self.mode {
            RpcMode::Sequencer { .. } => {
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
            RpcMode::FullNode { source_rpc, .. } => source_rpc
                .as_ref()
                .clone()
                .get_network_note_status(forwarded_request)
                .await?
                .into_inner(),
        };

        Ok(response)
    }
}
