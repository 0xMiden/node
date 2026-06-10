use miden_node_proto::generated as proto;
use tonic::Request;
use tonic::metadata::{Ascii, MetadataValue};
use tracing::debug;

use super::{COMPONENT, RpcMode, RpcService};

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

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        let GetNetworkNoteStatusInput { request, original_accept_header } = request;

        debug!(target: COMPONENT, ?request);

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
