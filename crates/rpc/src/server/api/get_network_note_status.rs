use miden_node_proto::generated as proto;
use tracing::debug;

use super::{COMPONENT, RpcMode, RpcService};

#[tonic::async_trait]
impl proto::server::rpc_api::GetNetworkNoteStatus for RpcService {
    type Input = proto::note::NoteId;
    type Output = proto::rpc::GetNetworkNoteStatusResponse;

    fn decode(request: proto::note::NoteId) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::GetNetworkNoteStatusResponse> {
        Ok(output)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::Output> {
        debug!(target: COMPONENT, ?request);

        let response = match &self.mode {
            RpcMode::Sequencer { .. } => {
                let Some(ntx_builder) = &self.ntx_builder else {
                    return Err(tonic::Status::unavailable(
                        "Network transaction builder is not enabled",
                    ));
                };

                ntx_builder.clone().get_network_note_status(request).await?.into_inner()
            },
            RpcMode::FullNode { source_rpc } => {
                source_rpc.as_ref().clone().get_network_note_status(request).await?.into_inner()
            },
        };

        Ok(response)
    }
}
