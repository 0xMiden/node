use miden_node_proto::generated as proto;
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::block::BlockNumber;
use tracing::debug;

use super::super::{COMPONENT, RpcService};
use super::stream::{StreamItem, SubscriptionStream};
use crate::LOG_TARGET;

#[tonic::async_trait]
impl proto::server::rpc_api::BlockSubscription for RpcService {
    type Input = BlockNumber;
    type Item = StreamItem;
    type ItemStream = SubscriptionStream;

    fn decode(request: proto::rpc::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(BlockNumber::from(request.block_from))
    }

    fn encode(event: Self::Item) -> tonic::Result<proto::rpc::BlockSubscriptionResponse> {
        Ok(proto::rpc::BlockSubscriptionResponse {
            block: event.data,
            committed_chain_tip: event.tip.as_u32(),
        })
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "block_subscription",
        fields(
            block.from = %input,
        ),
        err,
    )]
    async fn handle(
        &self,
        input: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        let client_ip = ClientIp::from_extensions(extensions);

        debug!(target: LOG_TARGET, "Subscribing to blocks");

        let from = input;
        SubscriptionStream::blocks(self, from, client_ip)
    }
}
