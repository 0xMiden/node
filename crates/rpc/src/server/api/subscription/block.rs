use std::net::IpAddr;

use futures::StreamExt;
use miden_node_proto::generated as proto;
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tonic::{Request, Status};
use tracing::{Span, debug};

use super::super::{COMPONENT, RpcService};
use super::stream::{StreamItem, SubscriptionStream};

pub struct BlockSubscriptionInput {
    request: proto::rpc::BlockSubscriptionRequest,
    client_ip: Option<IpAddr>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::BlockSubscription for RpcService {
    type Input = BlockSubscriptionInput;
    type Item = StreamItem;
    type ItemStream = SubscriptionStream;

    fn decode(request: proto::rpc::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(BlockSubscriptionInput { request, client_ip: None })
    }

    fn encode(event: Self::Item) -> tonic::Result<proto::rpc::BlockSubscriptionResponse> {
        Ok(proto::rpc::BlockSubscriptionResponse {
            block: event.data,
            committed_chain_tip: event.tip.as_u32(),
        })
    }

    async fn full(
        &self,
        request: Request<proto::rpc::BlockSubscriptionRequest>,
    ) -> tonic::Result<BlockSubscriptionResponseStream> {
        let client_ip = ClientIp::from_request(&request);
        let mut input = Self::decode(request.into_inner())?;
        input.client_ip = client_ip;
        let stream = self.handle(input).await?;
        Ok(Box::pin(stream.map(|item| item.and_then(Self::encode))))
    }

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::ItemStream> {
        let BlockSubscriptionInput { request, client_ip } = input;
        Span::current().set_attribute("block.from", request.block_from);

        debug!(target: COMPONENT, ?request);

        let from = BlockNumber::from(request.block_from);
        self.block_subscription_stream(from, client_ip)
    }
}

type BlockSubscriptionResponseStream = std::pin::Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<
                Item = Result<proto::rpc::BlockSubscriptionResponse, Status>,
            > + Send
            + 'static,
    >,
>;
