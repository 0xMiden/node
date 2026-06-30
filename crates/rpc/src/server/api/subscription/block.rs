use std::net::IpAddr;
use std::sync::Arc;

use futures::StreamExt;
use miden_node_proto::generated as proto;
use miden_node_store::State;
use miden_node_store::state::{DataError, Finality, StreamError, SubscriptionStream};
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tokio::sync::OwnedSemaphorePermit;
use tonic::{Request, Status};
use tracing::{Span, debug};

use super::super::{COMPONENT, RpcService};
use super::{
    IpBanList,
    MAX_FUTURE_GAP_IN_SUBSCRIPTIONS,
    stream_error_to_status,
    subscription_ban_status,
};

pub struct BlockSubscriptionInput {
    request: proto::rpc::BlockSubscriptionRequest,
    client_ip: Option<IpAddr>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::BlockSubscription for RpcService {
    type Input = BlockSubscriptionInput;
    type Item = proto::rpc::BlockSubscriptionResponse;
    type ItemStream = BlockSubscriptionStream;

    fn decode(request: proto::rpc::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(BlockSubscriptionInput { request, client_ip: None })
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::rpc::BlockSubscriptionResponse> {
        Ok(item)
    }

    async fn full(
        &self,
        request: Request<proto::rpc::BlockSubscriptionRequest>,
    ) -> tonic::Result<Self::ItemStream> {
        let client_ip = ClientIp::from_request(&request);
        let mut input = Self::decode(request.into_inner())?;
        input.client_ip = client_ip;
        self.handle(input).await
    }

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::ItemStream> {
        let BlockSubscriptionInput { request, client_ip } = input;
        Span::current().set_attribute("block.from", request.block_from);

        debug!(target: COMPONENT, ?request);

        if request.block_from + MAX_FUTURE_GAP_IN_SUBSCRIPTIONS
            > self.store.chain_tip(Finality::Committed).await.as_u32()
        {
            return Err(tonic::Status::out_of_range(
                "subscription starting block exceeds committed chain tip",
            ));
        }

        // Reject clients that were recently disconnected for being too slow.
        if let Some(until) = client_ip.and_then(|ip| self.subscription_ban.banned_until(ip)) {
            return Err(subscription_ban_status(until));
        }

        let permit = Arc::clone(&self.block_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum block subscriptions reached"))?;

        let from = BlockNumber::from(request.block_from);
        let ban_list = Arc::clone(&self.subscription_ban);

        let stream = BlockStream {
            client_ip,
            ban_list,
            _permit: permit,
            store: Arc::clone(&self.store),
        };

        let stream = stream.stream(from, self.store.subscribe_committed_tip()).map(move |event| {
            event
                .map(|event| proto::rpc::BlockSubscriptionResponse {
                    block: event.data,
                    committed_chain_tip: event.tip.as_u32(),
                })
                .map_err(stream_error_to_status)
        });
        Ok(stream.boxed())
    }
}

struct BlockStream {
    client_ip: Option<IpAddr>,
    ban_list: Arc<IpBanList>,
    store: Arc<State>,
    _permit: OwnedSemaphorePermit,
}

type BlockSubscriptionStream = std::pin::Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<
                Item = Result<proto::rpc::BlockSubscriptionResponse, Status>,
            > + Send
            + 'static,
    >,
>;

impl miden_node_store::state::SubscriptionStream for BlockStream {
    fn on_eos(&self, err: &StreamError) {
        if let (Some(ip), StreamError::SlowSubscriber) = (self.client_ip, err) {
            self.ban_list.add(ip);
        }
    }

    async fn get_data(&self, block: BlockNumber) -> Result<Vec<u8>, DataError> {
        self.store
            .load_block(block)
            .await
            .map_err(|source| DataError::DatabaseError { source })?
            .ok_or(DataError::NotFound)
    }
}
