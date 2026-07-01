use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use miden_node_proto::generated as proto;
use miden_node_store::State;
use miden_node_utils::grpc::ClientIp;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tokio::sync::OwnedSemaphorePermit;
use tonic::{Request, Status};
use tracing::{Span, debug};

use super::super::{COMPONENT, RpcService};
use super::stream::{DataError, StreamError, Subscription};
use super::{IpBanList, subscription_ban_status};

pub struct ProofSubscriptionInput {
    request: proto::rpc::ProofSubscriptionRequest,
    client_ip: Option<IpAddr>,
}

#[tonic::async_trait]
impl proto::server::rpc_api::ProofSubscription for RpcService {
    type Input = ProofSubscriptionInput;
    type Item = proto::rpc::ProofSubscriptionResponse;
    type ItemStream = ProofSubscriptionStream;

    fn decode(request: proto::rpc::ProofSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(ProofSubscriptionInput { request, client_ip: None })
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::rpc::ProofSubscriptionResponse> {
        Ok(item)
    }

    async fn full(
        &self,
        request: Request<proto::rpc::ProofSubscriptionRequest>,
    ) -> tonic::Result<Self::ItemStream> {
        let client_ip = ClientIp::from_request(&request);
        let mut input = Self::decode(request.into_inner())?;
        input.client_ip = client_ip;
        self.handle(input).await
    }

    async fn handle(&self, input: Self::Input) -> tonic::Result<Self::ItemStream> {
        let ProofSubscriptionInput { request, client_ip } = input;
        Span::current().set_attribute("block.from", request.block_from);

        debug!(target: COMPONENT, ?request);

        // Reject clients that were recently disconnected for being too slow.
        if let Some(until) = client_ip.and_then(|ip| self.subscription_ban.banned_until(ip)) {
            return Err(subscription_ban_status(until));
        }

        let permit = Arc::clone(&self.proof_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum proof subscriptions reached"))?;

        let from = BlockNumber::from(request.block_from);
        let ban_list = Arc::clone(&self.subscription_ban);

        let stream = ProofStream {
            client_ip,
            ban_list,
            _permit: permit,
            store: Arc::clone(&self.store),
        };

        let stream =
            stream
                .into_stream(from, self.store.subscribe_proven_tip())
                .await?
                .map(move |event| {
                    event.map(|event| proto::rpc::ProofSubscriptionResponse {
                        block_num: event.block.as_u32(),
                        proof: event.data,
                        proven_chain_tip: event.tip.as_u32(),
                    })
                });
        Ok(stream.boxed())
    }
}

struct ProofStream {
    client_ip: Option<IpAddr>,
    ban_list: Arc<IpBanList>,
    store: Arc<State>,
    _permit: OwnedSemaphorePermit,
}

type ProofSubscriptionStream = Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<
                Item = Result<proto::rpc::ProofSubscriptionResponse, Status>,
            > + Send
            + 'static,
    >,
>;

impl Subscription for ProofStream {
    fn on_eos(&self, err: StreamError) {
        if let (Some(ip), StreamError::SlowSubscriber) = (self.client_ip, err) {
            self.ban_list.add(ip);
        }
    }

    async fn get_data(&self, block: BlockNumber) -> Result<Vec<u8>, DataError> {
        self.store
            .load_proof(block)
            .await
            .map_err(|source| DataError::DatabaseError { source })?
            .ok_or(DataError::NotFound)
    }
}
