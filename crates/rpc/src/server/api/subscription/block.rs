use std::pin::Pin;
use std::sync::Arc;

use futures::{Stream, TryStreamExt};
use miden_node_proto::generated as proto;
use miden_node_tracing::{debug, miden_instrument};
use miden_node_utils::grpc::ClientIp;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::utils::serde::Deserializable;

use super::super::{COMPONENT, RpcService};
use super::stream::SubscriptionStream;
use crate::LOG_TARGET;

#[tonic::async_trait]
impl proto::server::rpc_api::BlockSubscription for RpcService {
    type Input = BlockNumber;
    type Item = proto::rpc::BlockSubscriptionResponse;
    type ItemStream = Pin<Box<dyn Stream<Item = tonic::Result<Self::Item>> + Send>>;

    fn decode(request: proto::rpc::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(BlockNumber::from(request.block_from))
    }

    fn encode(event: Self::Item) -> tonic::Result<proto::rpc::BlockSubscriptionResponse> {
        Ok(event)
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "block_subscription",
        fields(
            block.from = input,
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

        let stream = SubscriptionStream::blocks(self, input, client_ip)?;
        let state = Arc::clone(&self.state);
        Ok(Box::pin(futures::stream::try_unfold(
            (stream, state, None),
            |(mut stream, state, previous)| async move {
                let Some(event) = stream.try_next().await? else {
                    return Ok(None);
                };
                let block = SignedBlock::read_from_bytes(&event.data).map_err(|err| {
                    tonic::Status::internal(format!("invalid stored block: {err}"))
                })?;
                let commitment = block.header().protocol_config_commitment();
                let protocol_config = if previous == Some(commitment) {
                    None
                } else {
                    Some(
                        super::super::load_protocol_config(&state.view(), block.header())
                            .await?
                            .into(),
                    )
                };
                let response = proto::rpc::BlockSubscriptionResponse {
                    block: Some(block.into()),
                    committed_chain_tip: event.tip.as_u32(),
                    protocol_config,
                };
                Ok(Some((response, (stream, state, Some(commitment)))))
            },
        )))
    }
}
