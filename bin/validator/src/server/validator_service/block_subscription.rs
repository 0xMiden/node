use miden_node_proto::generated as grpc;
use miden_node_proto::generated::validator::BlockSubscriptionResponse;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tokio_stream::wrappers::ReceiverStream;
use tracing::Span;

use super::ValidatorService;

type BlockStream = std::pin::Pin<
    Box<
        dyn tonic::codegen::tokio_stream::Stream<Item = tonic::Result<BlockSubscriptionResponse>>
            + Send
            + 'static,
    >,
>;

#[tonic::async_trait]
impl grpc::server::validator_api::BlockSubscription for ValidatorService {
    type Input = grpc::validator::BlockSubscriptionRequest;
    type Item = BlockSubscriptionResponse;
    type ItemStream = BlockStream;

    fn decode(request: grpc::validator::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(item: Self::Item) -> tonic::Result<Self::Item> {
        Ok(item)
    }

    async fn handle(&self, request: Self::Input) -> tonic::Result<Self::ItemStream> {
        Span::current().set_attribute("block.from", request.block_from);

        let from = BlockNumber::from(request.block_from);
        // The tip should never move since we are in recovery mode and therefore there is no active
        // sequencer.
        let tip = *self.committed_tip.subscribe().borrow();
        Span::current().set_attribute("chain.tip", tip);

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        tokio::spawn({
            let store = self.block_store.clone();
            async move {
                for block in from.as_u32()..=tip.as_u32() {
                    let response = match store.load_block(block.into()).await {
                        Ok(Some(block)) => Ok(BlockSubscriptionResponse {
                            block,
                            committed_chain_tip: tip.as_u32(),
                        }),
                        Ok(None) => {
                            Err(tonic::Status::not_found(format!("block {block} not found")))
                        },
                        Err(err) => Err(tonic::Status::internal(
                            err.as_report_context("failed to load block"),
                        )),
                    };

                    let is_err = response.is_err();

                    if tx.send(response).await.is_err() || is_err {
                        return;
                    }
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}
