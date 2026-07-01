use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use miden_node_proto::generated as grpc;
use miden_node_proto::generated::validator::BlockSubscriptionResponse;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::block::BlockNumber;
use tokio::sync::OwnedRwLockWriteGuard;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tonic::codegen::tokio_stream::Stream;
use tracing::Span;

use super::ValidatorService;

type BlockStream =
    Pin<Box<dyn Stream<Item = tonic::Result<BlockSubscriptionResponse>> + Send + 'static>>;

struct BackupBlockStream {
    inner: ReceiverStream<tonic::Result<BlockSubscriptionResponse>>,
    _guard: OwnedRwLockWriteGuard<()>,
}

impl Stream for BackupBlockStream {
    type Item = tonic::Result<BlockSubscriptionResponse>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}

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

        let committed_tip = self.committed_tip.borrow().as_u32();
        if request.block_from > committed_tip {
            return Err(Status::out_of_range(
                "subscriber's requested starting block should be <= the committed chain tip",
            ));
        }

        // Hold the exclusive backup lock for the entire lifetime of the stream. While a backup
        // subscription is active no other RPCs may run, and vice versa.
        let guard = Arc::clone(&self.serve_lock).try_write_owned().map_err(|_| {
            Status::resource_exhausted("cannot stream backup while validator is serving requests")
        })?;

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
                        }
                        Err(err) => Err(tonic::Status::internal(
                            err.as_report_context("failed to load block"),
                        )),
                    }.inspect_err(|err| {
                        tracing::error!(block.number = %block, message = %err.message(), "failed to load block in validator recovery stream");
                    });

                    // Errors are not recoverable so we abort the stream after informing the client.
                    //
                    // Also exit if the client closed the stream.
                    //
                    // Note that the condition ordering is deliberate; otherwise `is_err` would short-circuit
                    // and prevent the sending of the error response.
                    let is_err = response.is_err();
                    if tx.send(response).await.is_err() || is_err {
                        tracing::info!("validator recovery stream closing");
                        return;
                    }
                }
            }
        });

        Ok(Box::pin(BackupBlockStream {
            inner: ReceiverStream::new(rx),
            _guard: guard,
        }))
    }
}
