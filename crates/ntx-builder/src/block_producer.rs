use std::time::Duration;

use futures::{TryStream, TryStreamExt};
use miden_node_proto::clients::{BlockProducerClient as InnerBlockProducerClient, Builder};
use miden_node_proto::domain::mempool::MempoolEvent;
use miden_node_proto::generated::{self as proto};
use miden_node_utils::FlattenResult;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::ProvenTransaction;
use miden_tx::utils::Serializable;
use tokio_stream::StreamExt;
use tonic::Status;
use tracing::{info, instrument};
use url::Url;

use crate::COMPONENT;

// CLIENT
// ================================================================================================

/// Interface to the block producer's gRPC API.
///
/// Essentially just a thin wrapper around the generated gRPC client which improves type safety.
#[derive(Clone, Debug)]
pub struct BlockProducerClient {
    client: InnerBlockProducerClient,
}

impl BlockProducerClient {
    /// Creates a new block producer client with a lazy connection.
    pub fn new(block_producer_url: Url) -> Self {
        info!(target: COMPONENT, block_producer_endpoint = %block_producer_url, "Initializing block producer client with lazy connection");

        let block_producer = Builder::new(block_producer_url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<InnerBlockProducerClient>();

        Self { client: block_producer }
    }

    #[instrument(target = COMPONENT, name = "ntx.block_producer.client.submit_proven_transaction", skip_all, err)]
    pub async fn submit_proven_transaction(
        &self,
        proven_tx: &ProvenTransaction,
    ) -> Result<(), Status> {
        let request = proto::transaction::ProvenTransaction {
            transaction: proven_tx.to_bytes(),
            transaction_inputs: None, /* Transaction inputs are only required for Validator
                                       * transaction re-execution. */
        };

        self.client.clone().submit_proven_transaction(request).await?;

        Ok(())
    }

    #[instrument(target = COMPONENT, name = "ntx.block_producer.client.subscribe_to_mempool", skip_all, err)]
    pub async fn subscribe_to_mempool_with_retry(
        &self,
        chain_tip: BlockNumber,
    ) -> Result<impl TryStream<Ok = MempoolEvent, Error = Status> + Send + 'static, Status> {
        let mut retry_counter = 0;
        loop {
            match self.subscribe_to_mempool(chain_tip).await {
                Err(err) if err.code() == tonic::Code::Unavailable => {
                    // Exponential backoff with base 500ms and max 30s.
                    let backoff = Duration::from_millis(500)
                        .saturating_mul(1 << retry_counter.min(6))
                        .min(Duration::from_secs(30));

                    tracing::warn!(
                        ?backoff,
                        %retry_counter,
                        %err,
                        "connection failed while subscribing to the mempool, retrying"
                    );

                    retry_counter += 1;
                    tokio::time::sleep(backoff).await;
                },
                result => return result,
            }
        }
    }

    async fn subscribe_to_mempool(
        &self,
        chain_tip: BlockNumber,
    ) -> Result<impl TryStream<Ok = MempoolEvent, Error = Status> + Send + 'static, Status> {
        let request =
            proto::block_producer::MempoolSubscriptionRequest { chain_tip: chain_tip.as_u32() };
        let stream = self.client.clone().mempool_subscription(request).await?;

        let stream = stream
            .into_inner()
            .map_ok(MempoolEvent::try_from)
            .map(FlattenResult::flatten_result);

        Ok(stream)
    }
}
