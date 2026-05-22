use miden_node_proto::clients::{BlockProducerClient as InnerBlockProducerClient, Builder};
use miden_node_proto::generated::{self as proto};
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::utils::serde::Serializable;
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
    #[cfg_attr(not(test), expect(dead_code))]
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

    #[instrument(target = COMPONENT, name = "ntx.block_producer.client.submit_proven_tx", skip_all, err)]
    pub async fn submit_proven_tx(&self, proven_tx: &ProvenTransaction) -> Result<(), Status> {
        let request = proto::transaction::ProvenTransaction {
            transaction: proven_tx.to_bytes(),
            transaction_inputs: None, /* Transaction inputs are only required for Validator
                                       * transaction re-execution. */
        };

        self.client.clone().submit_proven_tx(request).await?;

        Ok(())
    }
}
