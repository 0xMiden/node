use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::Duration;

use tracing::{error, info};
use url::Url;

use crate::batch_builder::BatchBuilder;
use crate::block_builder::BlockBuilder;
use crate::errors::{BlockProducerError, StoreError};
use crate::mempool::{BatchBudget, BlockBudget, Mempool, MempoolConfig};
use crate::store::StoreClient;
use crate::validator::BlockProducerValidatorClient;
use crate::{COMPONENT, SERVER_NUM_BATCH_BUILDERS};

#[cfg(test)]
mod tests;

/// The block producer component.
///
/// Specifies how to connect to the store, batch prover, and block prover components.
/// The connection to the store is established at startup and retried with exponential backoff
/// until the store becomes available. Once the connection is established, the block producer
/// will start producing batches and blocks.
pub struct BlockProducer {
    /// The address of the store component.
    pub store_url: Url,
    /// The address of the validator component.
    pub validator_url: Url,
    /// The address of the batch prover component.
    pub batch_prover_url: Option<Url>,
    /// The interval at which to produce batches.
    pub batch_interval: Duration,
    /// The interval at which to produce blocks.
    pub block_interval: Duration,
    /// The maximum number of transactions per batch.
    pub max_txs_per_batch: usize,
    /// The maximum number of batches per block.
    pub max_batches_per_block: usize,
    /// The maximum number of inflight transactions allowed in the mempool at once.
    pub mempool_tx_capacity: NonZeroUsize,
}

// BLOCK PRODUCER
// ================================================================================================

impl BlockProducer {
    /// Runs the batch-builder and block-builder.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        info!(target: COMPONENT, store=%self.store_url, "Initializing block producer");
        let store = StoreClient::new(self.store_url.clone());
        let validator = BlockProducerValidatorClient::new(self.validator_url.clone());

        // Retry fetching the chain tip from the store until it succeeds.
        let mut retries_counter = 0;
        let chain_tip = loop {
            match store.latest_header().await {
                Err(StoreError::GrpcClientError(err)) => {
                    // exponential backoff with base 500ms and max 30s
                    let backoff = Duration::from_millis(500)
                        .saturating_mul(1 << retries_counter)
                        .min(Duration::from_secs(30));

                    error!(
                        store = %self.store_url,
                        ?backoff,
                        %retries_counter,
                        %err,
                        "store connection failed while fetching chain tip, retrying"
                    );

                    retries_counter += 1;
                    tokio::time::sleep(backoff).await;
                },
                Ok(header) => break header.block_num(),
                Err(e) => {
                    error!(target: COMPONENT, %e, "failed to fetch chain tip from store");
                    return Err(e.into());
                },
            }
        };

        info!(target: COMPONENT, chain_tip = %chain_tip, "Block producer initialized");

        let block_builder = BlockBuilder::new(store.clone(), validator, self.block_interval);
        let batch_builder = BatchBuilder::new(
            store.clone(),
            SERVER_NUM_BATCH_BUILDERS,
            self.batch_prover_url,
            self.batch_interval,
        );
        let mempool = MempoolConfig {
            batch_budget: BatchBudget {
                transactions: self.max_txs_per_batch,
                ..BatchBudget::default()
            },
            block_budget: BlockBudget { batches: self.max_batches_per_block },
            tx_capacity: self.mempool_tx_capacity,
            ..Default::default()
        };
        let mempool = Mempool::shared(chain_tip, mempool);

        // Spawn batch and block builders. These communicate indirectly via a shared mempool.
        //
        // These should run forever, so we combine them into a joinset so that if
        // any complete or fail, we can shutdown the rest (somewhat) gracefully.
        let mut tasks = tokio::task::JoinSet::new();

        let batch_builder_id = tasks
            .spawn({
                let mempool = mempool.clone();
                async { batch_builder.run(mempool).await }
            })
            .id();
        let block_builder_id = tasks
            .spawn({
                let mempool = mempool.clone();
                async { block_builder.run(mempool).await }
            })
            .id();

        let task_ids = HashMap::from([
            (batch_builder_id, "batch-builder"),
            (block_builder_id, "block-builder"),
        ]);

        // Wait for any task to end. They should run indefinitely, so this is an unexpected result.
        //
        // SAFETY: The JoinSet is definitely not empty.
        let task_result = tasks.join_next_with_id().await.unwrap();

        let task_id = match &task_result {
            Ok((id, _)) => *id,
            Err(err) => err.id(),
        };
        let task = task_ids.get(&task_id).unwrap_or(&"unknown");

        // We could abort the other tasks here, but not much point as we're probably crashing the
        // node.
        task_result
            .map_err(|source| BlockProducerError::JoinError { task, source })
            .map(|(_, result)| match result {
                Ok(_) => Err(BlockProducerError::UnexpectedTaskCompletion { task }),
                Err(source) => Err(BlockProducerError::TaskError { task, source }),
            })
            .and_then(|x| x)?
    }
}
