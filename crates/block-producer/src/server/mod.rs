use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use miden_node_store::state::{Finality, State};
use tracing::info;
use url::Url;

use crate::batch_builder::BatchBuilder;
use crate::block_builder::BlockBuilder;
use crate::errors::BlockProducerError;
use crate::mempool::{BatchBudget, BlockBudget, Mempool, MempoolConfig};
use crate::validator::BlockProducerValidatorClient;
use crate::{COMPONENT, SERVER_NUM_BATCH_BUILDERS};

#[cfg(test)]
mod tests;

/// The block producer component.
///
/// Specifies the shared store state and how to connect to validator and prover components.
pub struct BlockProducer {
    /// Shared store state used by the batch and block builders.
    pub state: Arc<State>,
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
        info!(target: COMPONENT, "Initializing block producer");
        let validator = BlockProducerValidatorClient::new(self.validator_url.clone());

        let chain_tip = self.state.chain_tip(Finality::Committed).await;

        info!(target: COMPONENT, chain_tip = %chain_tip, "Block producer initialized");

        let block_builder =
            BlockBuilder::new(Arc::clone(&self.state), validator, self.block_interval);
        let batch_builder = BatchBuilder::new(
            Arc::clone(&self.state),
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
