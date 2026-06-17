use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use miden_node_store::state::{Finality, State};
use miden_node_utils::formatting::{format_input_notes, format_output_notes};
use miden_node_utils::tasks::Tasks;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::ProvenTransaction;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, instrument};
use url::Url;

use crate::batch_builder::BatchBuilder;
use crate::block_builder::BlockBuilder;
use crate::block_prover::BlockProver;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::MempoolSubmissionError;
use crate::mempool::{BatchBudget, BlockBudget, Mempool, MempoolConfig, SharedMempool};
use crate::validator::BlockProducerValidatorClient;
use crate::{CACHED_MEMPOOL_STATS_UPDATE_INTERVAL, COMPONENT, proof_scheduler};

#[cfg(test)]
mod tests;

/// Configuration for the in-process block producer API.
#[derive(Clone, Copy, Debug)]
pub struct BlockProducerApiConfig {
    /// The maximum number of transactions per batch.
    pub max_txs_per_batch: usize,
    /// The maximum number of batches per block.
    pub max_batches_per_block: usize,
    /// The maximum number of inflight transactions allowed in the mempool at once.
    pub mempool_tx_capacity: NonZeroUsize,
}

impl Default for BlockProducerApiConfig {
    fn default() -> Self {
        Self {
            max_txs_per_batch: crate::DEFAULT_MAX_TXS_PER_BATCH,
            max_batches_per_block: crate::DEFAULT_MAX_BATCHES_PER_BLOCK,
            mempool_tx_capacity: crate::DEFAULT_MEMPOOL_TX_CAPACITY,
        }
    }
}

impl BlockProducerApiConfig {
    fn mempool_config(self) -> MempoolConfig {
        MempoolConfig {
            batch_budget: BatchBudget {
                transactions: self.max_txs_per_batch,
                ..BatchBudget::default()
            },
            block_budget: BlockBudget { batches: self.max_batches_per_block },
            tx_capacity: self.mempool_tx_capacity,
            ..Default::default()
        }
    }
}

/// The sequencer runtime configuration.
///
/// Specifies how to connect to the batch prover and block prover components.
pub struct Sequencer {
    /// The store state shared with the block producer.
    pub store: Arc<State>,
    /// The address of the validator component.
    pub validator_url: Url,
    /// The request timeout for calls to the validator component.
    pub validator_timeout: Duration,
    /// The address of the batch prover component.
    pub batch_prover_url: Option<Url>,
    /// The address of the block prover component.
    pub block_prover_url: Option<Url>,
    /// The interval at which to produce batches.
    pub batch_interval: Duration,
    /// The interval at which to produce blocks.
    pub block_interval: Duration,
    /// The maximum number of transactions per batch.
    pub max_txs_per_batch: usize,
    /// The maximum number of batches per block.
    pub max_batches_per_block: usize,
    /// The maximum number of concurrent block proofs to schedule.
    pub max_concurrent_proofs: NonZeroUsize,

    /// The maximum number of inflight transactions allowed in the mempool at once.
    pub mempool_tx_capacity: NonZeroUsize,

    /// The number of concurrent batch-builder workers.
    pub batch_workers: NonZeroUsize,
}

// BLOCK PRODUCER
// ================================================================================================

impl Sequencer {
    /// Spawns the sequencer tasks and returns its in-process API.
    pub async fn spawn(self) -> Result<SequencerHandle> {
        info!(target: COMPONENT, "Initializing sequencer");
        let store = self.store;
        let validator =
            BlockProducerValidatorClient::new(self.validator_url.clone(), self.validator_timeout)?;
        let chain_tip = store.chain_tip(Finality::Committed).await;

        info!(target: COMPONENT, "Sequencer initialized");

        let block_builder = BlockBuilder::new(Arc::clone(&store), validator, self.block_interval);
        let batch_builder = BatchBuilder::new(
            Arc::clone(&store),
            self.batch_workers,
            self.batch_prover_url,
            self.batch_interval,
        );
        let api_config = BlockProducerApiConfig {
            max_txs_per_batch: self.max_txs_per_batch,
            max_batches_per_block: self.max_batches_per_block,
            mempool_tx_capacity: self.mempool_tx_capacity,
        };
        let mempool = Mempool::shared(chain_tip, api_config.mempool_config());
        let api = BlockProducerApi::from_shared_mempool(mempool.clone(), store);
        let block_prover = if let Some(url) = self.block_prover_url {
            Arc::new(BlockProver::remote(url))
        } else {
            Arc::new(BlockProver::local())
        };
        let chain_tip_rx = api.store.subscribe_committed_tip();

        // Spawn batch builder, block builder, and proof scheduler. The builders communicate
        // indirectly via a shared mempool.
        //
        // These should run forever, so if any complete or fail, the sequencer reports the failure
        // and aborts the rest when the task set is dropped.
        let mut tasks = Tasks::new();

        tasks.spawn("batch-builder", {
            let mempool = mempool.clone();
            async { batch_builder.run(mempool).await }
        });
        tasks.spawn("block-builder", {
            let mempool = mempool.clone();
            async { block_builder.run(mempool).await }
        });
        tasks.spawn("proof-scheduler", {
            let store = Arc::clone(&api.store);
            async move {
                proof_scheduler::run(block_prover, store, chain_tip_rx, self.max_concurrent_proofs)
                    .await
            }
        });
        let task = tokio::spawn(async move { tasks.join_next_as_error().await });

        Ok(SequencerHandle { api, task })
    }

    /// Serves the sequencer tasks.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        self.spawn().await?.wait().await
    }
}

/// Running sequencer tasks plus the API used to submit work to them.
pub struct SequencerHandle {
    api: BlockProducerApi,
    task: JoinHandle<anyhow::Result<()>>,
}

impl SequencerHandle {
    /// Returns a cloneable handle to the block producer API.
    pub fn api(&self) -> BlockProducerApi {
        self.api.clone()
    }

    /// Waits for the sequencer tasks to end.
    pub async fn wait(self) -> anyhow::Result<()> {
        self.task.await?
    }
}

// BLOCK PRODUCER API
// ================================================================================================

/// In-process block producer API used by the RPC layer.
#[derive(Clone)]
pub struct BlockProducerApi {
    /// The mutex effectively rate limits incoming transactions into the mempool by forcing them
    /// through a queue.
    ///
    /// This gives mempool users such as the batch and block builders equal footing with __all__
    /// incoming transactions combined. Without this incoming transactions would greatly restrict
    /// the block-producers usage of the mempool.
    mempool: Arc<Mutex<SharedMempool>>,

    store: Arc<State>,

    /// Cached mempool statistics that are updated periodically to avoid locking the mempool for
    /// each status request.
    cached_mempool_stats: Arc<RwLock<MempoolStats>>,
}

impl std::fmt::Debug for BlockProducerApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockProducerApi").finish_non_exhaustive()
    }
}

/// Current block producer status.
#[derive(Clone, Debug)]
pub struct BlockProducerStatus {
    /// The block producer crate version.
    pub version: String,
    /// Human-readable status string.
    pub status: String,
    /// The mempool's current view of the chain tip height.
    pub chain_tip: BlockNumber,
    /// Cached mempool statistics.
    pub mempool_stats: MempoolStats,
}

impl BlockProducerApi {
    /// Creates an API backed by a fresh mempool.
    pub fn new(store: Arc<State>, chain_tip: BlockNumber, config: BlockProducerApiConfig) -> Self {
        Self::from_shared_mempool(Mempool::shared(chain_tip, config.mempool_config()), store)
    }

    fn from_shared_mempool(mempool: SharedMempool, store: Arc<State>) -> Self {
        let cached_mempool_stats = mempool
            .lock()
            .map(|mempool| MempoolStats::from_mempool(&mempool))
            .unwrap_or_default();
        let api = Self {
            mempool: Arc::new(Mutex::new(mempool)),
            store,
            cached_mempool_stats: Arc::new(RwLock::new(cached_mempool_stats)),
        };
        api.spawn_mempool_stats_updater();
        api
    }

    /// Starts a background task that periodically updates the cached mempool statistics.
    ///
    /// This prevents the need to lock the mempool for each status request.
    fn spawn_mempool_stats_updater(&self) {
        let cached_mempool_stats = Arc::clone(&self.cached_mempool_stats);
        let mempool = Arc::clone(&self.mempool);

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        handle.spawn(async move {
            let mempool = mempool.lock().await.clone();
            let mut interval = tokio::time::interval(CACHED_MEMPOOL_STATS_UPDATE_INTERVAL);

            loop {
                interval.tick().await;

                let stats = {
                    let Ok(mempool) = mempool.lock() else {
                        tracing::error!("mempool lock poisoned, stopping mempool stats updater");
                        return;
                    };
                    MempoolStats::from_mempool(&mempool)
                };

                let mut cache = cached_mempool_stats.write().await;
                *cache = stats;
            }
        });
    }

    // ENDPOINTS
    // --------------------------------------------------------------------------------------------

    #[instrument(
         target = COMPONENT,
         name = "block_producer.api.submit_proven_tx",
         skip_all,
         err
     )]
    #[expect(clippy::let_and_return)]
    pub async fn submit_proven_tx(
        &self,
        tx: ProvenTransaction,
    ) -> Result<BlockNumber, MempoolSubmissionError> {
        let tx_id = tx.id();

        debug!(
            target: COMPONENT,
            tx_id = %tx_id.to_hex(),
            account_id = %tx.account_id().to_hex(),
            initial_state_commitment = %tx.account_update().initial_state_commitment(),
            final_state_commitment = %tx.account_update().final_state_commitment(),
            input_notes = %format_input_notes(tx.input_notes()),
            output_notes = %format_output_notes(tx.output_notes()),
            ref_block_commitment = %tx.ref_block_commitment(),
            "Submitting transaction"
        );
        debug!(target: COMPONENT, proof = ?tx.proof());

        let inputs = crate::store::get_tx_inputs(&self.store, &tx)
            .await
            .map_err(MempoolSubmissionError::StoreStateReadFailed)?;

        // SAFETY: we assume that the rpc component has verified the transaction proof already.
        let tx = AuthenticatedTransaction::new_unchecked(Arc::new(tx), inputs)
            .map(Arc::new)
            .map_err(MempoolSubmissionError::StateConflict)?;

        let shared_mempool = self.mempool.lock().await;
        // We need the let binding here to avoid E0597 `shared_mempool` does not live long enough
        let result = shared_mempool
            .lock()
            .map_err(MempoolSubmissionError::MempoolPoisoned)?
            .add_transaction(tx);
        result
    }

    #[instrument(
         target = COMPONENT,
         name = "block_producer.api.submit_proven_tx_batch",
         skip_all,
         err
     )]
    #[expect(clippy::let_and_return)]
    pub async fn submit_proven_tx_batch(
        &self,
        batch: ProposedBatch,
    ) -> Result<BlockNumber, MempoolSubmissionError> {
        // We assume that the rpc component has verified everything, including the transaction
        // proofs.

        let mut txs = Vec::with_capacity(batch.transactions().len());
        for tx in batch.transactions() {
            let inputs = crate::store::get_tx_inputs(&self.store, tx)
                .await
                .map_err(MempoolSubmissionError::StoreStateReadFailed)?;

            // SAFETY: We assume that the rpc component has verified the transaction proofs, as well
            // as the batch integrity itself.
            let tx = AuthenticatedTransaction::new_unchecked(Arc::clone(tx), inputs)
                .map(Arc::new)
                .map_err(MempoolSubmissionError::StateConflict)?;
            txs.push(tx);
        }

        let shared_mempool = self.mempool.lock().await;
        // We need the let binding here to avoid E0597 `shared_mempool` does not live long enough
        let result = shared_mempool
            .lock()
            .map_err(MempoolSubmissionError::MempoolPoisoned)?
            .add_user_batch(&txs);
        result
    }

    pub async fn status(&self) -> BlockProducerStatus {
        let mempool_stats = *self.cached_mempool_stats.read().await;

        BlockProducerStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: "connected".to_string(),
            chain_tip: mempool_stats.chain_tip,
            mempool_stats,
        }
    }
}

// MEMPOOL STATISTICS
// ================================================================================================

/// Mempool statistics that are updated periodically to avoid locking the mempool.
#[derive(Clone, Copy, Debug, Default)]
pub struct MempoolStats {
    /// The mempool's current view of the chain tip height.
    pub chain_tip: BlockNumber,
    /// Number of transactions currently in the mempool waiting to be batched.
    pub unbatched_transactions: u64,
    /// Number of batches currently being proven.
    pub proposed_batches: u64,
    /// Number of proven batches waiting for block inclusion.
    pub proven_batches: u64,
}

impl MempoolStats {
    fn from_mempool(mempool: &Mempool) -> Self {
        Self {
            chain_tip: mempool.chain_tip(),
            unbatched_transactions: mempool.unbatched_transactions_count() as u64,
            proposed_batches: mempool.proposed_batches_count() as u64,
            proven_batches: mempool.proven_batches_count() as u64,
        }
    }
}
