use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use miden_node_proto::generated::{self as proto};
use miden_node_utils::formatting::{format_input_notes, format_output_notes};
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::utils::serde::Deserializable;
use tokio::sync::{Mutex, RwLock};
use tokio::task::{Id, JoinSet};
use tracing::{debug, error, info, instrument};
use url::Url;

use crate::batch_builder::BatchBuilder;
use crate::block_builder::BlockBuilder;
use crate::domain::transaction::AuthenticatedTransaction;
use crate::errors::{BlockProducerError, MempoolSubmissionError, StoreError};
use crate::mempool::{BatchBudget, BlockBudget, Mempool, MempoolConfig, SharedMempool};
use crate::store::StoreClient;
use crate::validator::BlockProducerValidatorClient;
use crate::{CACHED_MEMPOOL_STATS_UPDATE_INTERVAL, COMPONENT, SERVER_NUM_BATCH_BUILDERS};

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

/// The block producer runtime.
///
/// Specifies how to connect to the store, batch prover, and block prover components.
/// The connection to the store is established at startup and retried with exponential backoff
/// until the store becomes available. Once the connection is established, the block producer
/// starts its batch and block builders.
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
    /// Starts the block producer and returns its in-process API.
    ///
    /// The returned handle owns the batch and block builder tasks. Dropping the handle stops those
    /// tasks.
    pub async fn start(self) -> Result<BlockProducerRuntime> {
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

        info!(target: COMPONENT, "Block producer initialized");

        let block_builder = BlockBuilder::new(store.clone(), validator, self.block_interval);
        let batch_builder = BatchBuilder::new(
            store.clone(),
            SERVER_NUM_BATCH_BUILDERS,
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

        // Spawn batch and block builders. These communicate indirectly via a shared mempool.
        //
        // These should run forever, so we combine them into a joinset so that if
        // any complete or fail, we can shutdown the rest (somewhat) gracefully.
        let mut tasks = JoinSet::new();

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

        Ok(BlockProducerRuntime { api, tasks, task_ids })
    }

    /// Serves the block producer's batch-builder and block-builder tasks.
    ///
    /// Executes in place (i.e. not spawned) and will run indefinitely until a fatal error is
    /// encountered.
    pub async fn serve(self) -> anyhow::Result<()> {
        self.start().await?.wait().await
    }
}

/// Running block producer tasks plus the API used to submit work to them.
pub struct BlockProducerRuntime {
    api: BlockProducerApi,
    tasks: JoinSet<anyhow::Result<()>>,
    task_ids: HashMap<Id, &'static str>,
}

impl BlockProducerRuntime {
    /// Returns a cloneable handle to the block producer API.
    pub fn api(&self) -> BlockProducerApi {
        self.api.clone()
    }

    /// Waits for the block producer runtime to end.
    ///
    /// The batch and block builder tasks should run indefinitely, so this returns an error when any
    /// task completes.
    pub async fn wait(mut self) -> anyhow::Result<()> {
        // Wait for any task to end. They should run indefinitely, so this is an unexpected result.
        //
        // SAFETY: The JoinSet is definitely not empty.
        let task_result = self.tasks.join_next_with_id().await.unwrap();

        let task_id = match &task_result {
            Ok((id, _)) => *id,
            Err(err) => err.id(),
        };
        let task = self.task_ids.get(&task_id).copied().unwrap_or("unknown");

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

// BLOCK PRODUCER API
// ================================================================================================

/// In-process block producer API used by the RPC layer.
#[derive(Clone, Debug)]
pub struct BlockProducerApi {
    /// The mutex effectively rate limits incoming transactions into the mempool by forcing them
    /// through a queue.
    ///
    /// This gives mempool users such as the batch and block builders equal footing with __all__
    /// incoming transactions combined. Without this incoming transactions would greatly restrict
    /// the block-producers usage of the mempool.
    mempool: Arc<Mutex<SharedMempool>>,

    store: StoreClient,

    /// Cached mempool statistics that are updated periodically to avoid locking the mempool for
    /// each status request.
    cached_mempool_stats: Arc<RwLock<MempoolStats>>,
}

impl BlockProducerApi {
    /// Creates an API backed by a fresh mempool.
    pub fn new(store: StoreClient, chain_tip: BlockNumber, config: BlockProducerApiConfig) -> Self {
        Self::from_shared_mempool(Mempool::shared(chain_tip, config.mempool_config()), store)
    }

    fn from_shared_mempool(mempool: SharedMempool, store: StoreClient) -> Self {
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
         name = "block_producer.server.submit_proven_tx",
         skip_all,
         err
     )]
    #[expect(clippy::let_and_return)]
    pub async fn submit_proven_tx(
        &self,
        request: proto::transaction::ProvenTransaction,
    ) -> Result<proto::blockchain::BlockNumber, MempoolSubmissionError> {
        debug!(target: COMPONENT, ?request);

        let tx = ProvenTransaction::read_from_bytes(&request.transaction)
            .map_err(MempoolSubmissionError::DeserializationFailed)?;

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
            "Deserialized transaction"
        );
        debug!(target: COMPONENT, proof = ?tx.proof());

        let inputs = self
            .store
            .get_tx_inputs(&tx)
            .await
            .map_err(MempoolSubmissionError::StoreConnectionFailed)?;

        // SAFETY: we assume that the rpc component has verified the transaction proof already.
        let tx = AuthenticatedTransaction::new_unchecked(Arc::new(tx), inputs)
            .map(Arc::new)
            .map_err(MempoolSubmissionError::StateConflict)?;

        let shared_mempool = self.mempool.lock().await;
        // We need the let binding here to avoid E0597 `shared_mempool` does not live long enough
        let result = shared_mempool
            .lock()
            .map_err(MempoolSubmissionError::MempoolPoisoned)?
            .add_transaction(tx)
            .map(Into::into);
        result
    }

    #[instrument(
         target = COMPONENT,
         name = "block_producer.server.submit_proven_tx_batch",
         skip_all,
         err
     )]
    #[expect(clippy::let_and_return)]
    pub async fn submit_proven_tx_batch(
        &self,
        request: proto::transaction::TransactionBatch,
    ) -> Result<proto::blockchain::BlockNumber, MempoolSubmissionError> {
        let proposed =
            request.proposed_batch.ok_or(MempoolSubmissionError::MissingProposedBatch)?;
        let batch = ProposedBatch::read_from_bytes(&proposed)
            .map_err(MempoolSubmissionError::DeserializationFailed)?;

        // We assume that the rpc component has verified everything, including the transaction
        // proofs.

        let mut txs = Vec::with_capacity(batch.transactions().len());
        for tx in batch.transactions() {
            let inputs = self
                .store
                .get_tx_inputs(tx)
                .await
                .map_err(MempoolSubmissionError::StoreConnectionFailed)?;

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
            .add_user_batch(&txs)
            .map(Into::into);
        result
    }

    pub async fn status(&self) -> proto::rpc::BlockProducerStatus {
        let mempool_stats = *self.cached_mempool_stats.read().await;

        proto::rpc::BlockProducerStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: "connected".to_string(),
            chain_tip: mempool_stats.chain_tip.as_u32(),
            mempool_stats: Some(mempool_stats.into()),
        }
    }
}

// MEMPOOL STATISTICS
// ================================================================================================

/// Mempool statistics that are updated periodically to avoid locking the mempool.
#[derive(Clone, Copy, Debug, Default)]
struct MempoolStats {
    /// The mempool's current view of the chain tip height.
    chain_tip: BlockNumber,
    /// Number of transactions currently in the mempool waiting to be batched.
    unbatched_transactions: u64,
    /// Number of batches currently being proven.
    proposed_batches: u64,
    /// Number of proven batches waiting for block inclusion.
    proven_batches: u64,
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

impl From<MempoolStats> for proto::rpc::MempoolStats {
    fn from(stats: MempoolStats) -> Self {
        proto::rpc::MempoolStats {
            unbatched_transactions: stats.unbatched_transactions,
            proposed_batches: stats.proposed_batches,
            proven_batches: stats.proven_batches,
        }
    }
}
