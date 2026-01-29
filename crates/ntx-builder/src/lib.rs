use std::num::NonZeroUsize;
use std::sync::Arc;

use actor::AccountActorContext;
use anyhow::Context;
use block_producer::BlockProducerClient;
use builder::{ChainState, MempoolEventStream};
use coordinator::Coordinator;
use futures::TryStreamExt;
use miden_node_utils::lru_cache::LruCache;
use store::StoreClient;
use tokio::sync::RwLock;
use url::Url;

mod actor;
mod block_producer;
mod builder;
mod coordinator;
mod store;

pub use builder::NetworkTransactionBuilder;

// CONSTANTS
// =================================================================================================

const COMPONENT: &str = "miden-ntx-builder";

/// Default maximum number of network notes a network transaction is allowed to consume.
const DEFAULT_MAX_NOTES_PER_TX: usize = 20;
const _: () = assert!(DEFAULT_MAX_NOTES_PER_TX <= miden_tx::MAX_NUM_CHECKER_NOTES);

/// Default maximum number of network transactions which should be in progress concurrently.
///
/// This only counts transactions which are being computed locally and does not include
/// uncommitted transactions in the mempool.
const DEFAULT_MAX_CONCURRENT_TXS: usize = 4;

/// Default maximum number of blocks to keep in the chain MMR.
const DEFAULT_MAX_BLOCK_COUNT: usize = 4;

/// Default channel capacity for account loading from the store.
const DEFAULT_ACCOUNT_CHANNEL_CAPACITY: usize = 1_000;

/// Default channel size for actor event channels.
const DEFAULT_ACTOR_CHANNEL_SIZE: usize = 100;

/// Default maximum number of attempts to execute a failing note before dropping it.
const DEFAULT_MAX_NOTE_ATTEMPTS: usize = 30;

/// Default script cache size.
const DEFAULT_SCRIPT_CACHE_SIZE: usize = 1_000;

// CONFIGURATION
// =================================================================================================

/// Configuration for the Network Transaction Builder.
///
/// This struct contains all the settings needed to create and run a `NetworkTransactionBuilder`.
#[derive(Debug, Clone)]
pub struct NtxBuilderConfig {
    /// Address of the store gRPC server (ntx-builder API).
    pub store_url: Url,

    /// Address of the block producer gRPC server.
    pub block_producer_url: Url,

    /// Address of the validator gRPC server.
    pub validator_url: Url,

    /// Address of the remote transaction prover. If `None`, transactions will be proven locally.
    pub tx_prover_url: Option<Url>,

    /// Size of the LRU cache for note scripts. Scripts are fetched from the store and cached
    /// to avoid repeated gRPC calls.
    pub script_cache_size: NonZeroUsize,

    /// Maximum number of network transactions which should be in progress concurrently across
    /// all account actors.
    pub max_concurrent_txs: usize,

    /// Maximum number of network notes a single transaction is allowed to consume.
    pub max_notes_per_tx: NonZeroUsize,

    /// Maximum number of attempts to execute a failing note before dropping it.
    /// Notes use exponential backoff between attempts.
    pub max_note_attempts: usize,

    /// Maximum number of blocks to keep in the chain MMR. Older blocks are pruned.
    pub max_block_count: usize,

    /// Channel capacity for loading accounts from the store during startup.
    pub account_channel_capacity: usize,

    /// Channel size for each actor's event channel.
    pub actor_channel_size: usize,
}

impl NtxBuilderConfig {
    pub fn new(store_url: Url, block_producer_url: Url, validator_url: Url) -> Self {
        Self {
            store_url,
            block_producer_url,
            validator_url,
            tx_prover_url: None,
            script_cache_size: NonZeroUsize::new(DEFAULT_SCRIPT_CACHE_SIZE).unwrap(),
            max_concurrent_txs: DEFAULT_MAX_CONCURRENT_TXS,
            max_notes_per_tx: NonZeroUsize::new(DEFAULT_MAX_NOTES_PER_TX).unwrap(),
            max_note_attempts: DEFAULT_MAX_NOTE_ATTEMPTS,
            max_block_count: DEFAULT_MAX_BLOCK_COUNT,
            account_channel_capacity: DEFAULT_ACCOUNT_CHANNEL_CAPACITY,
            actor_channel_size: DEFAULT_ACTOR_CHANNEL_SIZE,
        }
    }

    /// Sets the remote transaction prover URL.
    ///
    /// If not set, transactions will be proven locally.
    #[must_use]
    pub fn with_tx_prover_url(mut self, url: Option<Url>) -> Self {
        self.tx_prover_url = url;
        self
    }

    /// Sets the script cache size.
    #[must_use]
    pub fn with_script_cache_size(mut self, size: NonZeroUsize) -> Self {
        self.script_cache_size = size;
        self
    }

    /// Sets the maximum number of concurrent transactions.
    #[must_use]
    pub fn with_max_concurrent_txs(mut self, max: usize) -> Self {
        self.max_concurrent_txs = max;
        self
    }

    /// Sets the maximum number of notes per transaction.
    ///
    /// # Panics
    ///
    /// Panics if `max` exceeds `miden_tx::MAX_NUM_CHECKER_NOTES`.
    #[must_use]
    pub fn with_max_notes_per_tx(mut self, max: NonZeroUsize) -> Self {
        assert!(
            max.get() <= miden_tx::MAX_NUM_CHECKER_NOTES,
            "max_notes_per_tx ({}) exceeds MAX_NUM_CHECKER_NOTES ({})",
            max,
            miden_tx::MAX_NUM_CHECKER_NOTES
        );
        self.max_notes_per_tx = max;
        self
    }

    /// Sets the maximum number of note execution attempts.
    #[must_use]
    pub fn with_max_note_attempts(mut self, max: usize) -> Self {
        self.max_note_attempts = max;
        self
    }

    /// Sets the maximum number of blocks to keep in the chain MMR.
    #[must_use]
    pub fn with_max_block_count(mut self, max: usize) -> Self {
        self.max_block_count = max;
        self
    }

    /// Sets the account channel capacity for startup loading.
    #[must_use]
    pub fn with_account_channel_capacity(mut self, capacity: usize) -> Self {
        self.account_channel_capacity = capacity;
        self
    }

    /// Sets the actor event channel size.
    #[must_use]
    pub fn with_actor_channel_size(mut self, size: usize) -> Self {
        self.actor_channel_size = size;
        self
    }

    /// Builds and initializes the network transaction builder.
    ///
    /// This method connects to the store and block producer services, fetches the current
    /// chain tip, and subscribes to mempool events.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The store connection fails
    /// - The mempool subscription fails (after retries)
    /// - The store contains no blocks (not bootstrapped)
    pub async fn build(self) -> anyhow::Result<NetworkTransactionBuilder> {
        let script_cache = LruCache::new(self.script_cache_size);
        let coordinator = Coordinator::new(self.max_concurrent_txs, self.actor_channel_size);

        let store = StoreClient::new(self.store_url.clone());
        let block_producer = BlockProducerClient::new(self.block_producer_url.clone());

        let (chain_tip_header, chain_mmr, mempool_events) = loop {
            let (chain_tip_header, chain_mmr) = store
                .get_latest_blockchain_data_with_retry()
                .await?
                .context("store should contain a latest block")?;

            match block_producer
                .subscribe_to_mempool_with_retry(chain_tip_header.block_num())
                .await
            {
                Ok(subscription) => {
                    let stream: MempoolEventStream = Box::pin(subscription.into_stream());
                    break (chain_tip_header, chain_mmr, stream);
                },
                Err(status) if status.code() == tonic::Code::InvalidArgument => {
                    tracing::warn!(
                        err = %status,
                        "mempool subscription failed due to chain tip desync, retrying"
                    );
                },
                Err(err) => return Err(err).context("failed to subscribe to mempool events"),
            }
        };

        let chain_state = Arc::new(RwLock::new(ChainState::new(chain_tip_header, chain_mmr)));

        let actor_context = AccountActorContext {
            block_producer_url: self.block_producer_url.clone(),
            validator_url: self.validator_url.clone(),
            tx_prover_url: self.tx_prover_url.clone(),
            chain_state: chain_state.clone(),
            store: store.clone(),
            script_cache,
            max_notes_per_tx: self.max_notes_per_tx,
            max_note_attempts: self.max_note_attempts,
        };

        Ok(NetworkTransactionBuilder::new(
            self,
            coordinator,
            store,
            chain_state,
            actor_context,
            mempool_events,
        ))
    }
}
