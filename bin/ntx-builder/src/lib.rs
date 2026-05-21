use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use actor::{AccountActorContext, ActorConfig, GrpcClients, State};
use anyhow::Context;
use builder::BlockStream;
use chain_state::{ChainState, SharedChainState};
use clients::{BlockProducerClient, StoreClient, ValidatorClient};
use coordinator::Coordinator;
use db::Db;
use futures::StreamExt;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_remote_prover_client::RemoteTransactionProver;
use tokio::sync::mpsc;
use url::Url;

use crate::committed_block::CommittedBlockEffects;

pub(crate) type NoteError = Arc<dyn ErrorReport + Send + Sync>;

mod actor;
mod builder;
mod chain_state;
mod clients;
mod committed_block;
mod coordinator;
pub(crate) mod db;
pub mod server;

#[cfg(test)]
pub(crate) mod test_utils;

pub use builder::NetworkTransactionBuilder;

// CONSTANTS
// =================================================================================================

const COMPONENT: &str = "miden-ntx-builder";

/// Default maximum number of network notes a network transaction is allowed to consume.
const DEFAULT_MAX_NOTES_PER_TX: NonZeroUsize = NonZeroUsize::new(20).expect("literal is non-zero");
const _: () = assert!(DEFAULT_MAX_NOTES_PER_TX.get() <= miden_tx::MAX_NUM_CHECKER_NOTES);

/// Default maximum number of network transactions which should be in progress concurrently.
///
/// This only counts transactions which are being computed locally and does not include
/// uncommitted transactions in the mempool.
const DEFAULT_MAX_CONCURRENT_TXS: usize = 4;

/// Default maximum number of blocks to keep in the chain MMR.
const DEFAULT_MAX_BLOCK_COUNT: usize = 4;

/// Default maximum number of attempts to execute a failing note before dropping it.
const DEFAULT_MAX_NOTE_ATTEMPTS: usize = 30;

/// Default script cache size.
const DEFAULT_SCRIPT_CACHE_SIZE: NonZeroUsize =
    NonZeroUsize::new(1_000).expect("literal is non-zero");

/// Default duration after which an idle network account actor will deactivate.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Default maximum number of crashes an account actor is allowed before being deactivated.
const DEFAULT_MAX_ACCOUNT_CRASHES: usize = 10;

/// Default initial sleep applied between per-request retries on transient infrastructure failures
/// (downed prover, transport error, validator/block-producer crash, store gRPC hiccup). Doubles on
/// each retry up to [`DEFAULT_REQUEST_BACKOFF_MAX`].
const DEFAULT_REQUEST_BACKOFF_INITIAL: Duration = Duration::from_millis(100);

/// Default upper bound on the per-request retry backoff sleep.
const DEFAULT_REQUEST_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Default maximum number of VM execution cycles allowed for a network transaction.
///
/// This limits the computational cost of network transactions. The protocol maximum is
/// `1 << 29` but network transactions should be much cheaper.
const DEFAULT_MAX_TX_CYCLES: u32 = 1 << 19;

/// Default number of blocks after which a submitted network transaction expires.
///
/// Short expiry means: if a tx doesn't get included into a block within this many blocks of
/// the chain tip at submission time, it is dropped. The ntx-builder can then construct a new tx
/// without waiting on the mempool to time out.
const DEFAULT_TX_EXPIRATION_DELTA: u16 = 5;

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

    /// Size of the LRU cache for note scripts. Scripts are fetched from the store and cached to
    /// avoid repeated gRPC calls.
    pub script_cache_size: NonZeroUsize,

    /// Maximum number of network transactions which should be in progress concurrently across all
    /// account actors.
    pub max_concurrent_txs: usize,

    /// Maximum number of network notes a single transaction is allowed to consume.
    pub max_notes_per_tx: NonZeroUsize,

    /// Maximum number of attempts to execute a failing note before dropping it. Notes use
    /// exponential backoff between attempts.
    pub max_note_attempts: usize,

    /// Maximum number of blocks to keep in the chain MMR. Older blocks are pruned.
    pub max_block_count: usize,

    /// Duration after which an idle network account will deactivate.
    ///
    /// An account is considered idle once it has no viable notes to consume.
    /// A deactivated account will reactivate if targeted with new notes.
    pub idle_timeout: Duration,

    /// Maximum number of crashes before an account deactivated.
    ///
    /// Once this limit is reached, no new transactions will be created for this account.
    pub max_account_crashes: usize,

    /// Maximum number of VM execution cycles allowed for a single network transaction.
    ///
    /// Network transactions that exceed this limit will fail with an execution error.
    /// Defaults to 2^18 cycles.
    pub max_cycles: u32,

    /// Expiration delta (in blocks) applied to every submitted network transaction.
    ///
    /// Transactions expire if they are not included within this many blocks of the reference
    /// block they were executed against.
    pub tx_expiration_delta: u16,

    /// Initial sleep applied between per-request retries on transient infrastructure failures (e.g.
    /// prover unreachable, validator/block-producer crash, transport error, store gRPC hiccup).
    /// Doubles on each retry up to [`Self::request_backoff_max`]. Per-note `attempt_count` is *not*
    /// advanced while retries are in progress.
    pub request_backoff_initial: Duration,

    /// Upper bound on the per-request retry backoff sleep.
    pub request_backoff_max: Duration,

    /// Path to the SQLite database file used for persistent state.
    pub database_filepath: PathBuf,

    /// Maximum number of SQLite connections in the database connection pool.
    pub sqlite_connection_pool_size: NonZeroUsize,
}

impl NtxBuilderConfig {
    pub fn new(
        store_url: Url,
        block_producer_url: Url,
        validator_url: Url,
        database_filepath: PathBuf,
    ) -> Self {
        Self {
            store_url,
            block_producer_url,
            validator_url,
            tx_prover_url: None,
            script_cache_size: DEFAULT_SCRIPT_CACHE_SIZE,
            max_concurrent_txs: DEFAULT_MAX_CONCURRENT_TXS,
            max_notes_per_tx: DEFAULT_MAX_NOTES_PER_TX,
            max_note_attempts: DEFAULT_MAX_NOTE_ATTEMPTS,
            max_block_count: DEFAULT_MAX_BLOCK_COUNT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_account_crashes: DEFAULT_MAX_ACCOUNT_CRASHES,
            max_cycles: DEFAULT_MAX_TX_CYCLES,
            tx_expiration_delta: DEFAULT_TX_EXPIRATION_DELTA,
            request_backoff_initial: DEFAULT_REQUEST_BACKOFF_INITIAL,
            request_backoff_max: DEFAULT_REQUEST_BACKOFF_MAX,
            database_filepath,
            sqlite_connection_pool_size: miden_node_db::default_connection_pool_size(),
        }
    }

    /// Sets the transaction expiration delta (in blocks).
    #[must_use]
    pub fn with_tx_expiration_delta(mut self, delta: u16) -> Self {
        self.tx_expiration_delta = delta;
        self
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

    /// Sets the idle timeout for actors.
    ///
    /// Actors that remain idle (no viable notes) for this duration will be deactivated.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Sets the maximum number of crashes before an account actor is deactivated.
    #[must_use]
    pub fn with_max_account_crashes(mut self, max: usize) -> Self {
        self.max_account_crashes = max;
        self
    }

    /// Sets the maximum number of VM execution cycles for network transactions.
    #[must_use]
    pub fn with_max_cycles(mut self, max: u32) -> Self {
        self.max_cycles = max;
        self
    }

    /// Sets the per-request retry backoff bounds (initial sleep and cap) used when retrying
    /// transient infrastructure failures inside a single transaction attempt.
    #[must_use]
    pub fn with_request_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.request_backoff_initial = initial;
        self.request_backoff_max = max;
        self
    }

    /// Sets the SQLite connection pool size.
    #[must_use]
    pub fn with_sqlite_connection_pool_size(mut self, size: NonZeroUsize) -> Self {
        self.sqlite_connection_pool_size = size;
        self
    }

    /// Builds and initializes the network transaction builder.
    ///
    /// Opens the committed-block subscription on the store. On a fresh DB the subscription
    /// starts at genesis and the first block is consumed inline to bootstrap the in-memory
    /// chain state; on resume, the in-memory chain state is loaded from the persisted MMR and
    /// the subscription starts at `persisted_tip + 1`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The store connection fails
    /// - The block subscription cannot be opened (after retries)
    /// - The genesis bootstrap fails to read the first block from the subscription
    pub async fn build(self) -> anyhow::Result<NetworkTransactionBuilder> {
        // Set up the database (bootstrap + connection pool).
        let db = Db::setup_with_pool_size(
            self.database_filepath.clone(),
            self.sqlite_connection_pool_size,
        )
        .await?;

        let script_cache = LruCache::new(self.script_cache_size);
        let coordinator =
            Coordinator::new(self.max_concurrent_txs, self.max_account_crashes, db.clone());

        let store = StoreClient::new(self.store_url.clone());
        let block_producer = BlockProducerClient::new(self.block_producer_url.clone());
        let validator = ValidatorClient::new(self.validator_url.clone());
        let prover = self.tx_prover_url.clone().map(RemoteTransactionProver::new);

        // Decide where to start the subscription. On resume we load the persisted chain state;
        // on fresh start we begin at genesis and bootstrap inline below.
        let stored_chain_state =
            db.get_chain_state().await.context("failed to read chain state")?;

        let block_from = stored_chain_state
            .as_ref()
            .map_or(BlockNumber::GENESIS, |(num, ..)| num.child());

        tracing::info!(
            %block_from,
            resume = stored_chain_state.is_some(),
            "ntx-builder opening block subscription"
        );

        let block_stream_inner = store
            .block_subscription_with_retry(block_from)
            .await
            .map_err(|err| anyhow::anyhow!(err))
            .context("failed to subscribe to committed blocks")?;
        let mut block_stream: BlockStream = Box::pin(block_stream_inner);

        let (chain_state, last_applied_block) =
            if let Some((block_num, header, mmr)) = stored_chain_state {
                let cs = Arc::new(SharedChainState::new(header, mmr));
                (cs, block_num)
            } else {
                // Fresh DB: consume the genesis block from the subscription, apply it with an empty
                // chain MMR (the MMR for tip=GENESIS has no leaves by the one-block-lag
                // convention), and bootstrap the in-memory chain state.
                let genesis = block_stream
                    .next()
                    .await
                    .context("block stream ended before delivering the genesis block")?
                    .context("block stream failed before delivering the genesis block")?;
                let genesis_header = genesis.header().clone();
                anyhow::ensure!(
                    genesis_header.block_num() == BlockNumber::GENESIS,
                    "expected genesis block from subscription but got block {}",
                    genesis_header.block_num()
                );

                let effects = CommittedBlockEffects::from_signed_block(&genesis);
                db.apply_committed_block(effects, PartialMmr::default())
                    .await
                    .context("failed to apply genesis block during bootstrap")?;

                let cs = Arc::new(SharedChainState::from_state(ChainState::bootstrap_genesis(
                    genesis_header,
                )));
                (cs, BlockNumber::GENESIS)
            };

        let (request_tx, actor_request_rx) = mpsc::channel(1);

        let actor_context = AccountActorContext {
            clients: GrpcClients {
                store: store.clone(),
                block_producer: block_producer.clone(),
                validator,
                prover,
            },
            state: State {
                db: db.clone(),
                chain: chain_state.clone(),
                script_cache,
            },
            config: ActorConfig {
                max_notes_per_tx: self.max_notes_per_tx,
                max_note_attempts: self.max_note_attempts,
                idle_timeout: self.idle_timeout,
                max_cycles: self.max_cycles,
                expiration_script: actor::compile_expiration_tx_script(self.tx_expiration_delta),
                tx_expiration_delta: self.tx_expiration_delta,
                request_backoff_initial: self.request_backoff_initial,
                request_backoff_max: self.request_backoff_max,
            },
            request_tx,
        };

        Ok(NetworkTransactionBuilder::new(
            self,
            coordinator,
            db,
            chain_state,
            actor_context,
            block_stream,
            last_applied_block,
            actor_request_rx,
        ))
    }
}
