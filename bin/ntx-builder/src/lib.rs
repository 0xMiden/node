use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use builder::BlockStream;
use chain_state::SharedChainState;
use clients::RpcClient;
use db::Db;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_remote_prover_client::RemoteTransactionProver;
use tokio::sync::mpsc;
use tonic::metadata::AsciiMetadataValue;
use url::Url;

use crate::actor::{AccountActorContext, ActorConfig, GrpcClients, State};
use crate::coordinator::Coordinator;

pub(crate) type NoteError = Arc<dyn ErrorReport + Send + Sync>;

// PR 2 spawns actors and runs their lifecycle (wait-for-account + notify/idle), but the transaction
// execution path (candidate selection, proving, submission) stays unwired until PR 3 reconnects it.
#[expect(dead_code)]
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

// BOOTSTRAP
// =================================================================================================

/// Bootstraps the ntx-builder database at `database_filepath` with the genesis block.
///
/// The genesis block is fetched from the node RPC with a single `GetBlockByNumber` request. After
/// this completes the singleton chain-state row exists at the genesis block number, so
/// [`NtxBuilderConfig`] startup can always resume from a persisted chain state instead of
/// consuming the genesis block from the subscription.
///
/// Returns an error if the node is unreachable, does not yet have the genesis block, or the
/// database has already been bootstrapped.
pub async fn bootstrap(
    database_filepath: PathBuf,
    rpc_url: Url,
    rpc_auth_header: Option<AsciiMetadataValue>,
) -> anyhow::Result<()> {
    let rpc = RpcClient::new_with_auth(
        rpc_url,
        rpc_auth_header,
        DEFAULT_REQUEST_BACKOFF_INITIAL,
        DEFAULT_REQUEST_BACKOFF_MAX,
    );

    let genesis = rpc
        .get_genesis_block()
        .await
        .map_err(|err| anyhow::anyhow!(err))
        .context("failed to fetch the genesis block from the node RPC")?
        .context("the node RPC returned no genesis block")?;

    db::Db::bootstrap(database_filepath, &genesis).await
}

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

/// Default channel capacity for account loading through RPC.
const DEFAULT_ACCOUNT_CHANNEL_CAPACITY: usize = 1_000;

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
/// (downed prover, transport error, RPC crash, RPC gRPC hiccup). Doubles on each retry up to
/// [`DEFAULT_REQUEST_BACKOFF_MAX`].
const DEFAULT_REQUEST_BACKOFF_INITIAL: Duration = Duration::from_millis(100);

/// Default upper bound on the per-request retry backoff sleep.
const DEFAULT_REQUEST_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Default maximum number of VM execution cycles allowed for a network transaction.
///
/// This limits the computational cost of network transactions. The protocol maximum is
/// `1 << 29` but network transactions should be much cheaper.
const DEFAULT_MAX_TX_CYCLES: u32 = 1 << 19;

// CONFIGURATION
// =================================================================================================

/// Configuration for the Network Transaction Builder.
///
/// This struct contains all the settings needed to create and run a `NetworkTransactionBuilder`.
#[derive(Debug, Clone)]
pub struct NtxBuilderConfig {
    /// Address of the node RPC gRPC server.
    pub rpc_url: Url,

    /// Optional auth header value injected into internal RPC requests.
    pub rpc_auth_header: Option<AsciiMetadataValue>,

    /// Address of the remote transaction prover. If `None`, transactions will be proven locally.
    pub tx_prover_url: Option<Url>,

    /// Size of the LRU cache for note scripts. Scripts are fetched through RPC and cached to avoid
    /// repeated gRPC calls.
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

    /// Channel capacity for loading accounts through RPC during startup.
    pub account_channel_capacity: usize,

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

    /// Initial sleep applied between per-request retries on transient infrastructure failures (e.g.
    /// prover unreachable, RPC crash, transport error, RPC gRPC hiccup). Doubles on each retry up
    /// to [`Self::request_backoff_max`]. Per-note `attempt_count` is *not* advanced while retries
    /// are in progress.
    pub request_backoff_initial: Duration,

    /// Upper bound on the per-request retry backoff sleep.
    pub request_backoff_max: Duration,

    /// Path to the SQLite database file used for persistent state.
    pub database_filepath: PathBuf,

    /// Maximum number of SQLite connections in the database connection pool.
    pub sqlite_connection_pool_size: NonZeroUsize,
}

impl NtxBuilderConfig {
    pub fn new(rpc_url: Url, database_filepath: PathBuf) -> Self {
        Self {
            rpc_url,
            rpc_auth_header: None,
            tx_prover_url: None,
            script_cache_size: DEFAULT_SCRIPT_CACHE_SIZE,
            max_concurrent_txs: DEFAULT_MAX_CONCURRENT_TXS,
            max_notes_per_tx: DEFAULT_MAX_NOTES_PER_TX,
            max_note_attempts: DEFAULT_MAX_NOTE_ATTEMPTS,
            max_block_count: DEFAULT_MAX_BLOCK_COUNT,
            account_channel_capacity: DEFAULT_ACCOUNT_CHANNEL_CAPACITY,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_account_crashes: DEFAULT_MAX_ACCOUNT_CRASHES,
            max_cycles: DEFAULT_MAX_TX_CYCLES,
            request_backoff_initial: DEFAULT_REQUEST_BACKOFF_INITIAL,
            request_backoff_max: DEFAULT_REQUEST_BACKOFF_MAX,
            database_filepath,
            sqlite_connection_pool_size: miden_node_db::default_connection_pool_size(),
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

    /// Sets the optional auth header value to inject into internal RPC requests.
    #[must_use]
    pub fn with_rpc_auth_header(mut self, value: AsciiMetadataValue) -> Self {
        self.rpc_auth_header = Some(value);
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
    /// Loads the in-memory chain state from the persisted header + chain MMR and opens a
    /// committed-block subscription against the node RPC service starting at `persisted_tip + 1`.
    /// The database must have been bootstrapped with the genesis block beforehand (see
    /// [`crate::bootstrap`]).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DB cannot be opened or migrated
    /// - The DB has not been bootstrapped (no persisted chain state)
    /// - The RPC connection fails (after retries)
    pub async fn build(self) -> anyhow::Result<NetworkTransactionBuilder> {
        // The event loop pins one connection for itself (so block application is never starved by
        // the account actors), leaving the rest of the pool for actors and the gRPC server. That
        // requires at least two connections.
        anyhow::ensure!(
            self.sqlite_connection_pool_size.get() >= 2,
            "sqlite connection pool size must be at least 2 (the event loop pins one connection)",
        );

        let rpc = match self.rpc_auth_header.clone() {
            Some(rpc_auth_header_value) => RpcClient::new_with_auth(
                self.rpc_url.clone(),
                Some(rpc_auth_header_value),
                self.request_backoff_initial,
                self.request_backoff_max,
            ),
            None => RpcClient::new(
                self.rpc_url.clone(),
                self.request_backoff_initial,
                self.request_backoff_max,
            ),
        };

        // Set up the database (bootstrap + connection pool).
        let db = Db::setup_with_pool_size(
            self.database_filepath.clone(),
            self.sqlite_connection_pool_size,
        )
        .await?;

        // The database is bootstrapped with the genesis block before startup (see
        // `miden-ntx-builder bootstrap`), so a persisted chain state is always present. Load it and
        // resume the subscription from the block after the last applied one.
        let (last_applied_block, header, mmr) =
            db.get_chain_state().await.context("failed to read chain state")?.context(
                "ntx-builder database has not been bootstrapped; \
                 run `miden-ntx-builder bootstrap` first",
            )?;

        let block_from = last_applied_block.child();

        tracing::info!(
            %block_from,
            "ntx-builder opening committed-block subscription"
        );

        let raw_stream = rpc
            .block_subscription_with_retry(block_from)
            .await
            .map_err(|err| anyhow::anyhow!(err))
            .context("failed to subscribe to committed blocks")?;
        let block_stream: BlockStream = Box::pin(raw_stream);

        let chain = Arc::new(SharedChainState::new(header, mmr));

        // Wire the actor context + coordinator. The actor request channel is owned by the builder
        // (receiver) and cloned into every spawned actor (sender) so all DB writes from actors
        // serialize through the builder's event loop.
        let (request_tx, actor_request_rx) = mpsc::channel(self.account_channel_capacity);
        let actor_context = AccountActorContext {
            clients: GrpcClients {
                rpc: rpc.clone(),
                prover: self
                    .tx_prover_url
                    .clone()
                    .map(|url| RemoteTransactionProver::new(url.as_str())),
            },
            state: State {
                db: db.clone(),
                chain: chain.clone(),
                script_cache: LruCache::new(self.script_cache_size),
            },
            config: ActorConfig {
                max_notes_per_tx: self.max_notes_per_tx,
                max_note_attempts: self.max_note_attempts,
                idle_timeout: self.idle_timeout,
                max_cycles: self.max_cycles,
                request_backoff_initial: self.request_backoff_initial,
                request_backoff_max: self.request_backoff_max,
            },
            request_tx,
        };
        let coordinator =
            Coordinator::new(self.max_concurrent_txs, self.max_account_crashes, actor_context);

        Ok(NetworkTransactionBuilder::new(
            self,
            db,
            block_stream,
            last_applied_block,
            chain,
            coordinator,
            actor_request_rx,
        ))
    }
}
