use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use builder::BlockStream;
use chain_state::ChainState;
use clients::RpcClient;
use db::Db;
use futures::StreamExt;
use miden_node_utils::ErrorReport;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use tonic::metadata::AsciiMetadataValue;
use url::Url;

use crate::committed_block::CommittedBlockEffects;

pub(crate) type NoteError = Arc<dyn ErrorReport + Send + Sync>;

// PR 1 of the block-subscription refactor leaves the actor execution path in tree but unwired. It
// is restored by PR 2
#[expect(dead_code)]
mod actor;
mod builder;
#[expect(dead_code)]
mod chain_state;
mod clients;
mod committed_block;
#[expect(dead_code)]
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
    /// Opens a committed-block subscription against the node RPC service. On a fresh DB the
    /// subscription starts at genesis and the first block is consumed inline to bootstrap the
    /// in-memory chain state; on resume, the in-memory chain state is loaded from the persisted
    /// header + chain MMR and the subscription starts at `persisted_tip + 1`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DB cannot be opened or migrated
    /// - The RPC connection fails (after retries)
    /// - The genesis block cannot be read from the subscription on a fresh start
    pub async fn build(self) -> anyhow::Result<NetworkTransactionBuilder> {
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

        // Decide where to start the subscription. On resume we load the persisted chain state; on
        // fresh start we begin at genesis and bootstrap inline below.
        let stored_chain_state =
            db.get_chain_state().await.context("failed to read chain state")?;

        let block_from = stored_chain_state
            .as_ref()
            .map_or(BlockNumber::GENESIS, |(num, ..)| num.child());

        tracing::info!(
            %block_from,
            resume = stored_chain_state.is_some(),
            "ntx-builder opening committed-block subscription"
        );

        let raw_stream = rpc
            .block_subscription_with_retry(block_from)
            .await
            .map_err(|err| anyhow::anyhow!(err))
            .context("failed to subscribe to committed blocks")?;
        let mut block_stream: BlockStream = Box::pin(raw_stream);

        let (chain, last_applied_block) = if let Some((block_num, header, mmr)) = stored_chain_state
        {
            (ChainState::new(header, mmr), block_num)
        } else {
            // Fresh DB: consume the genesis block inline so the in-memory chain state is non- empty
            // before the steady-state loop runs.
            let (genesis, _committed_tip) = block_stream
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

            (ChainState::new(genesis_header, PartialMmr::default()), BlockNumber::GENESIS)
        };

        Ok(NetworkTransactionBuilder::new(
            self,
            db,
            block_stream,
            last_applied_block,
            chain,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tonic::metadata::AsciiMetadataValue;
    use url::Url;

    use super::NtxBuilderConfig;

    #[test]
    fn ntx_builder_config_default_has_no_rpc_auth_header() {
        let config = NtxBuilderConfig::new(
            Url::parse("http://127.0.0.1:57291").expect("valid url"),
            PathBuf::from("ntx-builder.sqlite3"),
        );

        assert_eq!(config.rpc_auth_header, None);
    }

    #[test]
    fn ntx_builder_config_with_rpc_auth_header_stores_value() {
        let secret_token = AsciiMetadataValue::from_static("secret-token");

        let config = NtxBuilderConfig::new(
            Url::parse("http://127.0.0.1:57291").expect("valid url"),
            PathBuf::from("ntx-builder.sqlite3"),
        )
        .with_rpc_auth_header(secret_token.clone());

        assert_eq!(config.rpc_auth_header, Some(secret_token));
    }
}
