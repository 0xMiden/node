use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use actor::{AccountActorContext, ActorConfig, GrpcClients, State};
use anyhow::Context;
use builder::BlockStream;
use chain_state::SharedChainState;
use clients::{BlockProducerClient, StoreClient, StoreReplicaStreamClient, ValidatorClient};
use coordinator::Coordinator;
use db::Db;
use miden_node_utils::ErrorReport;
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::block::BlockNumber;
use miden_remote_prover_client::RemoteTransactionProver;
use tokio::sync::mpsc;
use url::Url;

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

/// Default channel capacity for account loading from the store.
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
            account_channel_capacity: DEFAULT_ACCOUNT_CHANNEL_CAPACITY,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_account_crashes: DEFAULT_MAX_ACCOUNT_CRASHES,
            max_cycles: DEFAULT_MAX_TX_CYCLES,
            tx_expiration_delta: DEFAULT_TX_EXPIRATION_DELTA,
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

    /// Sets the SQLite connection pool size.
    #[must_use]
    pub fn with_sqlite_connection_pool_size(mut self, size: NonZeroUsize) -> Self {
        self.sqlite_connection_pool_size = size;
        self
    }

    /// Builds and initializes the network transaction builder.
    ///
    /// This method connects to the store services, determines the catch-up target block, and
    /// opens a committed-block subscription. The catch-up phase itself runs inside
    /// [`NetworkTransactionBuilder::run`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The store connection fails
    /// - The block subscription cannot be opened (after retries)
    /// - The store contains no blocks (not bootstrapped)
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
        let store_replica = StoreReplicaStreamClient::new(self.store_url.clone());
        let block_producer = BlockProducerClient::new(self.block_producer_url.clone());
        let validator = ValidatorClient::new(self.validator_url.clone());
        let prover = self.tx_prover_url.clone().map(RemoteTransactionProver::new);

        // Fetch the current chain tip + MMR. This is needed as the catch-up target and as the
        // initial in-memory chain state used by actors.
        let (chain_tip_header, chain_mmr) = store
            .get_latest_blockchain_data_with_retry()
            .await?
            .context("store should contain a latest block")?;
        let chain_tip_block_num = chain_tip_header.block_num();

        // Resume from where we left off. If the DB has no chain state yet, we initialize it
        // from the current chain tip.
        // Existing DBs resume from their persisted block; the catch-up phase then drains the
        // stream until the in-memory chain state reaches the current tip.
        let stored_chain_state =
            db.get_chain_state().await.context("failed to read chain state")?;

        let (block_from, last_applied_block) =
            resume_point(stored_chain_state.as_ref().map(|(num, _)| *num), chain_tip_block_num);

        if stored_chain_state.is_none() {
            db.upsert_chain_state(chain_tip_block_num, chain_tip_header.clone())
                .await
                .context("failed to upsert chain state")?;
        }

        tracing::info!(
            %block_from,
            %chain_tip_block_num,
            "ntx-builder opening block subscription"
        );

        let block_stream_inner = store_replica
            .block_subscription_with_retry(block_from)
            .await
            .map_err(|err| anyhow::anyhow!(err))
            .context("failed to subscribe to committed blocks")?;
        let block_stream: BlockStream = Box::pin(block_stream_inner);

        // Chain state is initialized at the chain tip, actors only start after catch-up, so the
        // tip is consistent with the DB by the time they run.
        let chain_state = Arc::new(SharedChainState::new(chain_tip_header, chain_mmr));

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
            },
            request_tx,
        };

        Ok(NetworkTransactionBuilder::new(
            self,
            coordinator,
            store,
            db,
            chain_state,
            actor_context,
            block_stream,
            chain_tip_block_num,
            last_applied_block,
            actor_request_rx,
        ))
    }
}

// HELPERS
// =================================================================================================

/// Decides where the ntx-builder should start consuming the block stream from on startup.
///
/// Returns `(block_from, last_applied_block)`:
/// - `block_from` is the first block number the subscription should yield (inclusive).
/// - `last_applied_block` is the highest block already reflected in the DB. The catch-up phase
///   drains the stream until this reaches the chain tip.
///
/// If the DB has a persisted chain state, resume from the block after it. Otherwise the DB is
/// fresh and we treat the current chain tip as already applied (the caller is responsible for
/// persisting that state).
fn resume_point(stored: Option<BlockNumber>, chain_tip: BlockNumber) -> (BlockNumber, BlockNumber) {
    match stored {
        Some(num) => (num.child(), num),
        None => (chain_tip.child(), chain_tip),
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    use super::resume_point;

    #[test]
    fn resume_point_fresh_db_starts_after_chain_tip() {
        let tip = BlockNumber::from(10u32);

        let (block_from, last_applied) = resume_point(None, tip);

        assert_eq!(last_applied, tip);
        assert_eq!(block_from, tip.child());
    }

    #[test]
    fn resume_point_existing_db_resumes_after_stored_block() {
        let tip = BlockNumber::from(10u32);
        let stored = BlockNumber::from(7u32);

        let (block_from, last_applied) = resume_point(Some(stored), tip);

        assert_eq!(last_applied, stored);
        assert_eq!(block_from, stored.child());
    }

    #[test]
    fn resume_point_db_already_at_tip() {
        let tip = BlockNumber::from(10u32);

        let (block_from, last_applied) = resume_point(Some(tip), tip);

        assert_eq!(last_applied, tip);
        assert_eq!(block_from, tip.child());
        // Catch-up loop terminates immediately because last_applied >= target.
    }
}
