use std::num::NonZeroUsize;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::spawn::spawn_blocking_in_span;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use tracing::{info, info_span, instrument};
use url::Url;

use crate::blocks::BlockStore;
use crate::db::Db;
use crate::errors::ApplyBlockError;
use crate::genesis::GenesisBlock;
use crate::proven_tip::ProvenTipWriter;
use crate::server::replica_sync::{BlockReplicaSync, ProofReplicaSync};
use crate::state::{ProofCache, State};
use crate::{BlockProver, COMPONENT};

pub mod block_prover_client;
mod replica_sync;

use replica_sync::ReplicaSync as _;
pub mod proof_scheduler;

/// Determines how the store receives new blocks.
///
/// The two modes are mutually exclusive: a store either acts as the primary writer for locally
/// produced blocks, or it syncs blocks from an upstream store instance.
pub enum StoreMode {
    /// Store mode for a sequencing node that produces local blocks.
    ///
    /// Runs the proof scheduler to generate block proofs.
    Sequencer {
        /// URL of the remote block prover. Uses a local prover if `None`.
        block_prover_url: Option<Url>,
        /// Maximum number of blocks proven concurrently by the proof scheduler.
        max_concurrent_proofs: NonZeroUsize,
    },

    /// Store mode for a full node that syncs from an upstream RPC service.
    Full { upstream_url: Url },
}

/// Database options used by the store.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DatabaseOptions {
    /// Maximum number of SQLite connections in the connection pool.
    pub connection_pool_size: NonZeroUsize,
}

impl Default for DatabaseOptions {
    fn default() -> Self {
        Self {
            connection_pool_size: miden_node_db::default_connection_pool_size(),
        }
    }
}

struct ModeSetup {
    /// Keeps the loaded state alive for background tasks that subscribe to its watch channels.
    _state: Arc<State>,
    /// Mode-specific background task: proof scheduler or replica sync.
    mode_task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// The store server.
pub struct Store {
    pub mode: StoreMode,
    pub data_directory: PathBuf,
    pub database_options: DatabaseOptions,
    pub storage_options: StorageOptions,
}

impl Store {
    /// Bootstraps the Store, creating the database state and inserting the genesis block data.
    #[instrument(
        target = COMPONENT,
        name = "store.bootstrap",
        skip_all,
        err,
    )]
    pub fn bootstrap(genesis: GenesisBlock, data_directory: &Path) -> anyhow::Result<()> {
        let data_directory =
            DataDirectory::load(data_directory.to_path_buf()).with_context(|| {
                format!("failed to load data directory at {}", data_directory.display())
            })?;
        tracing::info!(target=COMPONENT, path=%data_directory.display(), "Data directory loaded");

        let block_store_path = data_directory.block_store_dir();
        let block_store =
            BlockStore::bootstrap(block_store_path.clone(), &genesis).with_context(|| {
                format!("failed to bootstrap block store at {}", block_store_path.display())
            })?;
        tracing::info!(target=COMPONENT, path=%block_store.display(), "Block store created");

        // Create the genesis block and insert it into the database.
        let database_filepath = data_directory.database_path();
        Db::bootstrap(database_filepath.clone(), genesis).with_context(|| {
            format!("failed to bootstrap database at {}", database_filepath.display())
        })?;
        tracing::info!(target=COMPONENT, path=%database_filepath.display(), "Database created");

        Ok(())
    }

    /// Serves the store APIs and background tasks.
    ///
    /// Note: this blocks until the server dies.
    pub async fn serve(self) -> anyhow::Result<()> {
        info!(target: COMPONENT,
            data_directory = ?self.data_directory,
            sqlite_connection_pool_size = %self.database_options.connection_pool_size,
            "Loading database");

        let (termination_ask, mut termination_signal) =
            tokio::sync::mpsc::channel::<ApplyBlockError>(1);
        let (state, tx_proven_tip) = State::load_with_database_options(
            &self.data_directory,
            self.storage_options,
            self.database_options,
            termination_ask,
        )
        .await
        .context("failed to load state")?;
        let _disk_monitor_task = Self::spawn_disk_monitor(self.data_directory.clone());

        let ModeSetup { _state, mode_task } = match self.mode {
            StoreMode::Sequencer { block_prover_url, max_concurrent_proofs } => {
                Self::setup_sequencer_mode(
                    state,
                    block_prover_url,
                    max_concurrent_proofs,
                    tx_proven_tip,
                )
            },
            StoreMode::Full { upstream_url } => Self::setup_full_mode(state, upstream_url),
        };

        tokio::select! {
            // Termination signal from apply_block.
            Some(err) = termination_signal.recv() => {
                Err(anyhow::anyhow!("received termination signal").context(err))
            },
            // Proof scheduler or replica task, depending on mode the store is running.
            result = mode_task => {
                match result {
                    Ok(Ok(())) => Err(anyhow::anyhow!("task exited unexpectedly")),
                    Ok(Err(err)) => Err(err.context("task fatal error")),
                    Err(join_err) => Err(join_err).context("task panicked"),
                }
            }
        }
    }

    fn setup_sequencer_mode(
        state: State,
        block_prover_url: Option<Url>,
        max_concurrent_proofs: NonZeroUsize,
        tx_proven_tip: ProvenTipWriter,
    ) -> ModeSetup {
        info!(target: COMPONENT, "Starting in sequencer mode");

        let state = Arc::new(state);
        let proof_cache = state.proof_cache.clone();
        let proof_scheduler_task = Self::spawn_proof_scheduler(
            &state,
            block_prover_url,
            max_concurrent_proofs,
            tx_proven_tip,
            proof_cache,
        );

        ModeSetup {
            _state: state,
            mode_task: proof_scheduler_task,
        }
    }

    fn setup_full_mode(state: State, upstream_url: Url) -> ModeSetup {
        info!(target: COMPONENT, %upstream_url, "Starting in full mode");

        let state = Arc::new(state);
        let block_handle = BlockReplicaSync::new(Arc::clone(&state), upstream_url.clone()).spawn();
        let proof_handle = ProofReplicaSync::new(Arc::clone(&state), upstream_url).spawn();
        let replica_task = tokio::spawn(async move {
            tokio::select! {
                result = block_handle => result?,
                result = proof_handle => result?,
            }
        });

        ModeSetup { _state: state, mode_task: replica_task }
    }

    /// Initializes the block prover client and spawns the proof scheduler as a background task.
    ///
    /// Returns the scheduler task handle.
    fn spawn_proof_scheduler(
        state: &State,
        block_prover_url: Option<Url>,
        max_concurrent_proofs: NonZeroUsize,
        proven_tip: ProvenTipWriter,
        proof_cache: ProofCache,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let block_prover = if let Some(url) = block_prover_url {
            Arc::new(BlockProver::remote(url))
        } else {
            Arc::new(BlockProver::local())
        };

        let chain_tip_rx = state.subscribe_committed_tip();

        proof_scheduler::spawn(
            block_prover,
            state.block_store(),
            chain_tip_rx,
            proven_tip,
            max_concurrent_proofs,
            proof_cache,
        )
    }

    /// Spawns a background task that periodically records the on-disk size of every store data path
    /// as `OTel` span attributes.
    fn spawn_disk_monitor(data_directory: PathBuf) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(5));
            loop {
                interval.tick().await;
                let dir = data_directory.clone();
                let span = info_span!(target: COMPONENT, "measure_disk_space_usage");
                let result =
                    spawn_blocking_in_span(move || measure_disk_usage_bytes(&dir), span.clone())
                        .await;
                match result {
                    Ok(usage) => {
                        span.set_attribute("db.sqlite.size", usage.sqlite_db);
                        span.set_attribute("db.sqlite.wal.size", usage.sqlite_wal);
                        span.set_attribute("db.block_store.size", usage.block_store);
                        #[cfg(feature = "rocksdb")]
                        {
                            span.set_attribute("db.account_tree.size", usage.account_tree);
                            span.set_attribute("db.nullifier_tree.size", usage.nullifier_tree);
                            span.set_attribute(
                                "db.account_state_forest.size",
                                usage.account_state_forest,
                            );
                        }
                    },
                    Err(err) => span.set_error(&err),
                }
            }
        })
    }
}

// DISK USAGE HELPERS
// ================================================================================================

/// Byte counts for each on-disk storage component.
struct DiskUsage {
    sqlite_db: u64,
    sqlite_wal: u64,
    block_store: u64,
    #[cfg(feature = "rocksdb")]
    account_tree: u64,
    #[cfg(feature = "rocksdb")]
    nullifier_tree: u64,
    #[cfg(feature = "rocksdb")]
    account_state_forest: u64,
}

/// Collects on-disk byte sizes for every store data path under `data_dir`.
fn measure_disk_usage_bytes(data_dir: &Path) -> DiskUsage {
    DiskUsage {
        sqlite_db: path_size_bytes(&data_dir.join("miden-store.sqlite3")),
        sqlite_wal: path_size_bytes(&data_dir.join("miden-store.sqlite3-wal")),
        block_store: dir_size_bytes(&data_dir.join("blocks")),
        #[cfg(feature = "rocksdb")]
        account_tree: dir_size_bytes(&data_dir.join("accounttree")),
        #[cfg(feature = "rocksdb")]
        nullifier_tree: dir_size_bytes(&data_dir.join("nullifiertree")),
        #[cfg(feature = "rocksdb")]
        account_state_forest: dir_size_bytes(&data_dir.join("accountstateforest")),
    }
}

/// Returns the byte length of the file at `path`, or `0` if it does not exist.
fn path_size_bytes(path: &Path) -> u64 {
    fs_err::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Returns the total byte length of all files in `path` iteratively, or `0` on any error.
fn dir_size_bytes(path: &Path) -> u64 {
    let mut to_process = vec![path.to_path_buf()];
    let mut total = 0u64;
    while let Some(dir) = to_process.pop() {
        let Ok(entries) = fs_err::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    to_process.push(entry.path());
                } else {
                    total += meta.len();
                }
            }
        }
    }
    total
}

/// Represents the store's data-directory and its content paths.
///
/// Used to keep our filepath assumptions in one location.
#[derive(Clone)]
pub struct DataDirectory(PathBuf);

impl DataDirectory {
    /// Creates a new [`DataDirectory`], ensuring that the directory exists and is accessible
    /// insofar as is possible.
    pub fn load(path: PathBuf) -> std::io::Result<Self> {
        let meta = fs_err::metadata(&path)?;
        if meta.is_dir().not() {
            return Err(std::io::ErrorKind::NotConnected.into());
        }

        Ok(Self(path))
    }

    pub fn block_store_dir(&self) -> PathBuf {
        self.0.join("blocks")
    }

    pub fn database_path(&self) -> PathBuf {
        self.0.join("miden-store.sqlite3")
    }

    pub fn display(&self) -> std::path::Display<'_> {
        self.0.display()
    }
}
