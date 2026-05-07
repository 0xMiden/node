use std::num::NonZeroUsize;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::generated::store;
use miden_node_proto_build::{
    store_block_producer_api_descriptor,
    store_ntx_builder_api_descriptor,
    store_rpc_api_descriptor,
};
use miden_node_utils::clap::{GrpcOptionsInternal, StorageOptions};
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::spawn::spawn_blocking_in_span;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_stream::wrappers::TcpListenerStream;
use tower_http::trace::TraceLayer;
use tracing::{info, info_span, instrument};
use url::Url;

use crate::blocks::BlockStore;
use crate::db::Db;
use crate::errors::ApplyBlockError;
use crate::genesis::GenesisBlock;
use crate::state::State;
use crate::{BlockProver, COMPONENT};

mod api;
mod block_producer;
pub mod block_prover_client;
mod ntx_builder;
pub mod proof_scheduler;
mod rpc_api;

/// The store server.
pub struct Store {
    pub rpc_listener: TcpListener,
    pub ntx_builder_listener: TcpListener,
    pub block_producer_listener: TcpListener,
    /// URL for the Block Prover client. Uses local prover if `None`.
    pub block_prover_url: Option<Url>,
    pub data_directory: PathBuf,
    /// Maximum number of blocks being proven concurrently by the proof scheduler.
    pub max_concurrent_proofs: NonZeroUsize,
    pub storage_options: StorageOptions,
    pub grpc_options: GrpcOptionsInternal,
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

        let block_store = data_directory.block_store_dir();
        let block_store =
            BlockStore::bootstrap(block_store.clone(), &genesis).with_context(|| {
                format!("failed to bootstrap block store at {}", block_store.display())
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

    /// Serves the store APIs (rpc, ntx-builder, block-producer) and DB maintenance background task.
    ///
    /// Note: this blocks until the server dies.
    pub async fn serve(self) -> anyhow::Result<()> {
        let rpc_address = self.rpc_listener.local_addr()?;
        let ntx_builder_address = self.ntx_builder_listener.local_addr()?;
        let block_producer_address = self.block_producer_listener.local_addr()?;
        let data_directory = self.data_directory.clone();
        info!(target: COMPONENT, rpc_endpoint=?rpc_address, ntx_builder_endpoint=?ntx_builder_address,
            block_producer_endpoint=?block_producer_address, ?self.data_directory, ?self.grpc_options.request_timeout,
            "Loading database");

        let (termination_ask, mut termination_signal) =
            tokio::sync::mpsc::channel::<ApplyBlockError>(1);
        let state = Arc::new(
            State::load(&self.data_directory, self.storage_options, termination_ask)
                .await
                .context("failed to load state")?,
        );

        // Initialize local or remote block prover.
        let block_prover = if let Some(url) = self.block_prover_url {
            Arc::new(BlockProver::remote(url))
        } else {
            Arc::new(BlockProver::local())
        };

        // Initialize the chain tip watch channel.
        let chain_tip = state.latest_block_num().await;
        let (chain_tip_sender, chain_tip_rx) = tokio::sync::watch::channel(chain_tip);

        // Spawn the proof scheduler as a background task. It will immediately pick up any
        // unproven blocks from previous runs and begin proving them.
        let proof_scheduler_task = proof_scheduler::spawn(
            state.db().clone(),
            block_prover,
            state.block_store(),
            chain_tip_rx,
            self.max_concurrent_proofs,
        );

        let rpc_service = store::rpc_server::RpcServer::new(api::StoreApi {
            state: Arc::clone(&state),
            chain_tip_sender: chain_tip_sender.clone(),
        });
        let ntx_builder_service = store::ntx_builder_server::NtxBuilderServer::new(api::StoreApi {
            state: Arc::clone(&state),
            chain_tip_sender: chain_tip_sender.clone(),
        });
        let block_producer_service =
            store::block_producer_server::BlockProducerServer::new(api::StoreApi {
                state: Arc::clone(&state),
                chain_tip_sender,
            });
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(store_rpc_api_descriptor())
            .register_file_descriptor_set(store_ntx_builder_api_descriptor())
            .register_file_descriptor_set(store_block_producer_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        info!(target: COMPONENT, "Database loaded");

        // Spawn disk monitor (fire-and-forget; never causes server shutdown).
        let _disk_monitor_task = Self::spawn_disk_monitor(data_directory);

        let mut join_set = JoinSet::new();
        join_set.spawn(
            tonic::transport::Server::builder()
                .timeout(self.grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                .add_service(rpc_service)
                .add_service(reflection_service.clone())
                .serve_with_incoming(TcpListenerStream::new(self.rpc_listener)),
        );

        join_set.spawn(
            tonic::transport::Server::builder()
                .timeout(self.grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                .add_service(ntx_builder_service)
                .add_service(reflection_service.clone())
                .serve_with_incoming(TcpListenerStream::new(self.ntx_builder_listener)),
        );

        join_set.spawn(
            tonic::transport::Server::builder()
                .accept_http1(true)
                .timeout(self.grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                .add_service(block_producer_service)
                .add_service(reflection_service)
                .serve_with_incoming(TcpListenerStream::new(self.block_producer_listener)),
        );

        // SAFETY: The joinset is definitely not empty.
        let service = async move { join_set.join_next().await.unwrap()?.map_err(Into::into) };
        tokio::select! {
            result = service => result,
            Some(err) = termination_signal.recv() => {
                Err(anyhow::anyhow!("received termination signal").context(err))
            },
            result = proof_scheduler_task => {
                match result {
                    Ok(Ok(())) => Err(anyhow::anyhow!("proof scheduler exited unexpectedly")),
                    Ok(Err(err)) => Err(err.context("proof scheduler fatal error")),
                    Err(join_err) => Err(join_err).context("proof scheduler panicked"),
                }
            }
        }
    }

    /// Spawns a background task that periodically records the on-disk size of every store data
    /// path as `OTel` span attributes.
    ///
    /// Sizes are measured with [`fs_err::metadata`] (no SQL connections, no lock contention).
    /// Errors are logged as warnings and never cause the server to stop.
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
                        }
                    },
                    Err(err) => span.set_error(&err),
                }
            }
        })
    }
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
}

/// Collects on-disk byte sizes for every store data path under `data_dir`.
///
/// Uses only [`fs_err::metadata`] and [`fs_err::read_dir`] — no SQLite connections are opened,
/// so there is no read-lock contention with concurrent database writers.
fn measure_disk_usage_bytes(data_dir: &Path) -> DiskUsage {
    DiskUsage {
        sqlite_db: path_size_bytes(&data_dir.join("miden-store.sqlite3")),
        sqlite_wal: path_size_bytes(&data_dir.join("miden-store.sqlite3-wal")),
        block_store: dir_size_bytes(&data_dir.join("blocks")),
        #[cfg(feature = "rocksdb")]
        account_tree: dir_size_bytes(&data_dir.join("accounttree")),
        #[cfg(feature = "rocksdb")]
        nullifier_tree: dir_size_bytes(&data_dir.join("nullifiertree")),
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
