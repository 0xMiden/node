use std::num::NonZeroUsize;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::generated::store;
use miden_node_proto_build::store_api_descriptor;
use miden_node_utils::clap::{GrpcOptionsInternal, StorageOptions};
use miden_node_utils::panic::{CatchPanicLayer, catch_panic_layer_fn};
use miden_node_utils::spawn::spawn_blocking_in_span;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_stream::wrappers::TcpListenerStream;
use tower_http::trace::TraceLayer;
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

mod api;
mod block_producer;
pub mod block_prover_client;
mod ntx_builder;
mod replica_sync;

use replica_sync::ReplicaSync as _;
pub mod proof_scheduler;
mod replica;
mod rpc_api;

/// Determines how the store receives new blocks.
///
/// The two modes are mutually exclusive: a store either accepts blocks from a block producer
/// via its `BlockProducer` gRPC service, or it syncs blocks from an upstream store instance.
/// The services exposed on the network differ between modes accordingly.
pub enum StoreMode {
    /// Accepts blocks from a block producer via the `BlockProducer` gRPC service.
    ///
    /// Exposes the `BlockProducer` and `NtxBuilder` gRPC services and runs the proof scheduler
    /// to generate block proofs.
    BlockProducer {
        /// Listener for the block producer gRPC endpoint.
        block_producer_listener: TcpListener,
        /// Listener for the network transaction builder gRPC endpoint.
        ntx_builder_listener: TcpListener,
        /// URL of the remote block prover. Uses a local prover if `None`.
        block_prover_url: Option<Url>,
        /// Maximum number of blocks proven concurrently by the proof scheduler.
        max_concurrent_proofs: NonZeroUsize,
    },

    /// Receives blocks from an upstream store's `StoreReplica` gRPC service.
    ///
    /// Only the `Rpc` and `StoreReplica` gRPC services are exposed. The `BlockProducer` and
    /// `NtxBuilder` services are not started and no proof scheduler runs.
    Replica { upstream_url: Url },
}

struct ModeSetup {
    /// gRPC server tasks (one per bound listener + the DB maintenance loop).
    grpc_servers: tokio::task::JoinSet<Result<(), tonic::transport::Error>>,
    /// Mode-specific background task: proof scheduler or replica sync.
    mode_task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// The store server.
pub struct Store {
    pub rpc_listener: TcpListener,
    pub mode: StoreMode,
    pub data_directory: PathBuf,
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
        let rpc_address = self.rpc_listener.local_addr()?;
        info!(target: COMPONENT, rpc_endpoint=?rpc_address,
            ?self.data_directory, ?self.grpc_options.request_timeout, "Loading database");

        let (termination_ask, mut termination_signal) =
            tokio::sync::mpsc::channel::<ApplyBlockError>(1);
        let (state, tx_proven_tip) =
            State::load(&self.data_directory, self.storage_options, termination_ask)
                .await
                .context("failed to load state")?;
        let _disk_monitor_task = Self::spawn_disk_monitor(self.data_directory.clone());

        let ModeSetup { mut grpc_servers, mode_task } = match self.mode {
            StoreMode::BlockProducer {
                block_producer_listener,
                ntx_builder_listener,
                block_prover_url,
                max_concurrent_proofs,
            } => {
                Self::setup_block_producer_mode(
                    state,
                    block_producer_listener,
                    ntx_builder_listener,
                    block_prover_url,
                    max_concurrent_proofs,
                    tx_proven_tip,
                    self.grpc_options,
                    self.rpc_listener,
                )
                .await?
            },
            StoreMode::Replica { upstream_url } => {
                Self::setup_replica_mode(state, upstream_url, self.grpc_options, self.rpc_listener)?
            },
        };

        tokio::select! {
            // GRPC service task.
            result = grpc_servers.join_next() => {
                result.expect("joinset is not empty")?.map_err(Into::into)
            },
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

    #[expect(clippy::too_many_arguments)]
    async fn setup_block_producer_mode(
        state: State,
        block_producer_listener: TcpListener,
        ntx_builder_listener: TcpListener,
        block_prover_url: Option<Url>,
        max_concurrent_proofs: NonZeroUsize,
        tx_proven_tip: ProvenTipWriter,
        grpc_options: GrpcOptionsInternal,
        rpc_listener: TcpListener,
    ) -> anyhow::Result<ModeSetup> {
        info!(target: COMPONENT,
            block_producer_endpoint=?block_producer_listener.local_addr()?,
            ntx_builder_endpoint=?ntx_builder_listener.local_addr()?,
            "Starting in block-producer mode");

        let proof_cache = state.proof_cache.clone();
        let (proof_scheduler_task, chain_tip_sender) = Self::spawn_proof_scheduler(
            &state,
            block_prover_url,
            max_concurrent_proofs,
            tx_proven_tip,
            proof_cache,
        )
        .await;

        let state = Arc::new(state);
        let store_api = api::StoreApi::new(state);
        let block_producer_api = block_producer::BlockProducerApi {
            inner: store_api.clone(),
            chain_tip_sender,
        };

        let join_set = Self::spawn_block_producer_grpc_servers(
            store_api,
            block_producer_api,
            grpc_options,
            rpc_listener,
            ntx_builder_listener,
            block_producer_listener,
        )?;

        Ok(ModeSetup {
            grpc_servers: join_set,
            mode_task: proof_scheduler_task,
        })
    }

    fn setup_replica_mode(
        state: State,
        upstream_url: Url,
        grpc_options: GrpcOptionsInternal,
        rpc_listener: TcpListener,
    ) -> anyhow::Result<ModeSetup> {
        info!(target: COMPONENT, %upstream_url, "Starting in replica mode");

        let state = Arc::new(state);
        let block_handle = BlockReplicaSync::new(Arc::clone(&state), upstream_url.clone()).spawn();
        let proof_handle = ProofReplicaSync::new(Arc::clone(&state), upstream_url).spawn();
        let replica_task = tokio::spawn(async move {
            tokio::select! {
                result = block_handle => result?,
                result = proof_handle => result?,
            }
        });

        let store_api = api::StoreApi::new(state);
        let join_set = Self::spawn_replica_grpc_servers(store_api, grpc_options, rpc_listener)?;

        Ok(ModeSetup {
            grpc_servers: join_set,
            mode_task: replica_task,
        })
    }

    /// Initializes the block prover client and spawns the proof scheduler as a background task.
    ///
    /// Returns the scheduler task handle and the chain tip sender (needed by the block-producer
    /// gRPC service to notify the scheduler of new blocks).
    async fn spawn_proof_scheduler(
        state: &State,
        block_prover_url: Option<Url>,
        max_concurrent_proofs: NonZeroUsize,
        proven_tip: ProvenTipWriter,
        proof_cache: ProofCache,
    ) -> (
        tokio::task::JoinHandle<anyhow::Result<()>>,
        watch::Sender<miden_protocol::block::BlockNumber>,
    ) {
        let block_prover = if let Some(url) = block_prover_url {
            Arc::new(BlockProver::remote(url))
        } else {
            Arc::new(BlockProver::local())
        };

        let chain_tip = state.chain_tip(crate::state::Finality::Committed).await;
        let (chain_tip_tx, chain_tip_rx) = watch::channel(chain_tip);

        let handle = proof_scheduler::spawn(
            block_prover,
            state.block_store(),
            chain_tip_rx,
            proven_tip,
            max_concurrent_proofs,
            proof_cache,
        );

        (handle, chain_tip_tx)
    }

    /// Spawns the gRPC servers for block-producer mode.
    ///
    /// Starts three listeners: Rpc+StoreReplica (shared), `NtxBuilder`, and `BlockProducer`.
    fn spawn_block_producer_grpc_servers(
        store_api: api::StoreApi,
        block_producer_api: block_producer::BlockProducerApi,
        grpc_options: GrpcOptionsInternal,
        rpc_listener: TcpListener,
        ntx_builder_listener: TcpListener,
        block_producer_listener: TcpListener,
    ) -> anyhow::Result<JoinSet<Result<(), tonic::transport::Error>>> {
        let mut join_set = JoinSet::new();

        let rpc_service = store::rpc_server::RpcServer::new(store_api.clone());
        let replica_service =
            store::store_replica_server::StoreReplicaServer::new(store_api.clone());
        let ntx_builder_replica_service =
            store::store_replica_server::StoreReplicaServer::new(store_api.clone());
        let ntx_builder_service = store::ntx_builder_server::NtxBuilderServer::new(store_api);
        let block_producer_service =
            store::block_producer_server::BlockProducerServer::new(block_producer_api);

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(store_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        let make_server = || {
            tonic::transport::Server::builder()
                .timeout(grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
        };

        join_set.spawn(
            make_server()
                .add_service(rpc_service)
                .add_service(replica_service)
                .add_service(reflection_service.clone())
                .serve_with_incoming(TcpListenerStream::new(rpc_listener)),
        );

        // The ntx-builder uses the replica stream against this same endpoint to drive its
        // committed-block subscription, so expose both services here.
        join_set.spawn(
            make_server()
                .add_service(ntx_builder_service)
                .add_service(ntx_builder_replica_service)
                .add_service(reflection_service.clone())
                .serve_with_incoming(TcpListenerStream::new(ntx_builder_listener)),
        );

        join_set.spawn(
            make_server()
                .accept_http1(true)
                .add_service(block_producer_service)
                .add_service(reflection_service)
                .serve_with_incoming(TcpListenerStream::new(block_producer_listener)),
        );

        Ok(join_set)
    }

    /// Spawns the gRPC servers for replica mode.
    ///
    /// Only the Rpc and `StoreReplica` services are exposed — no `BlockProducer`, `NtxBuilder`, or
    /// proof scheduler.
    fn spawn_replica_grpc_servers(
        store_api: api::StoreApi,
        grpc_options: GrpcOptionsInternal,
        rpc_listener: TcpListener,
    ) -> anyhow::Result<JoinSet<Result<(), tonic::transport::Error>>> {
        let mut join_set = JoinSet::new();

        let rpc_service = store::rpc_server::RpcServer::new(store_api.clone());
        let replica_service = store::store_replica_server::StoreReplicaServer::new(store_api);

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(store_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        join_set.spawn(
            tonic::transport::Server::builder()
                .timeout(grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                .add_service(rpc_service)
                .add_service(replica_service)
                .add_service(reflection_service)
                .serve_with_incoming(TcpListenerStream::new(rpc_listener)),
        );

        Ok(join_set)
    }
    /// Spawns a background task that periodically records the on-disk size of every store data
    /// path as `OTel` span attributes.
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
