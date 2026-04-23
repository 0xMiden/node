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
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinSet;
use tokio_stream::wrappers::TcpListenerStream;
use tower_http::trace::TraceLayer;
use tracing::{info, instrument};
use url::Url;

use crate::blocks::BlockStore;
use crate::db::Db;
use crate::errors::ApplyBlockError;
use crate::genesis::GenesisBlock;
use crate::proven_tip::ProvenTipWriter;
use crate::state::State;
use crate::{BlockProver, COMPONENT};

mod api;
mod block_producer;
pub mod block_prover_client;
mod ntx_builder;
pub mod proof_scheduler;
mod replica;
mod replica_client;
mod rpc_api;

/// Broadcast channel capacity for replica proof notifications.
///
/// 512 slots gives replicas ~512 proofs of buffer during historical replay before
/// the sender considers them lagged. On lag, the replica should reconnect.
const PROOF_BROADCAST_CAPACITY: usize = 512;

/// Determines how the store receives new blocks.
///
/// The two modes are mutually exclusive: a store either accepts blocks from a block producer
/// via its `BlockProducer` gRPC service, or it syncs blocks from an upstream store instance.
/// The services exposed on the network differ between modes accordingly.
pub enum StoreMode {
    /// Accepts blocks from a block producer via the `BlockProducer` gRPC service.
    ///
    /// Exposes the `BlockProducer` and `NtxBuilder` gRPC services and runs the proof scheduler
    /// to generate block proofs locally.
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

    /// Serves the store APIs and background tasks.
    ///
    /// Note: this blocks until the server dies.
    pub async fn serve(self) -> anyhow::Result<()> {
        let rpc_address = self.rpc_listener.local_addr()?;
        info!(target: COMPONENT, rpc_endpoint=?rpc_address,
            ?self.data_directory, ?self.grpc_options.request_timeout, "Loading database");

        // Load initial state.
        let (termination_ask, mut termination_signal) =
            tokio::sync::mpsc::channel::<ApplyBlockError>(1);
        let (state, tx_proven_tip, block_sender) =
            State::load(&self.data_directory, self.storage_options, termination_ask)
                .await
                .context("failed to load state")?;

        let (proof_sender, _) = broadcast::channel(PROOF_BROADCAST_CAPACITY);

        let (mut join_set, mode_task) = match self.mode {
            StoreMode::BlockProducer {
                block_producer_listener,
                ntx_builder_listener,
                block_prover_url,
                max_concurrent_proofs,
            } => {
                let block_producer_address = block_producer_listener.local_addr()?;
                let ntx_builder_address = ntx_builder_listener.local_addr()?;
                info!(target: COMPONENT,
                    block_producer_endpoint=?block_producer_address,
                    ntx_builder_endpoint=?ntx_builder_address,
                    "Starting in block-producer mode");

                let (proof_scheduler_task, chain_tip_sender) = Self::spawn_proof_scheduler(
                    &state,
                    block_prover_url,
                    max_concurrent_proofs,
                    tx_proven_tip,
                    proof_sender.clone(),
                )
                .await;

                let join_set = Self::spawn_grpc_servers(
                    &Arc::new(state),
                    chain_tip_sender,
                    block_sender,
                    proof_sender,
                    self.grpc_options,
                    self.rpc_listener,
                    Some(ntx_builder_listener),
                    Some(block_producer_listener),
                )?;

                (join_set, proof_scheduler_task)
            },

            StoreMode::Replica { upstream_url } => {
                info!(target: COMPONENT, %upstream_url, "Starting in replica mode");

                // A dummy watch channel satisfies StoreApi's chain_tip_sender field. No proof
                // scheduler reads from it in replica mode.
                let chain_tip = state.chain_tip(crate::state::Finality::Committed).await;
                let (chain_tip_sender, _) = watch::channel(chain_tip);

                let state = Arc::new(state);
                let replica_task = replica_client::spawn(Arc::clone(&state), upstream_url);

                let join_set = Self::spawn_grpc_servers(
                    &state,
                    chain_tip_sender,
                    block_sender,
                    proof_sender,
                    self.grpc_options,
                    self.rpc_listener,
                    None, // no ntx-builder in replica mode
                    None, // no block-producer in replica mode
                )?;

                (join_set, replica_task)
            },
        };

        // Wait on any workload to finish / error out.
        let service = async move {
            join_set.join_next().await.expect("joinset is not empty")?.map_err(Into::into)
        };

        tokio::select! {
            result = service => result,
            Some(err) = termination_signal.recv() => {
                Err(anyhow::anyhow!("received termination signal").context(err))
            },
            result = mode_task => {
                match result {
                    Ok(Ok(())) => Err(anyhow::anyhow!("mode task exited unexpectedly")),
                    Ok(Err(err)) => Err(err.context("mode task fatal error")),
                    Err(join_err) => Err(join_err).context("mode task panicked"),
                }
            }
        }
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
        proof_sender: broadcast::Sender<proof_scheduler::ProofNotification>,
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
            state.db().clone(),
            block_prover,
            state.block_store(),
            chain_tip_rx,
            proven_tip,
            max_concurrent_proofs,
            proof_sender,
        );

        (handle, chain_tip_tx)
    }

    /// Spawns the gRPC servers and the DB maintenance background task.
    ///
    /// - `ntx_builder_listener`: `Some` in block-producer mode, `None` in replica mode.
    /// - `block_producer_listener`: `Some` in block-producer mode, `None` in replica mode.
    #[expect(clippy::too_many_arguments)]
    fn spawn_grpc_servers(
        state: &Arc<State>,
        chain_tip_sender: watch::Sender<miden_protocol::block::BlockNumber>,
        block_sender: broadcast::Sender<crate::state::BlockNotification>,
        proof_sender: broadcast::Sender<proof_scheduler::ProofNotification>,
        grpc_options: GrpcOptionsInternal,
        rpc_listener: TcpListener,
        ntx_builder_listener: Option<TcpListener>,
        block_producer_listener: Option<TcpListener>,
    ) -> anyhow::Result<JoinSet<Result<(), tonic::transport::Error>>> {
        let make_api = |state: &Arc<State>| api::StoreApi {
            state: Arc::clone(state),
            chain_tip_sender: chain_tip_sender.clone(),
            block_sender: block_sender.clone(),
            proof_sender: proof_sender.clone(),
        };

        let rpc_service = store::rpc_server::RpcServer::new(make_api(state));
        let replica_service = store::store_replica_server::StoreReplicaServer::new(make_api(state));

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(store_api_descriptor())
            .build_v1()
            .context("failed to build reflection service")?;

        info!(target: COMPONENT, "Database loaded");

        let mut join_set = JoinSet::new();

        let state_for_maintenance = Arc::clone(state);
        join_set.spawn(async move {
            // Manual tests on testnet indicate each iteration takes ~2s once things are OS cached.
            //
            // 5 minutes seems like a reasonable interval, where this should have minimal database
            // IO impact while providing a decent view into table growth over time.
            let mut interval = tokio::time::interval(Duration::from_mins(5));
            loop {
                interval.tick().await;
                let _ = state_for_maintenance.analyze_table_sizes().await;
            }
        });

        join_set.spawn(
            tonic::transport::Server::builder()
                .timeout(grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                .add_service(rpc_service)
                .add_service(replica_service)
                .add_service(reflection_service.clone())
                .serve_with_incoming(TcpListenerStream::new(rpc_listener)),
        );

        if let Some(listener) = ntx_builder_listener {
            let ntx_builder_service =
                store::ntx_builder_server::NtxBuilderServer::new(make_api(state));
            join_set.spawn(
                tonic::transport::Server::builder()
                    .timeout(grpc_options.request_timeout)
                    .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                    .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                    .add_service(ntx_builder_service)
                    .add_service(reflection_service.clone())
                    .serve_with_incoming(TcpListenerStream::new(listener)),
            );
        }

        if let Some(listener) = block_producer_listener {
            let block_producer_service =
                store::block_producer_server::BlockProducerServer::new(api::StoreApi {
                    state: Arc::clone(state),
                    chain_tip_sender,
                    block_sender,
                    proof_sender,
                });
            join_set.spawn(
                tonic::transport::Server::builder()
                    .accept_http1(true)
                    .timeout(grpc_options.request_timeout)
                    .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                    .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                    .add_service(block_producer_service)
                    .add_service(reflection_service)
                    .serve_with_incoming(TcpListenerStream::new(listener)),
            );
        }

        Ok(join_set)
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
