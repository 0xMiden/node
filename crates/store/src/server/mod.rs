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
use miden_node_utils::tracing::grpc::grpc_trace_fn;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_stream::wrappers::TcpListenerStream;
use tower_http::trace::TraceLayer;
use tracing::{info, instrument};
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
        info!(target: COMPONENT, rpc_endpoint=?rpc_address, ntx_builder_endpoint=?ntx_builder_address,
            block_producer_endpoint=?block_producer_address, ?self.data_directory, ?self.grpc_options.request_timeout,
            "Loading database");

        // Load initial state.
        let (termination_ask, mut termination_signal) =
            tokio::sync::mpsc::channel::<ApplyBlockError>(1);
        let (state, tx_proven_tip) =
            State::load(&self.data_directory, self.storage_options, termination_ask)
                .await
                .context("failed to load state")?;

        // Spawn proof scheduler.
        let (proof_scheduler_task, chain_tip_sender) = Self::spawn_proof_scheduler(
            &state,
            self.block_prover_url,
            self.max_concurrent_proofs,
            tx_proven_tip,
        )
        .await;

        // Spawn gRPC Servers.
        let mut join_set = Self::spawn_grpc_servers(
            state,
            chain_tip_sender,
            self.grpc_options,
            self.rpc_listener,
            self.ntx_builder_listener,
            self.block_producer_listener,
        )?;

        // Wait on any workload to finish / error out.
        let service = async move {
            join_set.join_next().await.expect("joinset is not empty")?.map_err(Into::into)
        };
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

    /// Initializes the block prover client and spawns the proof scheduler as a background task.
    ///
    /// Returns the scheduler task handle and the chain tip sender (needed by gRPC services to
    /// notify the scheduler of new blocks).
    async fn spawn_proof_scheduler(
        state: &State,
        block_prover_url: Option<Url>,
        max_concurrent_proofs: NonZeroUsize,
        proven_tip_tx: watch::Sender<miden_protocol::block::BlockNumber>,
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
            proven_tip_tx,
            max_concurrent_proofs,
        );

        (handle, chain_tip_tx)
    }

    /// Spawns the gRPC servers and the DB maintenance background task.
    fn spawn_grpc_servers(
        state: State,
        chain_tip_sender: watch::Sender<miden_protocol::block::BlockNumber>,
        grpc_options: GrpcOptionsInternal,
        rpc_listener: TcpListener,
        ntx_builder_listener: TcpListener,
        block_producer_listener: TcpListener,
    ) -> anyhow::Result<JoinSet<Result<(), tonic::transport::Error>>> {
        let state = Arc::new(state);
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

        let mut join_set = JoinSet::new();

        join_set.spawn(async move {
            // Manual tests on testnet indicate each iteration takes ~2s once things are OS cached.
            //
            // 5 minutes seems like a reasonable interval, where this should have minimal database
            // IO impact while providing a decent view into table growth over time.
            let mut interval = tokio::time::interval(Duration::from_mins(5));
            loop {
                interval.tick().await;
                let _ = state.analyze_table_sizes().await;
            }
        });

        join_set.spawn(
            tonic::transport::Server::builder()
                .timeout(grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                .add_service(rpc_service)
                .add_service(reflection_service.clone())
                .serve_with_incoming(TcpListenerStream::new(rpc_listener)),
        );

        join_set.spawn(
            tonic::transport::Server::builder()
                .timeout(grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                .add_service(ntx_builder_service)
                .add_service(reflection_service.clone())
                .serve_with_incoming(TcpListenerStream::new(ntx_builder_listener)),
        );

        join_set.spawn(
            tonic::transport::Server::builder()
                .accept_http1(true)
                .timeout(grpc_options.request_timeout)
                .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
                .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
                .add_service(block_producer_service)
                .add_service(reflection_service)
                .serve_with_incoming(TcpListenerStream::new(block_producer_listener)),
        );

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
