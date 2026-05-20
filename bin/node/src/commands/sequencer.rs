use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use miden_node_block_producer::EmbeddedBlockProducer;
use miden_node_rpc::{BlockProducerBackend, EmbeddedRpc};
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::{
    ApplyBlockError,
    DEFAULT_MAX_CONCURRENT_PROOFS,
    DatabaseOptions,
    State,
    StoreApi,
    default_sqlite_connection_pool_size,
    serve_replica,
};
use miden_node_utils::clap::{GrpcOptionsExternal, StorageOptions};
use miden_node_utils::fs::ensure_empty_directory;
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;
use url::Url;

use super::ENV_ENABLE_OTEL;
use crate::commands::ENV_DATA_DIRECTORY;
use crate::commands::block_producer::BlockProducerConfig;

const ENV_RPC_LISTEN: &str = "MIDEN_NODE_SEQUENCER_RPC_LISTEN";
const ENV_BLOCK_PRODUCER_LISTEN: &str = "MIDEN_NODE_SEQUENCER_BLOCK_PRODUCER_LISTEN";
const ENV_REPLICA_LISTEN: &str = "MIDEN_NODE_SEQUENCER_REPLICA_LISTEN";
const ENV_VALIDATOR_URL: &str = "MIDEN_NODE_SEQUENCER_VALIDATOR_URL";
const ENV_BLOCK_PROVER_URL: &str = "MIDEN_NODE_SEQUENCER_BLOCK_PROVER_URL";
const ENV_SQLITE_CONNECTION_POOL_SIZE: &str = "MIDEN_NODE_SEQUENCER_SQLITE_CONNECTION_POOL_SIZE";

#[derive(clap::Subcommand)]
pub enum SequencerCommand {
    /// Bootstraps the blockchain database with a pre-existing genesis block.
    ///
    /// The genesis block file should be produced by `miden-validator bootstrap`.
    Bootstrap {
        /// Directory in which to store the database and raw block data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
        /// Path to the pre-signed genesis block file produced by the validator.
        #[arg(long, value_name = "FILE")]
        genesis_block: PathBuf,
    },

    /// Starts the sequencer: store, block-producer, and RPC in a single process.
    ///
    /// Exposes three gRPC endpoints: the client-facing RPC API, the block-producer API,
    /// and the replica streaming API (for downstream replicas).
    Start {
        /// Socket address at which to serve the client-facing RPC API.
        #[arg(long = "rpc.listen", env = ENV_RPC_LISTEN, value_name = "LISTEN")]
        rpc_listen: SocketAddr,

        /// Socket address at which to serve the block-producer gRPC API.
        #[arg(long = "block-producer.listen", env = ENV_BLOCK_PRODUCER_LISTEN, value_name = "LISTEN")]
        block_producer_listen: SocketAddr,

        /// Socket address at which to serve the replica streaming API.
        #[arg(long = "replica.listen", env = ENV_REPLICA_LISTEN, value_name = "LISTEN")]
        replica_listen: SocketAddr,

        /// The validator's gRPC url.
        #[arg(long = "validator.url", env = ENV_VALIDATOR_URL, value_name = "URL")]
        validator_url: Url,

        /// The remote block prover's gRPC url. If not provided, a local block prover will be used.
        #[arg(long = "block-prover.url", env = ENV_BLOCK_PROVER_URL, value_name = "URL")]
        block_prover_url: Option<Url>,

        /// Directory in which to store the database and raw block data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,

        /// Enables the exporting of traces for OpenTelemetry.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        /// Maximum number of concurrent block proofs to be scheduled.
        #[arg(
            long = "max-concurrent-proofs",
            default_value_t = DEFAULT_MAX_CONCURRENT_PROOFS,
            value_name = "NUM"
        )]
        max_concurrent_proofs: NonZeroUsize,

        /// Maximum number of SQLite connections in the store database connection pool.
        #[arg(
            long = "sqlite.connection_pool_size",
            env = ENV_SQLITE_CONNECTION_POOL_SIZE,
            default_value_t = default_sqlite_connection_pool_size(),
            value_name = "NUM"
        )]
        sqlite_connection_pool_size: NonZeroUsize,

        #[command(flatten)]
        block_producer: BlockProducerConfig,

        #[command(flatten)]
        grpc_options: GrpcOptionsExternal,

        #[command(flatten)]
        storage_options: StorageOptions,
    },
}

impl SequencerCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        match self {
            Self::Bootstrap { data_directory, genesis_block } => {
                ensure_empty_directory(&data_directory)?;
                bootstrap_sequencer(&data_directory, &genesis_block)
            },
            Self::Start {
                rpc_listen,
                block_producer_listen,
                replica_listen,
                validator_url,
                block_prover_url,
                data_directory,
                enable_otel: _,
                max_concurrent_proofs,
                sqlite_connection_pool_size,
                block_producer,
                grpc_options,
                storage_options,
            } => {
                if block_producer.max_batches_per_block > miden_protocol::MAX_BATCHES_PER_BLOCK {
                    anyhow::bail!(
                        "max-batches-per-block cannot exceed protocol limit of {}",
                        miden_protocol::MAX_BATCHES_PER_BLOCK
                    );
                }
                if block_producer.max_txs_per_batch > miden_protocol::MAX_ACCOUNTS_PER_BATCH {
                    anyhow::bail!(
                        "max-txs-per-batch cannot exceed protocol limit of {}",
                        miden_protocol::MAX_ACCOUNTS_PER_BATCH
                    );
                }

                Self::start(
                    rpc_listen,
                    block_producer_listen,
                    replica_listen,
                    validator_url,
                    block_prover_url,
                    data_directory,
                    max_concurrent_proofs,
                    DatabaseOptions {
                        connection_pool_size: sqlite_connection_pool_size,
                    },
                    block_producer,
                    grpc_options,
                    storage_options,
                )
                .await
            },
        }
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        match self {
            Self::Start { enable_otel, .. } => *enable_otel,
            Self::Bootstrap { .. } => false,
        }
    }

    #[expect(clippy::too_many_arguments)]
    async fn start(
        rpc_listen: SocketAddr,
        block_producer_listen: SocketAddr,
        replica_listen: SocketAddr,
        validator_url: Url,
        block_prover_url: Option<Url>,
        data_directory: PathBuf,
        max_concurrent_proofs: NonZeroUsize,
        database_options: DatabaseOptions,
        block_producer_config: BlockProducerConfig,
        grpc_options: GrpcOptionsExternal,
        storage_options: StorageOptions,
    ) -> anyhow::Result<()> {
        // Bind eagerly to catch address conflicts before loading state.
        let rpc_listener = tokio::net::TcpListener::bind(rpc_listen)
            .await
            .context("Failed to bind to RPC gRPC socket")?;
        let replica_listener = tokio::net::TcpListener::bind(replica_listen)
            .await
            .context("Failed to bind to replica gRPC socket")?;

        let (termination_ask, mut termination_signal) =
            tokio::sync::mpsc::channel::<ApplyBlockError>(1);

        let (state, proven_tip) = State::load_with_database_options(
            &data_directory,
            storage_options,
            database_options,
            termination_ask,
        )
        .await
        .context("failed to load state")?;

        let state = Arc::new(state);
        let store_api = Arc::new(StoreApi::new(Arc::clone(&state)));
        let grpc_internal = grpc_options.into();

        let replica_task = tokio::spawn(serve_replica(
            Arc::clone(&state),
            proven_tip,
            replica_listener,
            block_prover_url,
            max_concurrent_proofs,
            grpc_internal,
        ));

        let (block_producer_handle, block_producer_serve) = EmbeddedBlockProducer {
            block_producer_address: block_producer_listen,
            state: Arc::clone(&state),
            validator_url: validator_url.clone(),
            batch_prover_url: block_producer_config.batch_prover_url,
            batch_interval: block_producer_config.batch_interval,
            block_interval: block_producer_config.block_interval,
            max_txs_per_batch: block_producer_config.max_txs_per_batch,
            max_batches_per_block: block_producer_config.max_batches_per_block,
            grpc_options: grpc_internal,
            mempool_tx_capacity: block_producer_config.mempool_tx_capacity,
        }
        .start()
        .await
        .context("failed to start embedded block producer")?;

        let block_producer_task = tokio::spawn(block_producer_serve);

        let rpc_task = tokio::spawn(
            EmbeddedRpc {
                listener: rpc_listener,
                state: store_api,
                block_producer: Some(BlockProducerBackend::Embedded(block_producer_handle)),
                validator_url,
                grpc_options,
            }
            .serve(),
        );

        tokio::select! {
            result = replica_task => {
                result.context("replica task panicked")?.context("replica task failed")
            },
            result = block_producer_task => {
                result.context("block-producer task panicked")?.context("block-producer task failed")
            },
            result = rpc_task => {
                result.context("rpc task panicked")?.context("rpc task failed")
            },
            Some(err) = termination_signal.recv() => {
                Err(anyhow::anyhow!("received termination signal from apply_block").context(err))
            },
        }
    }
}

fn bootstrap_sequencer(data_directory: &Path, genesis_block_path: &Path) -> anyhow::Result<()> {
    let bytes = fs_err::read(genesis_block_path).context("failed to read genesis block")?;
    let signed_block = SignedBlock::read_from_bytes(&bytes)
        .context("failed to deserialize genesis block from file")?;
    let genesis_block =
        GenesisBlock::try_from(signed_block).context("genesis block validation failed")?;

    miden_node_store::Store::bootstrap(genesis_block, data_directory)
}
