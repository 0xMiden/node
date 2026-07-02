use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use miden_node_utils::clap::duration_to_human_readable_string;
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::genesis::{
    OfficialNetwork,
    fetch_signed_genesis_block,
    read_signed_genesis_block,
};
use miden_node_utils::logging::OpenTelemetry;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::block::SignedBlock;
use tokio::net::TcpListener;
use tonic::metadata::AsciiMetadataValue;
use url::Url;

const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";
const ENV_LISTEN: &str = "MIDEN_NODE_NTX_BUILDER_LISTEN";
const ENV_RPC_URL: &str = "MIDEN_NODE_NTX_BUILDER_RPC_URL";
const ENV_RPC_AUTH_HEADER_VALUE: &str = "MIDEN_NODE_NTX_BUILDER_RPC_AUTH_HEADER_VALUE";
const ENV_TX_PROVER_URL: &str = "MIDEN_NODE_NTX_BUILDER_NTX_PROVER_URL";
const ENV_SCRIPT_CACHE_SIZE: &str = "MIDEN_NODE_NTX_BUILDER_SCRIPT_CACHE_SIZE";
const ENV_MAX_CYCLES: &str = "MIDEN_NODE_NTX_BUILDER_MAX_CYCLES";
const ENV_TX_EXPIRATION_DELTA: &str = "MIDEN_NODE_NTX_BUILDER_TX_EXPIRATION_DELTA";
const ENV_SQLITE_CONNECTION_POOL_SIZE: &str = "MIDEN_NODE_NTX_BUILDER_SQLITE_CONNECTION_POOL_SIZE";

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_SCRIPT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
const DEFAULT_MAX_CYCLES: u32 = 1 << 18;
const DEFAULT_TX_EXPIRATION_DELTA: NonZeroU16 = NonZeroU16::new(30).unwrap();

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[expect(clippy::large_enum_variant, reason = "CLI args are a once off")]
pub enum NtxBuilderCommand {
    /// Starts the network transaction builder component.
    Start {
        /// Socket address at which to serve the ntx-builder's gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: SocketAddr,

        /// The node RPC service gRPC url.
        #[arg(long = "rpc.url", alias = "store.url", env = ENV_RPC_URL, value_name = "URL")]
        rpc_url: Url,

        /// Optional value for the fixed `x-miden-network-tx-auth` metadata header.
        #[arg(
            long = "rpc.auth-header-value",
            env = ENV_RPC_AUTH_HEADER_VALUE,
            value_name = "VALUE"
        )]
        rpc_auth_header_value: Option<AsciiMetadataValue>,

        /// The remote transaction prover's gRPC url.
        #[arg(long = "tx-prover.url", env = ENV_TX_PROVER_URL, value_name = "URL")]
        tx_prover_url: Url,

        /// Number of note scripts to cache locally.
        ///
        /// Note scripts not in cache must first be retrieved through RPC.
        #[arg(
            long = "script-cache-size",
            env = ENV_SCRIPT_CACHE_SIZE,
            value_name = "NUM",
            default_value_t = DEFAULT_SCRIPT_CACHE_SIZE
        )]
        script_cache_size: NonZeroUsize,

        /// Duration after which an idle network account will deactivate.
        ///
        /// An account is considered idle once it has no viable notes to consume.
        /// A deactivated account will reactivate if targeted with new notes.
        #[arg(
            long = "idle-timeout",
            default_value = &duration_to_human_readable_string(DEFAULT_IDLE_TIMEOUT),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        idle_timeout: Duration,

        /// Maximum number of crashes before an account deactivated.
        ///
        /// Once this limit is reached, no new transactions will be created for this account.
        #[arg(long = "max-account-crashes", default_value_t = 10, value_name = "NUM")]
        max_account_crashes: usize,

        /// Maximum number of VM execution cycles allowed for a single network transaction.
        ///
        /// Network transactions that exceed this limit will fail. Defaults to 2^18 (262.144)
        /// cycles.
        #[arg(
            long = "max-cycles",
            env = ENV_MAX_CYCLES,
            default_value_t = DEFAULT_MAX_CYCLES,
            value_name = "NUM",
        )]
        max_tx_cycles: u32,

        /// Number of blocks after which a submitted network transaction expires.
        ///
        /// Set as the on-chain transaction expiration delta and reused as the actor's local retry
        /// timeout. Must be between 1 and 65535.
        #[arg(
            long = "tx-expiration-delta",
            env = ENV_TX_EXPIRATION_DELTA,
            default_value_t = DEFAULT_TX_EXPIRATION_DELTA,
            value_parser = clap::value_parser!(NonZeroU16),
            value_name = "NUM",
        )]
        tx_expiration_delta: NonZeroU16,

        /// Maximum number of SQLite connections in the ntx-builder database connection pool.
        #[arg(
            long = "sqlite.connection_pool_size",
            env = ENV_SQLITE_CONNECTION_POOL_SIZE,
            default_value_t = miden_node_db::default_connection_pool_size(),
            value_name = "NUM"
        )]
        sqlite_connection_pool_size: NonZeroUsize,

        /// Directory for the ntx-builder's persistent database.
        #[arg(long = "data-directory", env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
    },

    /// Bootstraps the ntx-builder database from a trusted genesis block.
    ///
    /// This must be run once before `start` so that the database always contains at least the
    /// genesis block.
    #[command(group(
        ArgGroup::new("genesis_block_source")
            .required(true)
            .multiple(false)
            .args(["genesis_block_file", "network"])
    ))]
    Bootstrap {
        /// Directory for the ntx-builder's persistent database.
        #[arg(long = "data-directory", env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,

        /// Bootstrap from a trusted genesis block file.
        #[arg(long = "file", value_name = "FILE")]
        genesis_block_file: Option<PathBuf>,

        /// Bootstrap for an official Miden network.
        #[arg(long, value_enum, value_name = "NETWORK")]
        network: Option<OfficialNetwork>,
    },

    /// Applies pending ntx-builder database migrations.
    ///
    /// Cannot be run on an empty data directory; run `bootstrap` first.
    Migrate {
        /// Directory for the ntx-builder's persistent database.
        #[arg(long = "data-directory", env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,
    },
}

impl NtxBuilderCommand {
    pub async fn handle(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        match self {
            Self::Start { .. } => self.start(shutdown).await,
            Self::Bootstrap {
                data_directory,
                genesis_block_file,
                network,
            } => {
                ensure_empty_directory(&data_directory)?;
                let database_filepath = data_directory.join("ntx-builder.sqlite3");
                let genesis =
                    read_bootstrap_genesis_block(genesis_block_file.as_deref(), network).await?;
                miden_ntx_builder::bootstrap(database_filepath, &genesis)
                    .await
                    .context("failed to bootstrap ntx-builder database")
            },
            Self::Migrate { data_directory } => {
                miden_ntx_builder::migrate(data_directory.join("ntx-builder.sqlite3"))
                    .context("failed to apply ntx-builder database migrations")
            },
        }
    }

    async fn start(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let Self::Start {
            listen,
            rpc_url,
            rpc_auth_header_value,
            tx_prover_url,
            script_cache_size,
            idle_timeout,
            max_account_crashes,
            max_tx_cycles,
            tx_expiration_delta,
            sqlite_connection_pool_size,
            data_directory,
        } = self
        else {
            unreachable!("start is only called for the Start variant")
        };

        let listener = TcpListener::bind(listen)
            .await
            .context("Failed to bind to ntx-builder's gRPC socket")?;

        let database_filepath = data_directory.join("ntx-builder.sqlite3");

        let config =
            miden_ntx_builder::NtxBuilderConfig::new(rpc_url, tx_prover_url, database_filepath)
                .with_script_cache_size(script_cache_size)
                .with_idle_timeout(idle_timeout)
                .with_max_account_crashes(max_account_crashes)
                .with_max_cycles(max_tx_cycles)
                .with_tx_expiration_delta(tx_expiration_delta)
                .with_sqlite_connection_pool_size(sqlite_connection_pool_size);
        let config = match rpc_auth_header_value {
            Some(value) => config.with_rpc_auth_header(value),
            None => config,
        };

        config
            .build(shutdown.clone())
            .await
            .context("failed to initialize ntx builder")?
            .run(listener, shutdown)
            .await
            .context("failed while running ntx builder component")
    }

    pub fn open_telemetry(&self) -> OpenTelemetry {
        match self {
            Self::Start { .. } => OpenTelemetry::from_env().with_name("ntx-builder"),
            // Bootstrap and migrate are one-shot commands and do not set up a tracing pipeline.
            Self::Bootstrap { .. } | Self::Migrate { .. } => OpenTelemetry::Disabled,
        }
    }
}

async fn read_bootstrap_genesis_block(
    genesis_block_file: Option<&Path>,
    network: Option<OfficialNetwork>,
) -> anyhow::Result<SignedBlock> {
    match (genesis_block_file, network) {
        (Some(path), None) => read_signed_genesis_block(path),
        (None, Some(network)) => fetch_signed_genesis_block(network).await,
        _ => unreachable!("clap requires exactly one genesis block source"),
    }
}
