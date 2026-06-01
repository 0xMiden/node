use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use miden_node_utils::clap::duration_to_human_readable_string;
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::logging::OpenTelemetry;
use miden_protocol::block::SignedBlock;
use miden_protocol::utils::serde::Deserializable;
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

        /// The remote transaction prover's gRPC url. If unset, will default to running a prover
        /// in-process which is expensive.
        #[arg(long = "tx-prover.url", env = ENV_TX_PROVER_URL, value_name = "URL")]
        tx_prover_url: Option<Url>,

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
    Bootstrap {
        /// Directory for the ntx-builder's persistent database.
        #[arg(long = "data-directory", env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,

        /// Path to the trusted, signed genesis block file.
        #[arg(long, value_name = "FILE")]
        genesis_block: PathBuf,
    },
}

impl NtxBuilderCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        match self {
            Self::Start { .. } => self.start().await,
            Self::Bootstrap { data_directory, genesis_block } => {
                ensure_empty_directory(&data_directory)?;
                let database_filepath = data_directory.join("ntx-builder.sqlite3");
                let genesis = read_genesis_block(&genesis_block)?;
                miden_ntx_builder::bootstrap(database_filepath, &genesis)
                    .await
                    .context("failed to bootstrap ntx-builder database")
            },
        }
    }

    async fn start(self) -> anyhow::Result<()> {
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

        let config = miden_ntx_builder::NtxBuilderConfig::new(rpc_url, database_filepath)
            .with_tx_prover_url(tx_prover_url)
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
            .build()
            .await
            .context("failed to initialize ntx builder")?
            .run(listener)
            .await
            .context("failed while running ntx builder component")
    }

    pub fn open_telemetry(&self) -> OpenTelemetry {
        match self {
            Self::Start { .. } => OpenTelemetry::from_env().with_name("ntx-builder"),
            // Bootstrap is a one-shot command and does not set up a tracing pipeline.
            Self::Bootstrap { .. } => OpenTelemetry::Disabled,
        }
    }
}

/// Reads a genesis block from disk and returns the signed block.
fn read_genesis_block(genesis_block_path: &Path) -> anyhow::Result<SignedBlock> {
    let bytes = fs_err::read(genesis_block_path).context("failed to read genesis block")?;
    SignedBlock::read_from_bytes(&bytes).context("failed to deserialize genesis block from file")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use tonic::metadata::AsciiMetadataValue;

    use super::NtxBuilderCommand;

    #[test]
    fn start_command_parses_rpc_auth_header_options() {
        let command = NtxBuilderCommand::try_parse_from([
            "miden-ntx-builder",
            "start",
            "--listen",
            "127.0.0.1:8080",
            "--rpc.url",
            "http://127.0.0.1:57291",
            "--rpc.auth-header-value",
            "secret-token",
            "--data-directory",
            "/tmp/miden-ntx-builder",
        ])
        .expect("command should parse");

        let NtxBuilderCommand::Start { rpc_auth_header_value, .. } = command else {
            panic!("expected the start command");
        };

        assert_eq!(rpc_auth_header_value, Some(AsciiMetadataValue::from_static("secret-token")));
    }

    #[test]
    fn bootstrap_command_parses_data_directory_and_genesis_block() {
        let command = NtxBuilderCommand::try_parse_from([
            "miden-ntx-builder",
            "bootstrap",
            "--data-directory",
            "/tmp/miden-ntx-builder",
            "--genesis-block",
            "/tmp/genesis.dat",
        ])
        .expect("command should parse");

        let NtxBuilderCommand::Bootstrap { data_directory, genesis_block } = command else {
            panic!("expected the bootstrap command");
        };

        assert_eq!(data_directory, PathBuf::from("/tmp/miden-ntx-builder"));
        assert_eq!(genesis_block, PathBuf::from("/tmp/genesis.dat"));
    }
}
