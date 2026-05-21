use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use miden_node_utils::clap::duration_to_human_readable_string;
use tokio::net::TcpListener;
use url::Url;

const ENV_ENABLE_OTEL: &str = "MIDEN_NODE_ENABLE_OTEL";
const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";
const ENV_LISTEN: &str = "MIDEN_NODE_NTX_BUILDER_LISTEN";
const ENV_SEQUENCER_URL: &str = "MIDEN_NODE_NTX_BUILDER_SEQUENCER_URL";
const ENV_BLOCK_PRODUCER_URL: &str = "MIDEN_NODE_NTX_BUILDER_BLOCK_PRODUCER_URL";
const ENV_VALIDATOR_URL: &str = "MIDEN_NODE_NTX_BUILDER_VALIDATOR_URL";
const ENV_TX_PROVER_URL: &str = "MIDEN_NODE_NTX_BUILDER_NTX_PROVER_URL";
const ENV_SCRIPT_CACHE_SIZE: &str = "MIDEN_NODE_NTX_BUILDER_SCRIPT_CACHE_SIZE";
const ENV_MAX_CYCLES: &str = "MIDEN_NODE_NTX_BUILDER_MAX_CYCLES";
const ENV_SQLITE_CONNECTION_POOL_SIZE: &str = "MIDEN_NODE_NTX_BUILDER_SQLITE_CONNECTION_POOL_SIZE";

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_SCRIPT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
const DEFAULT_MAX_CYCLES: u32 = 1 << 18;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub enum NtxBuilderCommand {
    /// Starts the network transaction builder component.
    Start {
        /// Socket address at which to serve the ntx-builder's gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: SocketAddr,

        /// The sequencer's `NtxBuilderApi` gRPC url.
        #[arg(long = "sequencer.url", env = ENV_SEQUENCER_URL, value_name = "URL")]
        sequencer_url: Url,

        /// The block-producer's gRPC url.
        #[arg(long = "block-producer.url", env = ENV_BLOCK_PRODUCER_URL, value_name = "URL")]
        block_producer_url: Url,

        /// The validator's gRPC url.
        #[arg(long = "validator.url", env = ENV_VALIDATOR_URL, value_name = "URL")]
        validator_url: Url,

        /// The remote transaction prover's gRPC url. If unset, will default to running a prover
        /// in-process which is expensive.
        #[arg(long = "tx-prover.url", env = ENV_TX_PROVER_URL, value_name = "URL")]
        tx_prover_url: Option<Url>,

        /// Number of note scripts to cache locally.
        ///
        /// Note scripts not in cache must first be retrieved from the store.
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

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,
    },
}

impl NtxBuilderCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let Self::Start {
            listen,
            sequencer_url,
            block_producer_url,
            validator_url,
            tx_prover_url,
            script_cache_size,
            idle_timeout,
            max_account_crashes,
            max_tx_cycles,
            sqlite_connection_pool_size,
            data_directory,
            enable_otel: _,
        } = self;

        let listener = TcpListener::bind(listen)
            .await
            .context("Failed to bind to ntx-builder's gRPC socket")?;

        let database_filepath = data_directory.join("ntx-builder.sqlite3");

        let config = miden_ntx_builder::NtxBuilderConfig::new(
            sequencer_url,
            block_producer_url,
            validator_url,
            database_filepath,
        )
        .with_tx_prover_url(tx_prover_url)
        .with_script_cache_size(script_cache_size)
        .with_idle_timeout(idle_timeout)
        .with_max_account_crashes(max_account_crashes)
        .with_max_cycles(max_tx_cycles)
        .with_sqlite_connection_pool_size(sqlite_connection_pool_size);

        config
            .build()
            .await
            .context("failed to initialize ntx builder")?
            .run(listener)
            .await
            .context("failed while running ntx builder component")
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        let Self::Start { enable_otel, .. } = self;
        *enable_otel
    }
}
