use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use miden_node_utils::clap::duration_to_human_readable_string;
use url::Url;

use super::{
    DEFAULT_NTX_SCRIPT_CACHE_SIZE,
    DEFAULT_NTX_TICKER_INTERVAL,
    ENV_BLOCK_PRODUCER_URL,
    ENV_ENABLE_OTEL,
    ENV_NTX_DATA_DIRECTORY,
    ENV_NTX_PROVER_URL,
    ENV_NTX_SCRIPT_CACHE_SIZE,
    ENV_STORE_NTX_BUILDER_URL,
    ENV_VALIDATOR_URL,
};

#[derive(clap::Subcommand)]
pub enum NtxBuilderCommand {
    /// Starts the network transaction builder component.
    Start {
        /// The store's ntx-builder service gRPC url.
        #[arg(long = "store.url", env = ENV_STORE_NTX_BUILDER_URL, value_name = "URL")]
        store_url: Url,

        /// The block-producer's gRPC url.
        #[arg(long = "block-producer.url", env = ENV_BLOCK_PRODUCER_URL, value_name = "URL")]
        block_producer_url: Url,

        /// The validator's gRPC url.
        #[arg(long = "validator.url", env = ENV_VALIDATOR_URL, value_name = "URL")]
        validator_url: Url,

        /// The remote transaction prover's gRPC url. If unset, will default to running a
        /// prover in-process which is expensive.
        #[arg(long = "tx-prover.url", env = ENV_NTX_PROVER_URL, value_name = "URL")]
        tx_prover_url: Option<Url>,

        /// Interval at which to run the network transaction builder's ticker.
        #[arg(
            long = "interval",
            default_value = &duration_to_human_readable_string(DEFAULT_NTX_TICKER_INTERVAL),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        ticker_interval: Duration,

        /// Number of note scripts to cache locally.
        ///
        /// Note scripts not in cache must first be retrieved from the store.
        #[arg(
            long = "script-cache-size",
            env = ENV_NTX_SCRIPT_CACHE_SIZE,
            value_name = "NUM",
            default_value_t = DEFAULT_NTX_SCRIPT_CACHE_SIZE
        )]
        script_cache_size: NonZeroUsize,

        /// Directory for the ntx-builder's persistent database.
        #[arg(long = "data-directory", env = ENV_NTX_DATA_DIRECTORY, value_name = "DIR")]
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
            store_url,
            block_producer_url,
            validator_url,
            tx_prover_url,
            ticker_interval: _,
            script_cache_size,
            data_directory,
            enable_otel: _,
        } = self;

        let database_filepath = data_directory.join("ntx-builder.sqlite3");

        let config = miden_node_ntx_builder::NtxBuilderConfig::new(
            store_url,
            block_producer_url,
            validator_url,
            database_filepath,
        )
        .with_tx_prover_url(tx_prover_url)
        .with_script_cache_size(script_cache_size);

        config
            .build()
            .await
            .context("failed to initialize ntx builder")?
            .run()
            .await
            .context("failed while running ntx builder component")
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        let Self::Start { enable_otel, .. } = self;
        *enable_otel
    }
}
