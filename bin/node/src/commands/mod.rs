use std::num::NonZeroUsize;
use std::time::Duration;

use miden_node_block_producer::{
    DEFAULT_BATCH_INTERVAL,
    DEFAULT_BLOCK_INTERVAL,
    DEFAULT_MAX_BATCHES_PER_BLOCK,
    DEFAULT_MAX_TXS_PER_BATCH,
};
use url::Url;

pub mod block_producer;
pub mod bundled;
pub mod rpc;
pub mod store;
pub mod validator;

/// A predefined, insecure validator key for development purposes.
const INSECURE_VALIDATOR_KEY_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";

const ENV_BLOCK_PRODUCER_URL: &str = "MIDEN_NODE_BLOCK_PRODUCER_URL";
const ENV_VALIDATOR_URL: &str = "MIDEN_NODE_VALIDATOR_URL";
const ENV_BATCH_PROVER_URL: &str = "MIDEN_NODE_BATCH_PROVER_URL";
const ENV_BLOCK_PROVER_URL: &str = "MIDEN_NODE_BLOCK_PROVER_URL";
const ENV_NTX_PROVER_URL: &str = "MIDEN_NODE_NTX_PROVER_URL";
const ENV_RPC_URL: &str = "MIDEN_NODE_RPC_URL";
const ENV_STORE_RPC_URL: &str = "MIDEN_NODE_STORE_RPC_URL";
const ENV_STORE_NTX_BUILDER_URL: &str = "MIDEN_NODE_STORE_NTX_BUILDER_URL";
const ENV_STORE_BLOCK_PRODUCER_URL: &str = "MIDEN_NODE_STORE_BLOCK_PRODUCER_URL";
const ENV_VALIDATOR_BLOCK_PRODUCER_URL: &str = "MIDEN_NODE_VALIDATOR_BLOCK_PRODUCER_URL";
const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";
const ENV_ENABLE_OTEL: &str = "MIDEN_NODE_ENABLE_OTEL";
const ENV_GENESIS_CONFIG_FILE: &str = "MIDEN_GENESIS_CONFIG_FILE";
const ENV_MAX_TXS_PER_BATCH: &str = "MIDEN_MAX_TXS_PER_BATCH";
const ENV_MAX_BATCHES_PER_BLOCK: &str = "MIDEN_MAX_BATCHES_PER_BLOCK";
const ENV_MEMPOOL_TX_CAPACITY: &str = "MIDEN_NODE_MEMPOOL_TX_CAPACITY";
const ENV_NTX_SCRIPT_CACHE_SIZE: &str = "MIDEN_NTX_DATA_STORE_SCRIPT_CACHE_SIZE";
const ENV_VALIDATOR_INSECURE_SECRET_KEY: &str = "MIDEN_NODE_VALIDATOR_INSECURE_SECRET_KEY";

const DEFAULT_NTX_TICKER_INTERVAL: Duration = Duration::from_millis(200);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_NTX_SCRIPT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

// Formats a Duration into a human-readable string for display in clap help text.
fn duration_to_human_readable_string(duration: Duration) -> String {
    humantime::format_duration(duration).to_string()
}

/// Configuration for the Network Transaction Builder component
#[derive(clap::Args)]
pub struct NtxBuilderConfig {
    /// Disable spawning the network transaction builder.
    #[arg(long = "no-ntx-builder", default_value_t = false)]
    pub disabled: bool,

    /// The remote transaction prover's gRPC url, used for the ntx builder. If unset,
    /// will default to running a prover in-process which is expensive.
    #[arg(long = "tx-prover.url", env = ENV_NTX_PROVER_URL, value_name = "URL")]
    pub tx_prover_url: Option<Url>,

    /// Interval at which to run the network transaction builder's ticker.
    #[arg(
        long = "ntx-builder.interval",
        default_value = &duration_to_human_readable_string(DEFAULT_NTX_TICKER_INTERVAL),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub ticker_interval: Duration,

    #[arg(
        long = "ntx-builder.script-cache-size",
        env = ENV_NTX_SCRIPT_CACHE_SIZE,
        value_name = "NUM",
        default_value_t = DEFAULT_NTX_SCRIPT_CACHE_SIZE
    )]
    pub script_cache_size: NonZeroUsize,
}

/// Configuration for the Block Producer component
#[derive(clap::Args)]
pub struct BlockProducerConfig {
    /// Interval at which to produce blocks.
    #[arg(
        long = "block.interval",
        default_value = &duration_to_human_readable_string(DEFAULT_BLOCK_INTERVAL),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub block_interval: Duration,

    /// Interval at which to produce batches.
    #[arg(
        long = "batch.interval",
        default_value = &duration_to_human_readable_string(DEFAULT_BATCH_INTERVAL),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub batch_interval: Duration,

    /// The remote batch prover's gRPC url. If unset, will default to running a prover
    /// in-process which is expensive.
    #[arg(long = "batch-prover.url", env = ENV_BATCH_PROVER_URL, value_name = "URL")]
    pub batch_prover_url: Option<Url>,

    /// The number of transactions per batch.
    #[arg(
        long = "max-txs-per-batch",
        env = ENV_MAX_TXS_PER_BATCH,
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_TXS_PER_BATCH
    )]
    pub max_txs_per_batch: usize,

    /// Maximum number of batches per block.
    #[arg(
        long = "max-batches-per-block",
        env = ENV_MAX_BATCHES_PER_BLOCK,
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_BATCHES_PER_BLOCK
    )]
    pub max_batches_per_block: usize,

    /// Maximum number of uncommitted transactions allowed in the mempool.
    #[arg(
        long = "mempool.tx-capacity",
        default_value_t = miden_node_block_producer::DEFAULT_MEMPOOL_TX_CAPACITY,
        env = ENV_MEMPOOL_TX_CAPACITY,
        value_name = "NUM"
    )]
    mempool_tx_capacity: NonZeroUsize,
}
