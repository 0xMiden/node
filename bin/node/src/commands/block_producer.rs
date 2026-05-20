use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use anyhow::Context;
use miden_node_block_producer::{
    BlockProducer,
    DEFAULT_BATCH_INTERVAL,
    DEFAULT_BLOCK_INTERVAL,
    DEFAULT_MAX_BATCHES_PER_BLOCK,
    DEFAULT_MAX_TXS_PER_BATCH,
};
use miden_node_utils::clap::{GrpcOptionsInternal, duration_to_human_readable_string};
use url::Url;

use super::ENV_ENABLE_OTEL;

const ENV_LISTEN: &str = "MIDEN_NODE_BLOCK_PRODUCER_LISTEN";
const ENV_STORE_URL: &str = "MIDEN_NODE_BLOCK_PRODUCER_STORE_URL";
const ENV_VALIDATOR_URL: &str = "MIDEN_NODE_BLOCK_PRODUCER_VALIDATOR_URL";
const ENV_MAX_TXS_PER_BATCH: &str = "MIDEN_NODE_BLOCK_PRODUCER_MAX_TXS_PER_BATCH";
const ENV_MAX_BATCHES_PER_BLOCK: &str = "MIDEN_NODE_BLOCK_PRODUCER_MAX_BATCHES_PER_BLOCK";
const ENV_MEMPOOL_TX_CAPACITY: &str = "MIDEN_NODE_BLOCK_PRODUCER_MEMPOOL_TX_CAPACITY";
const ENV_BATCH_PROVER_URL: &str = "MIDEN_NODE_BLOCK_PRODUCER_BATCH_PROVER_URL";

// BLOCK PRODUCER COMMAND
// ================================================================================================

#[derive(clap::Subcommand)]
pub enum BlockProducerCommand {
    /// Starts the block-producer component.
    Start {
        /// Socket address at which to serve the gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: SocketAddr,

        /// The store's block-producer service gRPC url.
        #[arg(long = "store.url", env = ENV_STORE_URL)]
        store_url: Url,

        /// The validator's service gRPC url.
        #[arg(long = "validator.url", env = ENV_VALIDATOR_URL)]
        validator_url: Url,

        #[command(flatten)]
        block_producer: BlockProducerConfig,

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        #[command(flatten)]
        grpc_options: GrpcOptionsInternal,
    },
}

impl BlockProducerCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let Self::Start {
            listen,
            store_url,
            validator_url,
            block_producer,
            enable_otel: _,
            grpc_options,
        } = self;

        let block_producer_address = listen;

        // Runtime validation for protocol constraints
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

        BlockProducer {
            block_producer_address,
            store_url,
            validator_url,
            batch_prover_url: block_producer.batch_prover_url,
            batch_interval: block_producer.batch_interval,
            block_interval: block_producer.block_interval,
            max_txs_per_batch: block_producer.max_txs_per_batch,
            max_batches_per_block: block_producer.max_batches_per_block,
            grpc_options,
            mempool_tx_capacity: block_producer.mempool_tx_capacity,
        }
        .serve()
        .await
        .context("failed while serving block-producer component")
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        let Self::Start { enable_otel, .. } = self;
        *enable_otel
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use url::Url;

    use super::*;

    fn dummy_url() -> Url {
        Url::parse("http://127.0.0.1:1234").unwrap()
    }

    #[tokio::test]
    async fn rejects_too_large_max_batches_per_block() {
        let cmd = BlockProducerCommand::Start {
            listen: "[::1]:0".parse().unwrap(),
            store_url: dummy_url(),
            validator_url: dummy_url(),
            block_producer: BlockProducerConfig {
                batch_prover_url: None,
                block_interval: std::time::Duration::from_secs(1),
                batch_interval: std::time::Duration::from_secs(1),
                max_txs_per_batch: 8,
                max_batches_per_block: miden_protocol::MAX_BATCHES_PER_BLOCK + 1, // Invalid value
                mempool_tx_capacity: NonZeroUsize::new(1000).unwrap(),
            },
            enable_otel: false,
            grpc_options: GrpcOptionsInternal::default(),
        };
        let result = cmd.handle().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("max-batches-per-block"));
    }

    #[tokio::test]
    async fn rejects_too_large_max_txs_per_batch() {
        let cmd = BlockProducerCommand::Start {
            listen: "[::1]:0".parse().unwrap(),
            store_url: dummy_url(),
            validator_url: dummy_url(),
            block_producer: BlockProducerConfig {
                batch_prover_url: None,
                block_interval: std::time::Duration::from_secs(1),
                batch_interval: std::time::Duration::from_secs(1),
                max_txs_per_batch: miden_protocol::MAX_ACCOUNTS_PER_BATCH + 1, /* Use protocol
                                                                                * limit
                                                                                * (should fail) */
                max_batches_per_block: 8,
                mempool_tx_capacity: NonZeroUsize::new(1000).unwrap(),
            },
            enable_otel: false,
            grpc_options: GrpcOptionsInternal::default(),
        };
        let result = cmd.handle().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("max-txs-per-batch"));
    }
}

// BLOCK PRODUCER CONFIG
// ================================================================================================

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

    /// The remote batch prover's gRPC url. If unset, will default to running a prover in-process
    /// which is expensive.
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
