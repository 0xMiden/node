use std::time::Duration;

use anyhow::Context;
use miden_node_block_producer::BlockProducer;
use miden_node_utils::grpc::UrlExt;
use url::Url;

use super::{ENV_BLOCK_PRODUCER_URL, ENV_STORE_BLOCK_PRODUCER_URL};
use crate::commands::{
    BlockProducerConfig,
    DEFAULT_TIMEOUT,
    ENV_ENABLE_OTEL,
    ENV_VALIDATOR_BLOCK_PRODUCER_URL,
    duration_to_human_readable_string,
};

#[derive(clap::Subcommand)]
pub enum BlockProducerCommand {
    /// Starts the block-producer component.
    Start {
        /// Url at which to serve the gRPC API.
        #[arg(env = ENV_BLOCK_PRODUCER_URL)]
        url: Url,

        /// The store's block-producer service gRPC url.
        #[arg(long = "store.url", env = ENV_STORE_BLOCK_PRODUCER_URL)]
        store_url: Url,

        /// The validator's service gRPC url.
        #[arg(long = "validator.url", env = ENV_VALIDATOR_BLOCK_PRODUCER_URL)]
        validator_url: Url,

        #[command(flatten)]
        block_producer: BlockProducerConfig,

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        /// Maximum duration a gRPC request is allocated before being dropped by the server.
        ///
        /// This may occur if the server is overloaded or due to an internal bug.
        #[arg(
            long = "grpc.timeout",
            default_value = &duration_to_human_readable_string(DEFAULT_TIMEOUT),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        grpc_timeout: Duration,
    },
}

impl BlockProducerCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let Self::Start {
            url,
            store_url,
            validator_url,
            block_producer,
            enable_otel: _,
            grpc_timeout,
        } = self;

        let block_producer_address =
            url.to_socket().context("Failed to extract socket address from store URL")?;

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
            grpc_timeout,
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
            url: dummy_url(),
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
            grpc_timeout: Duration::from_secs(10),
        };
        let result = cmd.handle().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("max-batches-per-block"));
    }

    #[tokio::test]
    async fn rejects_too_large_max_txs_per_batch() {
        let cmd = BlockProducerCommand::Start {
            url: dummy_url(),
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
            grpc_timeout: Duration::from_secs(10),
        };
        let result = cmd.handle().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("max-txs-per-batch"));
    }
}
