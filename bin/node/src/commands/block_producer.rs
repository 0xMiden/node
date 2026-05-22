use std::num::NonZeroUsize;
use std::time::Duration;

use miden_node_block_producer::{
    DEFAULT_BATCH_INTERVAL,
    DEFAULT_BLOCK_INTERVAL,
    DEFAULT_MAX_BATCHES_PER_BLOCK,
    DEFAULT_MAX_TXS_PER_BATCH,
};
use miden_node_store::DEFAULT_MAX_CONCURRENT_PROOFS;
use miden_node_utils::clap::duration_to_human_readable_string;
use url::Url;

// BLOCK PRODUCTION
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct BlockProducerOptions {
    #[command(flatten)]
    pub batch: BatchOptions,

    #[command(flatten)]
    pub block: BlockOptions,

    #[command(flatten)]
    pub block_prover: BlockProverOptions,

    #[command(flatten)]
    pub mempool: MempoolOptions,
}

impl BlockProducerOptions {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.block.max_batches > miden_protocol::MAX_BATCHES_PER_BLOCK {
            anyhow::bail!(
                "block.max-batches cannot exceed protocol limit of {}",
                miden_protocol::MAX_BATCHES_PER_BLOCK
            );
        }

        if self.batch.max_txs > miden_protocol::MAX_ACCOUNTS_PER_BATCH {
            anyhow::bail!(
                "batch.max-txs cannot exceed protocol limit of {}",
                miden_protocol::MAX_ACCOUNTS_PER_BATCH
            );
        }

        Ok(())
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct BatchOptions {
    /// Interval at which to produce batches.
    #[arg(
        id = "batch.interval",
        long = "batch.interval",
        env = "MIDEN_NODE_BATCH_INTERVAL",
        default_value = duration_to_human_readable_string(DEFAULT_BATCH_INTERVAL),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub interval: Duration,

    /// Maximum number of transactions per batch.
    #[arg(
        id = "batch.max-txs",
        long = "batch.max-txs",
        env = "MIDEN_NODE_BATCH_MAX_TXS",
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_TXS_PER_BATCH
    )]
    pub max_txs: usize,

    /// The remote batch prover gRPC URL. If unset, a local prover will be used.
    #[arg(
        id = "batch-prover.url",
        long = "batch-prover.url",
        env = "MIDEN_NODE_BATCH_PROVER_URL",
        value_name = "URL"
    )]
    pub prover_url: Option<Url>,
}

#[derive(clap::Args, Clone, Debug)]
pub struct BlockOptions {
    /// Interval at which to produce blocks.
    #[arg(
        id = "block.interval",
        long = "block.interval",
        env = "MIDEN_NODE_BLOCK_INTERVAL",
        default_value = duration_to_human_readable_string(DEFAULT_BLOCK_INTERVAL),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub interval: Duration,

    /// Maximum number of batches per block.
    #[arg(
        id = "block.max-batches",
        long = "block.max-batches",
        env = "MIDEN_NODE_BLOCK_MAX_BATCHES",
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_BATCHES_PER_BLOCK
    )]
    pub max_batches: usize,

    /// Maximum number of concurrent block proofs to be scheduled.
    #[arg(
        id = "block.max-concurrent-proofs",
        long = "block.max-concurrent-proofs",
        env = "MIDEN_NODE_BLOCK_MAX_CONCURRENT_PROOFS",
        default_value_t = DEFAULT_MAX_CONCURRENT_PROOFS,
        value_name = "NUM"
    )]
    pub max_concurrent_proofs: NonZeroUsize,
}

#[derive(clap::Args, Clone, Debug)]
pub struct BlockProverOptions {
    /// The remote block prover gRPC URL. If not provided, a local block prover will be used.
    #[arg(
        id = "block-prover.url",
        long = "block-prover.url",
        env = "MIDEN_NODE_BLOCK_PROVER_URL",
        value_name = "URL"
    )]
    pub url: Option<Url>,
}

#[derive(clap::Args, Clone, Debug)]
pub struct MempoolOptions {
    /// Maximum number of uncommitted transactions allowed in the mempool.
    #[arg(
        id = "mempool.tx-capacity",
        long = "mempool.tx-capacity",
        default_value_t = miden_node_block_producer::DEFAULT_MEMPOOL_TX_CAPACITY,
        env = "MIDEN_NODE_MEMPOOL_TX_CAPACITY",
        value_name = "NUM"
    )]
    pub tx_capacity: NonZeroUsize,
}
