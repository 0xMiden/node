use std::num::NonZeroUsize;
use std::time::Duration;

use miden_node_block_producer::{
    DEFAULT_BATCH_INTERVAL,
    DEFAULT_BLOCK_INTERVAL,
    DEFAULT_MAX_BATCHES_PER_BLOCK,
    DEFAULT_MAX_TXS_PER_BATCH,
};
use miden_node_utils::clap::duration_to_human_readable_string;
use miden_node_validator::ValidatorSigner;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::utils::serde::Deserializable;
use url::Url;

pub mod block_producer;
pub mod ntx_builder;
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
const ENV_VALIDATOR_KEY: &str = "MIDEN_NODE_VALIDATOR_KEY";
const ENV_VALIDATOR_KMS_KEY_ID: &str = "MIDEN_NODE_VALIDATOR_KMS_KEY_ID";
const ENV_NTX_DATA_DIRECTORY: &str = "MIDEN_NODE_NTX_DATA_DIRECTORY";
const ENV_NTX_BUILDER_URL: &str = "MIDEN_NODE_NTX_BUILDER_URL";
const ENV_NTX_MAX_CYCLES: &str = "MIDEN_NTX_MAX_CYCLES";

const DEFAULT_NTX_TICKER_INTERVAL: Duration = Duration::from_millis(200);
const DEFAULT_NTX_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_NTX_SCRIPT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
const DEFAULT_NTX_MAX_CYCLES: u32 = 1 << 18;

/// Configuration for the Validator key used to sign blocks.
///
/// Used by the Validator command and the genesis bootstrap command.
#[derive(clap::Args)]
#[group(required = false, multiple = false)]
pub struct ValidatorKey {
    /// Insecure, hex-encoded validator secret key for development and testing purposes.
    ///
    /// If not provided, a predefined key is used.
    ///
    /// Cannot be used with `validator.key.kms-id`.
    #[arg(
        long = "validator.key.hex",
        env = ENV_VALIDATOR_KEY,
        value_name = "VALIDATOR_KEY",
        default_value = INSECURE_VALIDATOR_KEY_HEX,
    )]
    validator_key: String,
    /// Key ID for the KMS key used by validator to sign blocks.
    ///
    /// Cannot be used with `validator.key.hex`.
    #[arg(
        long = "validator.key.kms-id",
        env = ENV_VALIDATOR_KMS_KEY_ID,
        value_name = "VALIDATOR_KMS_KEY_ID",
    )]
    validator_kms_key_id: Option<String>,
}

impl ValidatorKey {
    /// Consumes the validator key configuration and returns a KMS or local key signer depending on
    /// the supplied configuration.
    pub async fn into_signer(self) -> anyhow::Result<ValidatorSigner> {
        if let Some(kms_key_id) = self.validator_kms_key_id {
            // Use KMS key ID to create a ValidatorSigner.
            let signer = ValidatorSigner::new_kms(kms_key_id).await?;
            Ok(signer)
        } else {
            // Use hex-encoded key to create a ValidatorSigner.
            let signer = SecretKey::read_from_bytes(hex::decode(self.validator_key)?.as_ref())?;
            let signer = ValidatorSigner::new_local(signer);
            Ok(signer)
        }
    }
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
