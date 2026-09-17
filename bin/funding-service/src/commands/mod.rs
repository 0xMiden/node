use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use miden_funding_service::{
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_AMOUNT,
    DEFAULT_MAX_NOTES_PER_TX,
    DEFAULT_P2ID_COLLECTION_INTERVAL,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_RPC_TIMEOUT,
    DEFAULT_TX_EXPIRATION_DELTA,
    DEFAULT_TX_PROVER_TIMEOUT,
    FundingServiceConfig,
};
use miden_node_tracing::{OpenTelemetry, info};
use miden_node_utils::clap::duration_to_human_readable_string;
use miden_node_utils::formatting::format_endpoint;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::utils::serde::Deserializable;
use tokio::net::TcpListener;
use url::Url;

const ENV_LISTEN: &str = "MIDEN_FUNDING_LISTEN";
const ENV_HTTP_TIMEOUT: &str = "MIDEN_FUNDING_HTTP_TIMEOUT";
const ENV_RPC_URL: &str = "MIDEN_FUNDING_RPC_URL";
const ENV_RPC_TIMEOUT: &str = "MIDEN_FUNDING_RPC_TIMEOUT";
const ENV_TX_PROVER_URL: &str = "MIDEN_FUNDING_TX_PROVER_URL";
const ENV_TX_PROVER_TIMEOUT: &str = "MIDEN_FUNDING_TX_PROVER_TIMEOUT";
const ENV_ACCOUNT_FILE: &str = "MIDEN_FUNDING_ACCOUNT_FILE";
const ENV_MAX_AMOUNT: &str = "MIDEN_FUNDING_MAX_AMOUNT";
const ENV_P2ID_COLLECTION_INTERVAL: &str = "MIDEN_FUNDING_P2ID_COLLECTION_INTERVAL";
const ENV_MAX_NOTES_PER_TX: &str = "MIDEN_FUNDING_MAX_NOTES_PER_TX";
const ENV_TX_EXPIRATION_DELTA: &str = "MIDEN_FUNDING_TX_EXPIRATION_DELTA";
const ENV_POLL_INTERVAL: &str = "MIDEN_FUNDING_POLL_INTERVAL";
const ENV_VALIDATOR_SIGNING_PUBLIC_KEYS: &str = "MIDEN_FUNDING_VALIDATOR_SIGNING_PUBLIC_KEYS";

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub enum FundingServiceCommand {
    /// Starts the funding service.
    Start {
        /// Socket address at which to serve the funding service's HTTP API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "IP:PORT")]
        listen: SocketAddr,

        /// Maximum duration allocated to an HTTP request served by the funding service.
        #[arg(
            long = "http.timeout",
            env = ENV_HTTP_TIMEOUT,
            default_value = duration_to_human_readable_string(DEFAULT_HTTP_TIMEOUT),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        http_timeout: Duration,

        /// The node RPC service gRPC url.
        #[arg(long = "rpc.url", env = ENV_RPC_URL, value_name = "URL")]
        rpc_url: Url,

        /// Request timeout for calls to the node RPC service.
        #[arg(
            long = "rpc.timeout",
            env = ENV_RPC_TIMEOUT,
            default_value = duration_to_human_readable_string(DEFAULT_RPC_TIMEOUT),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        rpc_timeout: Duration,

        /// The remote transaction prover's gRPC url.
        #[arg(long = "tx-prover.url", env = ENV_TX_PROVER_URL, value_name = "URL")]
        tx_prover_url: Option<Url>,

        /// Request timeout for calls to the remote transaction prover.
        #[arg(
            long = "tx-prover.timeout",
            env = ENV_TX_PROVER_TIMEOUT,
            default_value = duration_to_human_readable_string(DEFAULT_TX_PROVER_TIMEOUT),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        tx_prover_timeout: Duration,

        /// Path to the account file of the funding account.
        #[arg(long = "account-file", env = ENV_ACCOUNT_FILE, value_name = "PATH")]
        account_file: PathBuf,

        /// Largest amount one request may ask for, in base units of the native asset.
        #[arg(
            long = "max-amount",
            env = ENV_MAX_AMOUNT,
            default_value_t = DEFAULT_MAX_AMOUNT,
            value_name = "AMOUNT"
        )]
        max_amount: u64,

        /// Largest number of notes one funding transaction creates.
        #[arg(
            long = "max-notes-per-tx",
            env = ENV_MAX_NOTES_PER_TX,
            default_value_t = DEFAULT_MAX_NOTES_PER_TX,
            value_name = "NUM"
        )]
        max_notes_per_tx: NonZeroUsize,

        /// Number of blocks after its reference block at which a funding transaction expires.
        #[arg(
            long = "tx-expiration-delta",
            env = ENV_TX_EXPIRATION_DELTA,
            default_value_t = DEFAULT_TX_EXPIRATION_DELTA,
            value_name = "BLOCKS"
        )]
        tx_expiration_delta: NonZeroU16,

        /// Interval at which the funding worker runs a cycle while it has work.
        #[arg(
            long = "poll-interval",
            env = ENV_POLL_INTERVAL,
            default_value = duration_to_human_readable_string(DEFAULT_POLL_INTERVAL),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        poll_interval: Duration,

        /// Interval at which the service scans for the pay-to-ID notes sent to the funding account.
        #[arg(
            long = "p2id-collection-interval",
            env = ENV_P2ID_COLLECTION_INTERVAL,
            default_value = duration_to_human_readable_string(DEFAULT_P2ID_COLLECTION_INTERVAL),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        p2id_collection_interval: Duration,

        /// Hex-encoded validator signing public key trusted to attest the transaction encryption
        /// key.
        #[arg(
            long = "validator-signing-public-key",
            env = ENV_VALIDATOR_SIGNING_PUBLIC_KEYS,
            value_delimiter = ',',
            value_parser = parse_validator_public_key,
            required = true,
            value_name = "HEX"
        )]
        validator_signing_public_keys: Vec<ValidatorPublicKey>,
    },
}

impl FundingServiceCommand {
    pub async fn handle(self, shutdown: CancellationToken) -> Result<()> {
        let Self::Start {
            listen,
            http_timeout,
            rpc_url,
            rpc_timeout,
            tx_prover_url,
            tx_prover_timeout,
            account_file,
            max_amount,
            max_notes_per_tx,
            tx_expiration_delta,
            poll_interval,
            p2id_collection_interval,
            validator_signing_public_keys,
        } = self;

        info!(
            target: miden_funding_service::LOG_TARGET,
            "Starting the funding service",
            service.name = "miden-funding-service",
            service.version = env!("CARGO_PKG_VERSION"),
            funding_service.listen = listen.to_string(),
            http.timeout = humantime::Duration::from(http_timeout).to_string(),
            rpc.endpoint = format_endpoint(&rpc_url),
            rpc.timeout = humantime::Duration::from(rpc_timeout).to_string(),
            tx_prover.endpoint =
                tx_prover_url.as_ref().map_or_else(|| "local".to_owned(), format_endpoint),
            account.file = account_file.as_path(),
            funding_service.max_amount = max_amount,
            funding_service.max_notes_per_tx = max_notes_per_tx.get(),
            funding_service.tx_expiration_delta = tx_expiration_delta.get(),
            funding_service.poll_interval = humantime::Duration::from(poll_interval).to_string(),
            funding_service.p2id_collection_interval =
                humantime::Duration::from(p2id_collection_interval).to_string()
        );

        let listener = TcpListener::bind(listen)
            .await
            .context("failed to bind to the funding service's HTTP socket")?;

        FundingServiceConfig::new(rpc_url, account_file, validator_signing_public_keys)
            .with_tx_prover_url(tx_prover_url)
            .with_http_timeout(http_timeout)
            .with_rpc_timeout(rpc_timeout)
            .with_tx_prover_timeout(tx_prover_timeout)
            .with_max_amount(max_amount)
            .with_max_notes_per_tx(max_notes_per_tx)
            .with_tx_expiration_delta(tx_expiration_delta)
            .with_poll_interval(poll_interval)
            .with_p2id_collection_interval(p2id_collection_interval)
            .build()
            .await
            .context("failed to initialize the funding service")?
            .run(listener, shutdown)
            .await
            .context("failed while running the funding service")
    }

    /// The OpenTelemetry configuration of the only command.
    #[expect(
        clippy::unused_self,
        reason = "the caller reads this from the parsed command, like the other binaries"
    )]
    pub fn open_telemetry(&self) -> OpenTelemetry {
        OpenTelemetry::from_env().with_name("funding-service")
    }
}

/// Decodes a hex-encoded validator signing public key.
fn parse_validator_public_key(value: &str) -> Result<ValidatorPublicKey> {
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .context("a validator signing public key must be hex encoded")?;
    ValidatorPublicKey::read_from_bytes(&bytes)
        .context("a validator signing public key must be a valid K256 public key")
}
