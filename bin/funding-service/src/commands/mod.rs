use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use miden_funding_service::{
    DEFAULT_GRPC_TIMEOUT,
    DEFAULT_MAX_AMOUNT,
    DEFAULT_RPC_TIMEOUT,
    FundingServiceConfig,
};
use miden_node_tracing::{OpenTelemetry, info};
use miden_node_utils::clap::duration_to_human_readable_string;
use miden_node_utils::formatting::format_endpoint;
use miden_node_utils::genesis::read_genesis_block;
use miden_node_utils::shutdown::CancellationToken;
use tokio::net::TcpListener;
use url::Url;

const ENV_LISTEN: &str = "MIDEN_FUNDING_LISTEN";
const ENV_GRPC_TIMEOUT: &str = "MIDEN_FUNDING_GRPC_TIMEOUT";
const ENV_RPC_URL: &str = "MIDEN_FUNDING_RPC_URL";
const ENV_RPC_TIMEOUT: &str = "MIDEN_FUNDING_RPC_TIMEOUT";
const ENV_ACCOUNT_FILE: &str = "MIDEN_FUNDING_ACCOUNT_FILE";
const ENV_GENESIS: &str = "MIDEN_FUNDING_GENESIS";
const ENV_MAX_AMOUNT: &str = "MIDEN_FUNDING_MAX_AMOUNT";

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub enum FundingServiceCommand {
    /// Starts the funding service.
    Start {
        /// Socket address at which to serve the funding service's gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: SocketAddr,

        /// Maximum duration allocated to a gRPC request served by the funding service.
        #[arg(
            long = "grpc.timeout",
            env = ENV_GRPC_TIMEOUT,
            default_value = duration_to_human_readable_string(DEFAULT_GRPC_TIMEOUT),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        grpc_timeout: Duration,

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

        /// Path to the account file of the funding account.
        #[arg(long = "account-file", env = ENV_ACCOUNT_FILE, value_name = "PATH")]
        account_file: PathBuf,

        /// Path to a trusted genesis block file, which names the chain's fee asset.
        #[arg(long = "genesis", env = ENV_GENESIS, value_name = "FILE")]
        genesis_block_file: PathBuf,

        /// Largest amount one request may ask for, in base units of the native asset.
        #[arg(
            long = "max-amount",
            env = ENV_MAX_AMOUNT,
            default_value_t = DEFAULT_MAX_AMOUNT,
            value_name = "AMOUNT"
        )]
        max_amount: u64,
    },
}

impl FundingServiceCommand {
    pub async fn handle(self, shutdown: CancellationToken) -> Result<()> {
        let Self::Start {
            listen,
            grpc_timeout,
            rpc_url,
            rpc_timeout,
            account_file,
            genesis_block_file,
            max_amount,
        } = self;

        info!(
            target: miden_funding_service::LOG_TARGET,
            "Starting the funding service",
            service.name = "miden-funding-service",
            service.version = env!("CARGO_PKG_VERSION"),
            funding_service.listen = listen.to_string(),
            grpc.timeout = humantime::Duration::from(grpc_timeout).to_string(),
            rpc.endpoint = format_endpoint(&rpc_url),
            rpc.timeout = humantime::Duration::from(rpc_timeout).to_string(),
            account.file = account_file.as_path(),
            funding_service.max_amount = max_amount
        );

        let genesis =
            read_genesis_block(&genesis_block_file).context("failed to read the genesis block")?;

        let listener = TcpListener::bind(listen)
            .await
            .context("failed to bind to the funding service's gRPC socket")?;

        FundingServiceConfig::new(rpc_url, account_file, genesis)
            .with_grpc_timeout(grpc_timeout)
            .with_rpc_timeout(rpc_timeout)
            .with_max_amount(max_amount)
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
