use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use anyhow::Context;
use miden_node_utils::clap::{GrpcOptionsExternal, duration_to_human_readable_string};
use tonic::metadata::AsciiMetadataValue;
use url::Url;

// RPC OPTIONS
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct RpcOptions {
    /// Socket address at which to serve the public RPC API.
    #[arg(long = "rpc.listen", env = "MIDEN_NODE_RPC_LISTEN", value_name = "LISTEN")]
    pub listen: SocketAddr,

    /// Optional metadata header value for internal network-transaction RPC authentication.
    #[arg(
        long = "rpc.network-tx-auth-header-value",
        env = "MIDEN_NODE_RPC_NETWORK_TX_AUTH_HEADER_VALUE",
        value_name = "VALUE",
        help_heading = super::section::RPC_CONFIGURATION_HELP_HEADING
    )]
    pub network_tx_auth_header_value: Option<String>,

    #[command(flatten)]
    pub grpc: GrpcOptions,

    #[command(flatten)]
    pub rate_limit: RpcRateLimitOptions,
}

impl RpcOptions {
    pub(super) fn external_grpc_options(&self) -> GrpcOptionsExternal {
        GrpcOptionsExternal {
            request_timeout: self.grpc.timeout,
            max_connection_age: self.grpc.max_connection_age,
            burst_size: self.rate_limit.burst_size,
            replenish_n_per_second_per_ip: self.rate_limit.replenish_per_second,
            max_concurrent_connections: self.rate_limit.max_concurrent_connections,
        }
    }

    pub(super) fn network_tx_auth(&self) -> anyhow::Result<Option<AsciiMetadataValue>> {
        self.network_tx_auth_header_value
            .as_deref()
            .map(|value| {
                value
                    .parse::<AsciiMetadataValue>()
                    .context("invalid rpc.network-tx-auth-header-value")
            })
            .transpose()
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct GrpcOptions {
    /// Maximum duration a gRPC request is allocated before being dropped by the server.
    #[arg(
        long = "rpc.grpc.timeout",
        env = "MIDEN_NODE_RPC_GRPC_TIMEOUT",
        default_value = duration_to_human_readable_string(Duration::from_secs(10)),
        value_parser = humantime::parse_duration,
        value_name = "DURATION",
        help_heading = super::section::RPC_CONFIGURATION_HELP_HEADING
    )]
    pub timeout: Duration,

    /// Maximum duration of an RPC connection before the server drops it irrespective of activity.
    #[arg(
        long = "rpc.grpc.max-connection-age",
        env = "MIDEN_NODE_RPC_GRPC_MAX_CONNECTION_AGE",
        default_value = duration_to_human_readable_string(Duration::from_secs(30 * 60)),
        value_parser = humantime::parse_duration,
        value_name = "DURATION",
        help_heading = super::section::RPC_CONFIGURATION_HELP_HEADING
    )]
    pub max_connection_age: Duration,
}

#[derive(clap::Args, Clone, Debug)]
pub struct RpcRateLimitOptions {
    /// Number of RPC request credits available per IP before replenishment.
    #[arg(
        long = "rpc.rate-limit.burst-size",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_BURST_SIZE",
        default_value_t = NonZeroU32::new(128).unwrap(),
        value_name = "NUM",
        help_heading = super::section::RPC_RATE_LIMITING_HELP_HEADING
    )]
    pub burst_size: NonZeroU32,

    /// Number of RPC request credits replenished per second per IP.
    #[arg(
        long = "rpc.rate-limit.replenish-per-second",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_REPLENISH_PER_SECOND",
        default_value_t = NonZeroU64::new(16).unwrap(),
        value_name = "NUM",
        help_heading = super::section::RPC_RATE_LIMITING_HELP_HEADING
    )]
    pub replenish_per_second: NonZeroU64,

    /// Maximum number of concurrent RPC connections accepted by the server.
    #[arg(
        long = "rpc.rate-limit.max-concurrent-connections",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_MAX_CONCURRENT_CONNECTIONS",
        default_value_t = 1_000,
        value_name = "NUM",
        help_heading = super::section::RPC_RATE_LIMITING_HELP_HEADING
    )]
    pub max_concurrent_connections: u64,
}

#[derive(clap::Args, Clone, Debug)]
pub struct SyncOptions {
    /// Upstream block sync source.
    ///
    /// This URL must host the RPC's block and proof subscription methods.
    #[arg(
        long = "sync.block-source.url",
        env = "MIDEN_NODE_SYNC_BLOCK_SOURCE_URL",
        value_name = "URL"
    )]
    pub block_source_url: Url,
}
