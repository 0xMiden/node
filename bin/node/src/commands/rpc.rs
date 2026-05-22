use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use miden_node_utils::clap::{
    GrpcOptionsExternal,
    GrpcOptionsInternal,
    duration_to_human_readable_string,
};
use url::Url;

// RPC OPTIONS
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct RpcOptions {
    /// Socket address at which to serve the public RPC API.
    #[arg(long = "rpc.listen", env = "MIDEN_NODE_RPC_LISTEN", value_name = "LISTEN")]
    pub listen: SocketAddr,

    #[command(flatten)]
    pub grpc: RpcGrpcOptions,

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
}

#[derive(clap::Args, Clone, Debug)]
pub struct RpcGrpcOptions {
    /// Maximum duration a gRPC request is allocated before being dropped by the server.
    #[arg(
        long = "rpc.grpc.timeout",
        env = "MIDEN_NODE_RPC_GRPC_TIMEOUT",
        default_value = duration_to_human_readable_string(Duration::from_secs(10)),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub timeout: Duration,

    /// Maximum duration of an RPC connection before the server drops it irrespective of activity.
    #[arg(
        long = "rpc.grpc.max-connection-age",
        env = "MIDEN_NODE_RPC_GRPC_MAX_CONNECTION_AGE",
        default_value = duration_to_human_readable_string(Duration::from_secs(30 * 60)),
        value_parser = humantime::parse_duration,
        value_name = "DURATION"
    )]
    pub max_connection_age: Duration,
}

impl RpcGrpcOptions {
    pub(super) fn internal_grpc_options(&self) -> GrpcOptionsInternal {
        GrpcOptionsInternal { request_timeout: self.timeout }
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct RpcRateLimitOptions {
    /// Number of RPC connections to be served before API tokens are replenished per IP address.
    #[arg(
        long = "rpc.rate-limit.burst-size",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_BURST_SIZE",
        default_value_t = NonZeroU32::new(128).unwrap(),
        value_name = "NUM"
    )]
    pub burst_size: NonZeroU32,

    /// Number of RPC request credits replenished per second per IP.
    #[arg(
        long = "rpc.rate-limit.replenish-per-second",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_REPLENISH_PER_SECOND",
        default_value_t = NonZeroU64::new(16).unwrap(),
        value_name = "NUM"
    )]
    pub replenish_per_second: NonZeroU64,

    /// Maximum number of concurrent RPC connections accepted by the server.
    #[arg(
        long = "rpc.rate-limit.max-concurrent-connections",
        env = "MIDEN_NODE_RPC_RATE_LIMIT_MAX_CONCURRENT_CONNECTIONS",
        default_value_t = 1_000,
        value_name = "NUM"
    )]
    pub max_concurrent_connections: u64,
}

#[derive(clap::Args, Clone, Debug)]
pub struct SyncOptions {
    /// URL for the block stream source used to sync this node's store.
    #[arg(
        long = "sync.block-source.url",
        env = "MIDEN_NODE_SYNC_BLOCK_SOURCE_URL",
        value_name = "URL"
    )]
    pub block_source_url: Url,
}
