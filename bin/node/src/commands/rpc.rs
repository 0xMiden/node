use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use miden_node_utils::clap::duration_to_human_readable_string;
use tonic::metadata::AsciiMetadataValue;
use url::Url;

// RPC OPTIONS
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct RpcOptions {
    /// Socket address at which to serve the public RPC API.
    #[arg(long = "rpc.listen", env = "MIDEN_NODE_RPC_LISTEN", value_name = "IP:PORT")]
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
}

impl RpcOptions {
    pub(super) fn grpc_options(&self) -> miden_node_utils::clap::GrpcOptions {
        miden_node_utils::clap::GrpcOptions { request_timeout: self.grpc.timeout }
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

    // Number of blocks that this RPC server must be within that of the sync source to be considered
    // ready.
    #[arg(
        long = "sync.ready-threshold",
        env = "MIDEN_NODE_SYNC_READY_THRESHOLD",
        value_name = "NUM",
        default_value_t = 10
    )]
    pub readiness_threshold: u32,
}
