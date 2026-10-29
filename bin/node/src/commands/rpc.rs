use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use anyhow::Context;
use clap::ArgGroup;
use miden_node_utils::clap::duration_to_human_readable_string;
use miden_node_utils::genesis::OfficialNetwork;
use tonic::metadata::AsciiMetadataValue;
use url::Url;

// RPC OPTIONS
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct RpcOptions {
    /// Socket address at which to serve the public RPC API.
    #[arg(long = "rpc.listen", env = "MIDEN_NODE_RPC_LISTEN", value_name = "IP:PORT")]
    pub listen: SocketAddr,

    #[command(flatten)]
    pub sync_account: SyncAccountOptions,

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
        miden_node_utils::clap::GrpcOptions {
            request_timeout: self.grpc.timeout,
            message_size: self.grpc.message_size,
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

#[derive(clap::Args, Clone, Copy, Debug)]
pub struct SyncAccountOptions {
    /// Maximum total storage slots, map entries, and vault assets accepted by `SyncAccount`.
    #[arg(
        long = "rpc.sync-account.limit",
        env = "MIDEN_NODE_RPC_SYNC_ACCOUNT_LIMIT",
        default_value_t = miden_node_rpc::SyncAccountConfig::default().limit,
        value_name = "ENTRIES",
        help_heading = super::section::RPC_CONFIGURATION_HELP_HEADING
    )]
    pub limit: NonZeroU32,

    /// Return a snapshot for changed accounts with at most this many map entries and vault assets.
    #[arg(
        long = "rpc.sync-account.snapshot-threshold",
        env = "MIDEN_NODE_RPC_SYNC_ACCOUNT_SNAPSHOT_THRESHOLD",
        default_value_t = miden_node_rpc::SyncAccountConfig::default().snapshot_threshold,
        value_name = "ENTRIES",
        help_heading = super::section::RPC_CONFIGURATION_HELP_HEADING
    )]
    pub snapshot_threshold: u32,

    /// Maximum map entries and vault assets in a delta before falling back to a snapshot.
    #[arg(
        long = "rpc.sync-account.delta-limit",
        env = "MIDEN_NODE_RPC_SYNC_ACCOUNT_DELTA_LIMIT",
        default_value_t = miden_node_rpc::SyncAccountConfig::default().delta_limit,
        value_name = "ENTRIES",
        help_heading = super::section::RPC_CONFIGURATION_HELP_HEADING
    )]
    pub delta_limit: NonZeroU32,
}

impl From<SyncAccountOptions> for miden_node_rpc::SyncAccountConfig {
    fn from(options: SyncAccountOptions) -> Self {
        Self {
            limit: options.limit,
            snapshot_threshold: options.snapshot_threshold,
            delta_limit: options.delta_limit,
        }
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct GrpcOptions {
    #[command(flatten)]
    pub message_size: miden_node_utils::clap::GrpcMessageSizeOptions,
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
#[command(group(
    ArgGroup::new("block_sync_source")
        .required(true)
        .multiple(false)
        .args(["block_source_url", "network"])
))]
pub struct SyncOptions {
    /// Upstream block sync source.
    ///
    /// This URL must host the RPC's block and proof subscription methods.
    #[arg(
        long = "sync.block-source.url",
        env = "MIDEN_NODE_SYNC_BLOCK_SOURCE_URL",
        value_name = "URL"
    )]
    pub block_source_url: Option<Url>,

    /// Sync from an official Miden network's public RPC endpoint.
    #[arg(long, value_enum, value_name = "NETWORK")]
    pub network: Option<OfficialNetwork>,

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

impl SyncOptions {
    pub fn block_source_url(&self) -> Url {
        match (&self.block_source_url, self.network) {
            (Some(url), None) => url.clone(),
            (None, Some(network)) => network.rpc_url(),
            _ => unreachable!("clap requires exactly one block sync source"),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::SyncAccountOptions;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        options: SyncAccountOptions,
    }

    #[test]
    fn sync_account_options_accept_tuning_and_reject_zero_limits() {
        let options = Command::try_parse_from([
            "node",
            "--rpc.sync-account.limit",
            "2000",
            "--rpc.sync-account.snapshot-threshold",
            "0",
            "--rpc.sync-account.delta-limit",
            "50",
        ])
        .unwrap()
        .options;
        let config = miden_node_rpc::SyncAccountConfig::from(options);
        assert_eq!(config.limit.get(), 2000);
        assert_eq!(config.snapshot_threshold, 0);
        assert_eq!(config.delta_limit.get(), 50);
        for flag in ["--rpc.sync-account.limit", "--rpc.sync-account.delta-limit"] {
            assert!(Command::try_parse_from(["node", flag, "0"]).is_err());
        }
    }
}
