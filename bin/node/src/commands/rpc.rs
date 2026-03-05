use std::time::Duration;

use anyhow::Context;
use miden_node_rpc::Rpc;
use miden_node_utils::grpc::UrlExt;
use url::Url;

use super::{ENV_BLOCK_PRODUCER_URL, ENV_RPC_URL, ENV_STORE_RPC_URL, ENV_VALIDATOR_URL};
use crate::commands::{
    DEFAULT_BURST_SIZE,
    DEFAULT_MAX_CONNECTION_AGE,
    DEFAULT_MAX_GLOBAL_CONNECTIONS,
    DEFAULT_REPLENISH_PER_SEC,
    DEFAULT_REQUEST_TIMEOUT,
    ENV_ENABLE_OTEL,
    duration_to_human_readable_string,
};

#[derive(clap::Subcommand)]
pub enum RpcCommand {
    /// Starts the RPC component.
    Start {
        /// Url at which to serve the gRPC API.
        #[arg(long = "url", env = ENV_RPC_URL, value_name = "URL")]
        url: Url,

        /// The store's RPC service gRPC url.
        #[arg(long = "store.url", env = ENV_STORE_RPC_URL, value_name = "URL")]
        store_url: Url,

        /// The block-producer's gRPC url. If unset, will run the RPC in read-only mode,
        /// i.e. without a block-producer.
        #[arg(long = "block-producer.url", env = ENV_BLOCK_PRODUCER_URL, value_name = "URL")]
        block_producer_url: Option<Url>,

        /// The validator's gRPC url.
        #[arg(long = "validator.url", env = ENV_VALIDATOR_URL, value_name = "URL")]
        validator_url: Url,

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
            default_value = &duration_to_human_readable_string(DEFAULT_REQUEST_TIMEOUT),
            value_parser = humantime::parse_duration,
            value_name = "DURATION"
        )]
        grpc_request_timeout: Duration,

        /// Maximum duration of a connection before we drop it on the server side irrespective of
        /// activity.
        #[arg(
            long = "grpc.max_connection_age",
            default_value = &duration_to_human_readable_string(DEFAULT_MAX_CONNECTION_AGE),
            value_parser = humantime::parse_duration,
            value_name = "MAX_CONNECTION_AGE"
        )]
        grpc_max_connection_age: Duration,

        /// Number of connections to be served before the "API tokens" need to be replenished
        /// per IP address.
        #[arg(
            long = "grpc.max_connection_age",
            default_value = DEFAULT_BURST_SIZE.to_string(),
            value_name = "BURST_SIZE"
        )]
        grpc_burst_size: u64,

        /// Number of requests to unlock per second.
        #[arg(
            long = "grpc.replenish_per_sec",
            default_value = DEFAULT_REPLENISH_PER_SEC.to_string(),
            value_name = "REPLENISH_PER_SEC"
        )]
        grpc_replenish_per_sec: u64,

        /// Number of global concurrent connections.
        #[arg(
            long = "grpc.max_global_connections",
            default_value = DEFAULT_MAX_GLOBAL_CONNECTIONS.to_string(),
            value_name = "MAX_GLOBAL_CONNECTIONS"
        )]
        grpc_max_global_concurrent_connections: u64,
    },
}

impl RpcCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let Self::Start {
            url,
            store_url,
            block_producer_url,
            validator_url,
            enable_otel: _,
            grpc_request_timeout: grpc_timeout,
            grpc_max_connection_age,
            grpc_burst_size,
            grpc_replenish_per_sec,
            grpc_max_global_concurrent_connections,
        } = self;

        let listener = url.to_socket().context("Failed to extract socket address from RPC URL")?;
        let listener = tokio::net::TcpListener::bind(listener)
            .await
            .context("Failed to bind to RPC's gRPC URL")?;

        Rpc {
            listener,
            store_url,
            block_producer_url,
            validator_url,
            grpc_request_timeout: grpc_timeout,
            grpc_max_connection_age,
            grpc_burst_size,
            grpc_replenish_per_sec,
            grpc_max_global_concurrent_connections,
        }
        .serve()
        .await
        .context("Serving RPC")
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        let Self::Start { enable_otel, .. } = self;
        *enable_otel
    }
}
