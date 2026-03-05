use anyhow::Context;
use miden_node_rpc::Rpc;
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::grpc::UrlExt;
use url::Url;

use super::{ENV_BLOCK_PRODUCER_URL, ENV_RPC_URL, ENV_STORE_RPC_URL, ENV_VALIDATOR_URL};
use crate::commands::ENV_ENABLE_OTEL;

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

        #[command(flatten)]
        grpc_options: GrpcOptions,
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
            grpc_options,
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
            grpc_request_timeout: grpc_options.request_timeout,
            grpc_max_connection_age: grpc_options.max_connection_age,
            grpc_burst_size: grpc_options.burst_size,
            grpc_replenish_per_sec: grpc_options.replenish_per_sec,
            grpc_max_global_concurrent_connections: grpc_options.max_global_concurrent_connections,
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
