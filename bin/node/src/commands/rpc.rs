use std::net::SocketAddr;

use anyhow::Context;
use miden_node_rpc::Rpc;
use miden_node_utils::clap::GrpcOptionsExternal;
use url::Url;

use super::ENV_ENABLE_OTEL;

const ENV_LISTEN: &str = "MIDEN_NODE_RPC_LISTEN";
const ENV_STORE_URL: &str = "MIDEN_NODE_RPC_STORE_URL";
const ENV_BLOCK_PRODUCER_URL: &str = "MIDEN_NODE_RPC_BLOCK_PRODUCER_URL";
const ENV_VALIDATOR_URL: &str = "MIDEN_NODE_RPC_VALIDATOR_URL";
const ENV_NTX_BUILDER_URL: &str = "MIDEN_NODE_RPC_NTX_BUILDER_URL";

#[derive(clap::Subcommand)]
pub enum RpcCommand {
    /// Starts the RPC component.
    Start {
        /// Socket address at which to serve the gRPC API.
        #[arg(long = "listen", env = ENV_LISTEN, value_name = "LISTEN")]
        listen: SocketAddr,

        /// The store's RPC service gRPC url.
        #[arg(long = "store.url", env = ENV_STORE_URL, value_name = "URL")]
        store_url: Url,

        /// The block-producer's gRPC url. If unset, will run the RPC in read-only mode, i.e.
        /// without a block-producer.
        #[arg(long = "block-producer.url", env = ENV_BLOCK_PRODUCER_URL, value_name = "URL")]
        block_producer_url: Option<Url>,

        /// The validator's gRPC url.
        #[arg(long = "validator.url", env = ENV_VALIDATOR_URL, value_name = "URL")]
        validator_url: Url,

        /// The network transaction builder's gRPC url.
        #[arg(long = "ntx-builder.url", env = ENV_NTX_BUILDER_URL, value_name = "URL")]
        ntx_builder_url: Option<Url>,

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = false, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        #[command(flatten)]
        grpc_options: GrpcOptionsExternal,
    },
}

impl RpcCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let Self::Start {
            listen,
            store_url,
            block_producer_url,
            validator_url,
            ntx_builder_url,
            enable_otel: _,
            grpc_options,
        } = self;

        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .context("Failed to bind to RPC's gRPC socket")?;

        Rpc {
            listener,
            store_url,
            block_producer_url,
            validator_url,
            ntx_builder_url,
            grpc_options,
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
