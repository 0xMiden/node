use std::net::SocketAddr;
use std::path::PathBuf;

use miden_node_store::DatabaseOptions;
use miden_node_utils::clap::{GrpcOptionsExternal, GrpcOptionsInternal, StorageOptions};
use miden_node_utils::logging::OpenTelemetry;
use url::Url;

use super::ENV_DATA_DIRECTORY;
use super::rpc::RpcOptions;
use super::store::StoreOptions;

// RUNTIME OPTIONS
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct RuntimeOptions {
    /// Directory in which to store the node database and raw block data.
    #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
    pub data_directory: PathBuf,

    /// Enables the exporting of traces for OpenTelemetry.
    ///
    /// This can be further configured using environment variables as defined in the official
    /// OpenTelemetry documentation. See our operator manual for further details.
    #[arg(
        long = "enable-otel",
        default_value_t = false,
        env = "MIDEN_NODE_ENABLE_OTEL",
        value_name = "BOOL"
    )]
    pub enable_otel: bool,

    #[command(flatten)]
    pub rpc: RpcOptions,

    #[command(flatten)]
    pub store: StoreOptions,

    #[command(flatten)]
    pub external_services: ExternalServiceOptions,
}

impl RuntimeOptions {
    pub fn open_telemetry(&self) -> OpenTelemetry {
        if self.enable_otel {
            OpenTelemetry::Enabled
        } else {
            OpenTelemetry::Disabled
        }
    }

    pub(super) fn runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            data_directory: self.data_directory.clone(),
            rpc_listen: self.rpc.listen,
            validator_url: self.external_services.validator_url.clone(),
            ntx_builder_url: self.external_services.ntx_builder_url.clone(),
            database_options: self.store.sqlite.database_options(),
            internal_grpc_options: self.rpc.grpc.internal_grpc_options(),
            external_grpc_options: self.rpc.external_grpc_options(),
            storage_options: self.store.storage.clone().into(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct RuntimeConfig {
    pub data_directory: PathBuf,
    pub rpc_listen: SocketAddr,
    pub validator_url: Option<Url>,
    pub ntx_builder_url: Option<Url>,
    pub database_options: DatabaseOptions,
    pub internal_grpc_options: GrpcOptionsInternal,
    pub external_grpc_options: GrpcOptionsExternal,
    pub storage_options: StorageOptions,
}

// EXTERNAL SERVICES
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct ExternalServiceOptions {
    /// The validator service gRPC URL, if this node should use one.
    #[arg(long = "validator.url", env = "MIDEN_NODE_VALIDATOR_URL", value_name = "URL")]
    pub validator_url: Option<Url>,

    /// The network transaction builder service gRPC URL, if this node should use one.
    #[arg(long = "ntx-builder.url", env = "MIDEN_NODE_NTX_BUILDER_URL", value_name = "URL")]
    pub ntx_builder_url: Option<Url>,
}
