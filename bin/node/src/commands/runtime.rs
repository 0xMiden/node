use std::net::SocketAddr;
use std::path::PathBuf;

use miden_node_store::DatabaseOptions;
use miden_node_utils::clap::{GrpcOptionsExternal, GrpcOptionsInternal, StorageOptions};
use miden_node_utils::logging::OpenTelemetry;

use super::ENV_DATA_DIRECTORY;
use super::rpc::RpcOptions;
use super::store::StoreOptions;

// RUNTIME OPTIONS
// ================================================================================================

#[derive(clap::Args, Clone, Debug)]
pub struct RuntimeOptions {
    /// Directory containing the node's local data storage.
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
}

impl RuntimeOptions {
    pub fn open_telemetry(&self) -> OpenTelemetry {
        if self.enable_otel {
            OpenTelemetry::Enabled
        } else {
            OpenTelemetry::Disabled
        }
    }

    pub(super) fn runtime_config(&self, store: &StoreOptions) -> RuntimeConfig {
        RuntimeConfig {
            data_directory: self.data_directory.clone(),
            rpc_listen: self.rpc.listen,
            database_options: store.sqlite.database_options(),
            internal_grpc_options: self.rpc.grpc.internal_grpc_options(),
            external_grpc_options: self.rpc.external_grpc_options(),
            storage_options: store.storage.clone().into(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct RuntimeConfig {
    pub data_directory: PathBuf,
    pub rpc_listen: SocketAddr,
    pub database_options: DatabaseOptions,
    pub internal_grpc_options: GrpcOptionsInternal,
    pub external_grpc_options: GrpcOptionsExternal,
    pub storage_options: StorageOptions,
}
