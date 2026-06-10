use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::Context;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_validator::{ValidatorServer, ValidatorSigner};

// Starts the validator component.
pub async fn start(
    address: SocketAddr,
    grpc_options: GrpcOptionsInternal,
    signer: ValidatorSigner,
    data_directory: PathBuf,
    sqlite_connection_pool_size: NonZeroUsize,
) -> anyhow::Result<()> {
    ValidatorServer {
        address,
        grpc_options,
        signer,
        data_directory,
        sqlite_connection_pool_size,
    }
    .serve()
    .await
    .context("failed while serving validator component")
}
