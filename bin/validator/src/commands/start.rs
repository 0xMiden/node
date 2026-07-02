use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::Context;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::shutdown::CancellationToken;
use miden_validator::{DataDirectory, ValidatorServer, ValidatorSigner};

// Starts the validator component.
pub async fn start(
    address: SocketAddr,
    grpc_options: GrpcOptionsInternal,
    signer: ValidatorSigner,
    data_directory: PathBuf,
    sqlite_connection_pool_size: NonZeroUsize,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let data_directory = DataDirectory::load_server(data_directory)
        .context("failed to load validator data directory")?;
    ValidatorServer {
        address,
        grpc_options,
        signer,
        data_directory,
        sqlite_connection_pool_size,
    }
    .serve(shutdown)
    .await
    .context("failed while serving validator component")
}
