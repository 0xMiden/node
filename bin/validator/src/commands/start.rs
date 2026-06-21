use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use anyhow::Context;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_validator::{DataDirectory, ValidatorServer, ValidatorSigner};
use url::Url;

// Starts the validator component.
pub async fn start(
    address: SocketAddr,
    standby_validator_url: Option<Url>,
    grpc_options: GrpcOptionsInternal,
    signer: ValidatorSigner,
    data_directory: PathBuf,
    sqlite_connection_pool_size: NonZeroUsize,
) -> anyhow::Result<()> {
    let data_directory = DataDirectory::load_server(data_directory)
        .context("failed to load validator data directory")?;
    ValidatorServer {
        address,
        standby_validator_url,
        grpc_options,
        signer,
        data_directory,
        sqlite_connection_pool_size,
    }
    .serve()
    .await
    .context("failed while serving validator component")
}
