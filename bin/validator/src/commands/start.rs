use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_validator::{Validator, ValidatorSigner};

// Starts the validator component.
pub async fn start(
    address: SocketAddr,
    grpc_options: GrpcOptionsInternal,
    signer: ValidatorSigner,
    data_directory: PathBuf,
) -> anyhow::Result<()> {
    Validator {
        address,
        grpc_options,
        signer,
        data_directory,
    }
    .serve()
    .await
    .context("failed while serving validator component")
}
