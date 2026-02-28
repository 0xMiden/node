use std::path::Path;

use fs_err as fs;
use miden_node_proto_build::remote_prover_api_descriptor;
use miette::{IntoDiagnostic, WrapErr};
use tonic_prost_build::FileDescriptorSet;

/// Generates Rust protobuf bindings.
fn main() -> miette::Result<()> {
    miden_node_rocksdb_cxx_linkage_fix::configure();

    let dst_dir = build_rs::input::out_dir().join("generated");

    // Remove all existing files.
    let _ = fs::remove_dir_all(&dst_dir);
    fs::create_dir(&dst_dir)
        .into_diagnostic()
        .wrap_err("creating destination folder")?;

    // Get the file descriptor set
    let remote_prover_descriptor = remote_prover_api_descriptor();

    // Build tonic code
    build_tonic_from_descriptor(remote_prover_descriptor, &dst_dir)?;

    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds tonic code from a `FileDescriptorSet`
fn build_tonic_from_descriptor(
    descriptor: FileDescriptorSet,
    dst_dir: &Path,
) -> miette::Result<()> {
    tonic_prost_build::configure()
        .out_dir(dst_dir)
        .build_server(true)
        .build_transport(true)
        .compile_fds_with_config(descriptor, tonic_prost_build::Config::new())
        .into_diagnostic()
}
