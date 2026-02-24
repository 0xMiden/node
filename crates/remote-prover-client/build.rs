use fs_err as fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use miden_node_proto_build::remote_prover_api_descriptor;
use miette::{Context, IntoDiagnostic};
use tonic_prost_build::FileDescriptorSet;

/// Generates Rust protobuf bindings.
fn main() -> miette::Result<()> {
    let dst_dir =
        PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is always set for build.rs"))
            .join("generated");

    // Remove all existing files.
    let _ = fs::remove_dir_all(&dst_dir);
    fs::create_dir(&dst_dir)
        .into_diagnostic()
        .wrap_err("creating destination folder")?;

    let remote_prover_descriptor = remote_prover_api_descriptor();

    // Build std version
    let std_path = dst_dir.join("std");
    build_tonic_from_descriptor(remote_prover_descriptor.clone(), &std_path, true)?;

    // Build nostd version
    let nostd_path = dst_dir.join("nostd");
    build_tonic_from_descriptor(remote_prover_descriptor, &nostd_path, false)?;

    // Convert nostd version to use core/alloc instead of std
    let nostd_file_path = nostd_path.join("remote_prover.rs");
    convert_to_nostd(&nostd_file_path)?;

    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds tonic code from a `FileDescriptorSet` with specified configuration
fn build_tonic_from_descriptor(
    descriptor: FileDescriptorSet,
    dst_dir: &Path,
    build_transport: bool,
) -> miette::Result<()> {
    fs::create_dir_all(dst_dir).into_diagnostic()?;
    tonic_prost_build::configure()
        .out_dir(dst_dir)
        .build_server(false)
        .build_transport(build_transport)
        .compile_fds_with_config(descriptor, tonic_prost_build::Config::new())
        .into_diagnostic()
}

/// Replaces std references with core and alloc for nostd compatibility
fn convert_to_nostd(file_path: &Path) -> miette::Result<()> {
    let file_content = fs_err::read_to_string(file_path).into_diagnostic()?;
    let updated_content = file_content
        .replace("std::result", "core::result")
        .replace("std::marker", "core::marker")
        .replace("format!", "alloc::format!");

    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file_path)
        .into_diagnostic()?;

    file.write_all(updated_content.as_bytes()).into_diagnostic()
}
