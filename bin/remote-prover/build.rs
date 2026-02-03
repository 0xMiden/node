use miden_node_proto_build::remote_prover_api_descriptor;
use miette::IntoDiagnostic;
use tonic_prost_build::FileDescriptorSet;

/// Defines whether the build script should generate files in `/src`.
///
/// The docs.rs build pipeline has a read-only filesystem, so we have to avoid writing to `src`,
/// otherwise the docs will fail to build there. Note that writing to `OUT_DIR` is fine.
const BUILD_GENERATED_FILES_IN_SRC: bool = option_env!("BUILD_PROTO").is_some();

const GENERATED_OUT_DIR: &str = "src/generated";

/// Generates Rust protobuf bindings.
fn main() -> miette::Result<()> {
    miden_node_rocksdb_cxx_linkage_fix::configure();
    println!("cargo:rerun-if-env-changed=BUILD_PROTO");
    if !BUILD_GENERATED_FILES_IN_SRC {
        return Ok(());
    }

    // Get the file descriptor set
    let remote_prover_descriptor = remote_prover_api_descriptor();

    // Build tonic code
    build_tonic_from_descriptor(remote_prover_descriptor)?;

    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds tonic code from a `FileDescriptorSet`
fn build_tonic_from_descriptor(descriptor: FileDescriptorSet) -> miette::Result<()> {
    tonic_prost_build::configure()
        .out_dir(GENERATED_OUT_DIR)
        .build_server(true)
        .build_transport(true)
        .compile_fds_with_config(descriptor, tonic_prost_build::Config::new())
        .into_diagnostic()
}
