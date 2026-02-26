use std::env;
use std::path::{Path, PathBuf};

use fs_err as fs;
use miden_node_proto_build::{
    block_producer_api_descriptor,
    remote_prover_api_descriptor,
    rpc_api_descriptor,
    store_block_producer_api_descriptor,
    store_ntx_builder_api_descriptor,
    store_rpc_api_descriptor,
    validator_api_descriptor,
};
use miette::{Context, IntoDiagnostic};
use tonic_prost_build::FileDescriptorSet;

/// Generates Rust protobuf bindings using `miden-node-proto-build`.
fn main() -> miette::Result<()> {
    println!("cargo::rerun-if-changed=../../proto/proto");

    miden_node_rocksdb_cxx_linkage_fix::configure();

    let dst_dir =
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR should be set")).join("generated");

    // Remove all existing files.
    let _ = fs::remove_dir_all(&dst_dir);
    fs::create_dir(&dst_dir)
        .into_diagnostic()
        .wrap_err("creating destination folder")?;

    generate_bindings(rpc_api_descriptor(), &dst_dir)?;
    generate_bindings(store_rpc_api_descriptor(), &dst_dir)?;
    generate_bindings(store_ntx_builder_api_descriptor(), &dst_dir)?;
    generate_bindings(store_block_producer_api_descriptor(), &dst_dir)?;
    generate_bindings(block_producer_api_descriptor(), &dst_dir)?;
    generate_bindings(remote_prover_api_descriptor(), &dst_dir)?;
    generate_bindings(validator_api_descriptor(), &dst_dir)?;

    generate_mod_rs(&dst_dir).into_diagnostic().wrap_err("generating mod.rs")?;

    Ok(())
}

/// Generates protobuf bindings from the given file descriptor set and stores them in the
/// given destination directory.
fn generate_bindings(file_descriptors: FileDescriptorSet, dst_dir: &Path) -> miette::Result<()> {
    let mut prost_config = tonic_prost_build::Config::new();
    prost_config.skip_debug(["AccountId", "Digest"]);

    // Generate the stub of the user facing server from its proto file
    tonic_prost_build::configure()
        .out_dir(dst_dir)
        .compile_fds_with_config(file_descriptors, prost_config)
        .into_diagnostic()
        .wrap_err("compiling protobufs")?;

    Ok(())
}

/// Generate `mod.rs` which includes all files in the folder as submodules.
fn generate_mod_rs(dst_dir: impl AsRef<Path>) -> std::io::Result<()> {
    let mod_filepath = dst_dir.as_ref().join("mod.rs");

    // Discover all submodules by iterating over the folder contents.
    let mut submodules = Vec::new();
    for entry in fs::read_dir(dst_dir.as_ref())? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let file_stem = path
                .file_stem()
                .and_then(|f| f.to_str())
                .expect("Could not get file name")
                .to_owned();

            submodules.push(file_stem);
        }
    }

    submodules.sort();

    let modules = submodules.iter().map(|f| format!("pub mod {f};\n"));
    let contents = modules.into_iter().collect::<String>();

    fs::write(mod_filepath, contents)
}
