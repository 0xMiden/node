use std::env;
use std::path::PathBuf;

use fs_err as fs;
use miette::{Context, IntoDiagnostic};
use protox::prost::Message;

const RPC_PROTO: &str = "rpc.proto";
// Unified internal store API (store.Rpc, store.BlockProducer, store.NtxBuilder).
// We compile the same file three times to preserve existing descriptor names.
const STORE_RPC_PROTO: &str = "internal/store.proto";
const STORE_NTX_BUILDER_PROTO: &str = "internal/store.proto";
const STORE_BLOCK_PRODUCER_PROTO: &str = "internal/store.proto";
const BLOCK_PRODUCER_PROTO: &str = "internal/block_producer.proto";
const REMOTE_PROVER_PROTO: &str = "remote_prover.proto";
const VALIDATOR_PROTO: &str = "internal/validator.proto";

const RPC_DESCRIPTOR: &str = "rpc_file_descriptor.bin";
const STORE_RPC_DESCRIPTOR: &str = "store_rpc_file_descriptor.bin";
const STORE_NTX_BUILDER_DESCRIPTOR: &str = "store_ntx_builder_file_descriptor.bin";
const STORE_BLOCK_PRODUCER_DESCRIPTOR: &str = "store_block_producer_file_descriptor.bin";
const BLOCK_PRODUCER_DESCRIPTOR: &str = "block_producer_file_descriptor.bin";
const REMOTE_PROVER_DESCRIPTOR: &str = "remote_prover_file_descriptor.bin";
const VALIDATOR_DESCRIPTOR: &str = "validator_file_descriptor.bin";

/// Generates Rust protobuf bindings from .proto files.
///
/// This is done only if `BUILD_PROTO` environment variable is set to `1` to avoid running the
/// script on crates.io where repo-level .proto files are not available.
fn main() -> miette::Result<()> {
    println!("cargo::rerun-if-changed=./proto");
    println!("cargo::rerun-if-env-changed=BUILD_PROTO");

    let out_dir = PathBuf::from(
        env::var("OUT_DIR").expect("env::OUT_DIR is always set in build.rs when used with cargo"),
    );

    let crate_root: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    let proto_src_dir = crate_root.join("proto");
    let includes = &[proto_src_dir];

    let rpc_file_descriptor = protox::compile([RPC_PROTO], includes)?;
    let rpc_path = out_dir.join(RPC_DESCRIPTOR);
    fs::write(&rpc_path, rpc_file_descriptor.encode_to_vec())
        .into_diagnostic()
        .wrap_err("writing rpc file descriptor")?;

    let remote_prover_file_descriptor = protox::compile([REMOTE_PROVER_PROTO], includes)?;
    let remote_prover_path = out_dir.join(REMOTE_PROVER_DESCRIPTOR);
    fs::write(&remote_prover_path, remote_prover_file_descriptor.encode_to_vec())
        .into_diagnostic()
        .wrap_err("writing remote prover file descriptor")?;

    let store_rpc_file_descriptor = protox::compile([STORE_RPC_PROTO], includes)?;
    let store_rpc_path = out_dir.join(STORE_RPC_DESCRIPTOR);
    fs::write(&store_rpc_path, store_rpc_file_descriptor.encode_to_vec())
        .into_diagnostic()
        .wrap_err("writing store rpc file descriptor")?;

    let store_ntx_builder_file_descriptor = protox::compile([STORE_NTX_BUILDER_PROTO], includes)?;
    let store_ntx_builder_path = out_dir.join(STORE_NTX_BUILDER_DESCRIPTOR);
    fs::write(&store_ntx_builder_path, store_ntx_builder_file_descriptor.encode_to_vec())
        .into_diagnostic()
        .wrap_err("writing store ntx builder file descriptor")?;

    let store_block_producer_file_descriptor =
        protox::compile([STORE_BLOCK_PRODUCER_PROTO], includes)?;
    let store_block_producer_path = out_dir.join(STORE_BLOCK_PRODUCER_DESCRIPTOR);
    fs::write(&store_block_producer_path, store_block_producer_file_descriptor.encode_to_vec())
        .into_diagnostic()
        .wrap_err("writing store block producer file descriptor")?;

    let block_producer_file_descriptor = protox::compile([BLOCK_PRODUCER_PROTO], includes)?;
    let block_producer_path = out_dir.join(BLOCK_PRODUCER_DESCRIPTOR);
    fs::write(&block_producer_path, block_producer_file_descriptor.encode_to_vec())
        .into_diagnostic()
        .wrap_err("writing block producer file descriptor")?;

    let validator_file_descriptor = protox::compile([VALIDATOR_PROTO], includes)?;
    let validator_path = out_dir.join(VALIDATOR_DESCRIPTOR);
    fs::write(&validator_path, validator_file_descriptor.encode_to_vec())
        .into_diagnostic()
        .wrap_err("writing validator file descriptor")?;

    Ok(())
}
