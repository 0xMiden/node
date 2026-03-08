use std::ffi::OsStr;
use std::path::PathBuf;

use fs_err as fs;
use miette::{IntoDiagnostic, miette};
use protox::prost::Message;

/// Compiles each gRPC service definitions into a
/// [`FileDescriptorSet`](tonic_prost_build::FileDescriptorSet) and exposes it as a function:
///
/// ```rust
/// fn <service>_api_descriptor() -> FileDescriptorSet;
/// ```
fn main() -> miette::Result<()> {
    build_rs::output::rerun_if_changed("./proto");
    build_rs::output::rerun_if_changed("Cargo.toml");

    let out_dir = build_rs::input::out_dir();
    let schema_dir = build_rs::input::cargo_manifest_dir().join("proto");

    // Codegen which will hold the file descriptor functions.
    //
    // `protox::prost::Message` is a trait which brings into scope the encoding and decoding of file
    // descriptors. This is required so because we serialize the descriptors in code as a `Vec<u8>`
    // and then decode it again inline.
    let mut code = codegen::Scope::new();
    code.import("tonic_prost_build", "FileDescriptorSet");
    code.import("protox::prost", "Message");

    // We split our gRPC services into public and internal.
    //
    // This is easy to do since public services are listed in the root of the schema folder,
    // and internal services are nested in the `internal` folder.
    for public_api in proto_files_in_directory(&schema_dir)? {
        let file_descriptor_fn = generate_file_descriptor(&public_api, &schema_dir)?;
        code.push_fn(file_descriptor_fn);
    }

    // Internal gRPC services need an additional feature gate `#[cfg(feature = "internal")]`.
    for internal_api in proto_files_in_directory(&schema_dir.join("internal"))? {
        let mut file_descriptor_fn = generate_file_descriptor(&internal_api, &schema_dir)?;
        file_descriptor_fn.attr("cfg(feature = \"internal\")");
        code.push_fn(file_descriptor_fn);
    }

    fs::write(out_dir.join("file_descriptors.rs"), code.to_string()).into_diagnostic()?;

    Ok(())
}

/// The list of `*.proto` files in the given directory.
///
/// Does _not_ recurse into folders; only top level files are returned.
fn proto_files_in_directory(directory: &PathBuf) -> Result<Vec<PathBuf>, miette::Error> {
    let mut proto_files = Vec::new();
    for entry in fs::read_dir(directory).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;

        // Skip non-files
        if !entry.file_type().into_diagnostic()?.is_file() {
            continue;
        }

        // Skip non-protobuf files
        if PathBuf::from(entry.file_name()).extension().is_none_or(|ext| ext != "proto") {
            continue;
        }

        proto_files.push(entry.path());
    }
    Ok(proto_files)
}

/// Creates a function which emits the file descriptor of the given gRPC service file.
///
/// The function looks as follows:
///
/// ```rust
/// fn <file_stem>_api_descriptor() -> FileDescriptorSet {
///     FileDescriptorSet::decode(vec![<encoded>].as_slice())
///         .expect("encoded file descriptor should decode")
/// }
/// ```
///
/// where `<encoded>` is bytes of the compiled gRPC service.
fn generate_file_descriptor(
    grpc_service: &PathBuf,
    includes: &PathBuf,
) -> Result<codegen::Function, miette::Error> {
    let file_name = grpc_service
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| miette!("invalid file name for {grpc_service:?}"))?;

    let file_descriptor = protox::compile([grpc_service], includes)?;
    let file_descriptor = file_descriptor.encode_to_vec();

    let mut f = codegen::Function::new(format!("{file_name}_api_descriptor"));
    f.vis("pub")
        .ret("FileDescriptorSet")
        .line(format!("FileDescriptorSet::decode(vec!{file_descriptor:?}.as_slice())"))
        .line(".expect(\"we just encoded this so it should decode\")");

    Ok(f)
}
