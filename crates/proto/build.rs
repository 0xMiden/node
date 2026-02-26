use std::fmt::Write;
use std::path::Path;

use fs_err as fs;
use miden_node_proto_build::{
    block_producer_api_descriptor,
    remote_prover_api_descriptor,
    rpc_api_descriptor,
    store_api_descriptor,
    validator_api_descriptor,
};
use miette::{Context, IntoDiagnostic};
use tonic_prost_build::FileDescriptorSet;

/// Generates Rust protobuf bindings using `miden-node-proto-build`.
fn main() -> miette::Result<()> {
    miden_node_rocksdb_cxx_linkage_fix::configure();

    let dst_dir = build_rs::input::out_dir().join("generated");

    // Remove all existing files.
    let _ = fs::remove_dir_all(&dst_dir);
    fs::create_dir(&dst_dir)
        .into_diagnostic()
        .wrap_err("creating destination folder")?;

    let descriptor_sets = [
        rpc_api_descriptor(),
        store_api_descriptor(),
        block_producer_api_descriptor(),
        remote_prover_api_descriptor(),
        validator_api_descriptor(),
    ];

    for file_descriptors in &descriptor_sets {
        generate_bindings(file_descriptors.clone(), &dst_dir)?;
    }

    let server_dst_dir = dst_dir.join("server");
    fs::create_dir_all(&server_dst_dir)
        .into_diagnostic()
        .wrap_err("creating server destination folder")?;

    generate_server_modules(&descriptor_sets, &server_dst_dir)?;
    generate_mod_rs(dst_dir)
        .into_diagnostic()
        .wrap_err("generating server mod.rs")?;

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
        } else if path.is_dir() {
            let dir_name = path
                .file_name()
                .and_then(|f| f.to_str())
                .expect("Could not get directory name")
                .to_owned();

            submodules.push(dir_name);
        }
    }

    submodules.sort();

    let modules = submodules.iter().map(|f| format!("pub mod {f};\n"));
    let contents = modules.into_iter().collect::<String>();

    fs::write(mod_filepath, contents)
}

/// Generate server facade modules (one per service) from the provided descriptor sets.
fn generate_server_modules(
    descriptor_sets: &[FileDescriptorSet],
    dst_dir: &Path,
) -> miette::Result<()> {
    for fds in descriptor_sets {
        for file in &fds.file {
            let package = file.package.as_deref().unwrap_or_default();
            let package_module = package.replace('.', "::");
            let package_prefix = package.replace('.', "_");

            for service in &file.service {
                let service_name = service.name.as_deref().unwrap_or("Service");
                let module_name = service_module_name(&package_prefix, service_name);
                let server_module = format!("{}_server", to_snake_case(service_name));

                let contents =
                    render_service_module(&package_module, service_name, &server_module, service);

                let path = dst_dir.join(format!("{module_name}.rs"));
                fs::write(path, contents).into_diagnostic().wrap_err("writing server module")?;
            }
        }
    }

    Ok(())
}

#[expect(clippy::too_many_lines, reason = "Will split later")]
fn render_service_module(
    package_module: &str,
    service_name: &str,
    server_module: &str,
    service: &prost_types::ServiceDescriptorProto,
) -> String {
    let mut out = String::new();

    writeln!(out, "use std::task::{{Context, Poll}};").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "use tonic::{{Request, Response, Status}};").unwrap();
    writeln!(out).unwrap();

    let package_use = if package_module.is_empty() {
        "crate::generated".to_string()
    } else {
        format!("crate::generated::{package_module}")
    };
    writeln!(out, "use {package_use}::{{{server_module}}};").unwrap();
    writeln!(
        out,
        "use crate::server::{{GrpcDecode, GrpcEncode, GrpcInterface, GrpcServerStream, GrpcUnary, handle_streaming, handle_unary}};"
    )
    .unwrap();
    writeln!(out).unwrap();

    let mut unary_methods = Vec::new();
    let mut streaming_methods = Vec::new();

    for method in &service.method {
        let method_name = method.name.as_deref().unwrap_or("Method");
        let method_struct = format!("{method_name}Method");
        let request_type = proto_type_to_rust_path(method.input_type.as_deref().unwrap_or(""));
        let response_type = proto_type_to_rust_path(method.output_type.as_deref().unwrap_or(""));

        if method.client_streaming() {
            writeln!(
                out,
                "// NOTE: client-streaming and bidi methods are not generated ({method_name})."
            )
            .unwrap();
            continue;
        }

        writeln!(out, "pub struct {method_struct};").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "impl GrpcInterface for {method_struct} {{").unwrap();
        writeln!(out, "    type Request = {request_type};").unwrap();
        writeln!(out, "    type Response = {response_type};").unwrap();
        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();

        if method.server_streaming() {
            streaming_methods.push((method_name.to_string(), method_struct));
        } else {
            unary_methods.push((method_name.to_string(), method_struct));
        }
    }

    let service_trait_name = format!("{service_name}Service");
    let mut trait_bounds = Vec::new();
    for (_, method_struct) in &unary_methods {
        trait_bounds.push(format!("GrpcUnary<{method_struct}>"));
    }
    for (_, method_struct) in &streaming_methods {
        trait_bounds.push(format!("GrpcServerStream<{method_struct}>"));
    }

    if trait_bounds.is_empty() {
        writeln!(out, "pub trait {service_trait_name} {{}}").unwrap();
        writeln!(out, "impl<T> {service_trait_name} for T {{}}").unwrap();
    } else {
        writeln!(out, "pub trait {service_trait_name}: {} {{}}", trait_bounds.join(" + ")).unwrap();
        writeln!(
            out,
            "impl<T> {service_trait_name} for T where T: {} {{}}",
            trait_bounds.join(" + ")
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "#[tonic::async_trait]").unwrap();
    writeln!(out, "impl<T> {server_module}::{service_name} for T").unwrap();
    writeln!(out, "where").unwrap();
    writeln!(out, "    T: {service_trait_name},").unwrap();

    for (method_name, method_struct) in &unary_methods {
        let request_type = proto_type_to_rust_path(
            service
                .method
                .iter()
                .find(|m| m.name.as_deref() == Some(method_name))
                .and_then(|m| m.input_type.as_deref())
                .unwrap_or(""),
        );
        let response_type = proto_type_to_rust_path(
            service
                .method
                .iter()
                .find(|m| m.name.as_deref() == Some(method_name))
                .and_then(|m| m.output_type.as_deref())
                .unwrap_or(""),
        );

        writeln!(out, "    {request_type}: GrpcDecode<<T as GrpcUnary<{method_struct}>>::Input>,")
            .unwrap();
        writeln!(
            out,
            "    <T as GrpcUnary<{method_struct}>>::Output: GrpcEncode<{response_type}>,"
        )
        .unwrap();
    }

    for (method_name, method_struct) in &streaming_methods {
        let request_type = proto_type_to_rust_path(
            service
                .method
                .iter()
                .find(|m| m.name.as_deref() == Some(method_name))
                .and_then(|m| m.input_type.as_deref())
                .unwrap_or(""),
        );
        writeln!(
            out,
            "    {request_type}: GrpcDecode<<T as GrpcServerStream<{method_struct}>>::Input>,"
        )
        .unwrap();
    }

    writeln!(out, "{{").unwrap();

    for (method_name, method_struct) in &streaming_methods {
        let stream_name = format!("{method_name}Stream");
        writeln!(
            out,
            "    type {stream_name} = <T as GrpcServerStream<{method_struct}>>::Stream;"
        )
        .unwrap();
    }

    for (method_name, method_struct) in &unary_methods {
        let method_fn = to_snake_case(method_name);
        let request_type = proto_type_to_rust_path(
            service
                .method
                .iter()
                .find(|m| m.name.as_deref() == Some(method_name))
                .and_then(|m| m.input_type.as_deref())
                .unwrap_or(""),
        );
        let response_type = proto_type_to_rust_path(
            service
                .method
                .iter()
                .find(|m| m.name.as_deref() == Some(method_name))
                .and_then(|m| m.output_type.as_deref())
                .unwrap_or(""),
        );

        writeln!(
            out,
            "    async fn {method_fn}(&self, request: Request<{request_type}>) -> Result<Response<{response_type}>, Status> {{"
        )
        .unwrap();
        writeln!(out, "        handle_unary::<{method_struct}, _>(self, request).await").unwrap();
        writeln!(out, "    }}").unwrap();
    }

    for (method_name, method_struct) in &streaming_methods {
        let method_fn = to_snake_case(method_name);
        let request_type = proto_type_to_rust_path(
            service
                .method
                .iter()
                .find(|m| m.name.as_deref() == Some(method_name))
                .and_then(|m| m.input_type.as_deref())
                .unwrap_or(""),
        );
        let stream_name = format!("{method_name}Stream");

        writeln!(
            out,
            "    async fn {method_fn}(&self, request: Request<{request_type}>) -> Result<Response<Self::{stream_name}>, Status> {{"
        )
        .unwrap();
        writeln!(out, "        handle_streaming::<{method_struct}, _>(self, request).await")
            .unwrap();
        writeln!(out, "    }}").unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "pub struct {service_name}Server<T> {{").unwrap();
    writeln!(out, "    inner: {server_module}::{service_name}Server<T>,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl<T> {service_name}Server<T>").unwrap();
    writeln!(out, "where").unwrap();
    writeln!(out, "    T: {service_trait_name},").unwrap();
    writeln!(out, "{{").unwrap();
    writeln!(out, "    pub fn new(service: T) -> Self {{").unwrap();
    writeln!(out, "        Self {{").unwrap();
    writeln!(out, "            inner: {server_module}::{service_name}Server::new(service),")
        .unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl<T> Clone for {service_name}Server<T> {{").unwrap();
    writeln!(out, "    fn clone(&self) -> Self {{").unwrap();
    writeln!(out, "        Self {{ inner: self.inner.clone() }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "impl<T, B> tonic::codegen::Service<http::Request<B>> for {service_name}Server<T>"
    )
    .unwrap();
    writeln!(out, "where").unwrap();
    writeln!(
        out,
        "    {server_module}::{service_name}Server<T>: tonic::codegen::Service<http::Request<B>>,"
    )
    .unwrap();
    writeln!(out, "{{").unwrap();
    writeln!(
        out,
        "    type Response = <{server_module}::{service_name}Server<T> as tonic::codegen::Service<http::Request<B>>>::Response;"
    )
    .unwrap();
    writeln!(
        out,
        "    type Error = <{server_module}::{service_name}Server<T> as tonic::codegen::Service<http::Request<B>>>::Error;"
    )
    .unwrap();
    writeln!(
        out,
        "    type Future = <{server_module}::{service_name}Server<T> as tonic::codegen::Service<http::Request<B>>>::Future;"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {{"
    )
    .unwrap();
    writeln!(out, "        self.inner.poll_ready(cx)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    fn call(&mut self, req: http::Request<B>) -> Self::Future {{").unwrap();
    writeln!(out, "        self.inner.call(req)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl<T> tonic::server::NamedService for {service_name}Server<T> {{").unwrap();
    writeln!(out, "    const NAME: &'static str = {server_module}::SERVICE_NAME;").unwrap();
    writeln!(out, "}}").unwrap();

    out
}

fn service_module_name(package: &str, service: &str) -> String {
    if package.is_empty() {
        to_snake_case(service)
    } else {
        format!("{package}_{}", to_snake_case(service))
    }
}

fn to_snake_case(value: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if ch.is_uppercase() {
            if idx != 0 {
                out.push('_');
            }
            for lower in ch.to_lowercase() {
                out.push(lower);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn proto_type_to_rust_path(proto_type: &str) -> String {
    if proto_type == ".google.protobuf.Empty" {
        return "()".to_string();
    }

    let trimmed = proto_type.trim_start_matches('.');
    let mut parts = trimmed.split('.').collect::<Vec<_>>();
    if parts.is_empty() {
        return "()".to_string();
    }

    let type_name = parts.pop().unwrap();
    let module_path = parts.join("::");
    if module_path.is_empty() {
        format!("crate::generated::{type_name}")
    } else {
        format!("crate::generated::{module_path}::{type_name}")
    }
}
