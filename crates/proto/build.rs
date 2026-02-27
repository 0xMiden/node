use std::path::Path;

use codegen::Scope;
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

    let mut scope = Scope::new();
    for module in submodules {
        scope.raw(format!("pub mod {module};\n"));
    }

    fs::write(mod_filepath, scope.to_string())
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
                    render_service_module(&package_module, service_name, &server_module, service)
                        .to_string();

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
) -> Scope {
    let mut scope = Scope::new();

    scope.import("std::task", "Context");
    scope.import("std::task", "Poll");
    scope.import("tonic", "Request");
    scope.import("tonic", "Response");
    scope.import("tonic", "Status");

    let package_use = if package_module.is_empty() {
        "crate::generated".to_string()
    } else {
        format!("crate::generated::{package_module}")
    };
    scope.import(&package_use, server_module);

    for import in [
        "GrpcDecode",
        "GrpcEncode",
        "GrpcInterface",
        "GrpcServerStream",
        "GrpcUnary",
        "handle_streaming",
        "handle_unary",
    ] {
        scope.import("crate::server", import);
    }

    let mut unary_methods = Vec::new();
    let mut streaming_methods = Vec::new();

    for method in &service.method {
        let method_name = method.name.as_deref().unwrap_or("Method");
        let method_struct = format!("{method_name}Method");
        let request_type = proto_type_to_rust_path(method.input_type.as_deref().unwrap_or(""));
        let response_type = proto_type_to_rust_path(method.output_type.as_deref().unwrap_or(""));

        if method.client_streaming() {
            continue;
        }

        scope.new_struct(&method_struct).vis("pub");

        let method_impl = scope.new_impl(&method_struct);
        method_impl.impl_trait("GrpcInterface");
        method_impl.associate_type("Request", request_type);
        method_impl.associate_type("Response", response_type);

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

    let service_trait = scope.new_trait(&service_trait_name);
    service_trait.vis("pub");
    for bound in &trait_bounds {
        service_trait.parent(bound);
    }

    let service_trait_impl = scope.new_impl("T");
    service_trait_impl.generic("T");
    service_trait_impl.impl_trait(&service_trait_name);
    for bound in &trait_bounds {
        service_trait_impl.bound("T", bound);
    }

    let service_impl = scope.new_impl("T");
    service_impl.generic("T");
    service_impl.impl_trait(format!("{server_module}::{service_name}"));
    service_impl.r#macro("#[tonic::async_trait]");
    service_impl.bound("T", &service_trait_name);

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

        service_impl
            .bound(request_type, format!("GrpcDecode<<T as GrpcUnary<{method_struct}>>::Input>"));
        service_impl.bound(
            format!("<T as GrpcUnary<{method_struct}>>::Output"),
            format!("GrpcEncode<{response_type}>"),
        );
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
        service_impl.bound(
            request_type,
            format!("GrpcDecode<<T as GrpcServerStream<{method_struct}>>::Input>"),
        );
    }

    for (method_name, method_struct) in &streaming_methods {
        let stream_name = format!("{method_name}Stream");
        service_impl.associate_type(
            stream_name,
            format!("<T as GrpcServerStream<{method_struct}>>::Stream"),
        );
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

        let func = service_impl.new_fn(method_fn);
        func.set_async(true);
        func.arg_ref_self();
        func.arg("request", format!("Request<{request_type}>"));
        func.ret(format!("Result<Response<{response_type}>, Status>"));
        func.line(format!("handle_unary::<{method_struct}, _>(self, request).await"));
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

        let func = service_impl.new_fn(method_fn);
        func.set_async(true);
        func.arg_ref_self();
        func.arg("request", format!("Request<{request_type}>"));
        func.ret(format!("Result<Response<Self::{stream_name}>, Status>"));
        func.line(format!("handle_streaming::<{method_struct}, _>(self, request).await"));
    }

    let server_struct = scope.new_struct(format!("{service_name}Server"));
    server_struct.vis("pub");
    server_struct.generic("T");
    server_struct.field("inner", format!("{server_module}::{service_name}Server<T>"));

    let server_impl = scope.new_impl(format!("{service_name}Server"));
    server_impl.generic("T");
    server_impl.target_generic("T");
    server_impl.bound("T", &service_trait_name);
    let new_fn = server_impl.new_fn("new");
    new_fn.vis("pub");
    new_fn.arg("service", "T");
    new_fn.ret("Self");
    new_fn.line("Self {");
    new_fn.line(format!("inner: {server_module}::{service_name}Server::new(service),"));
    new_fn.line("}");

    let clone_impl = scope.new_impl(format!("{service_name}Server"));
    clone_impl.generic("T");
    clone_impl.target_generic("T");
    clone_impl.impl_trait("Clone");
    let clone_fn = clone_impl.new_fn("clone");
    clone_fn.arg_ref_self();
    clone_fn.ret("Self");
    clone_fn.line("Self { inner: self.inner.clone() }");

    let tonic_service_impl = scope.new_impl(format!("{service_name}Server"));
    tonic_service_impl.generic("T");
    tonic_service_impl.generic("B");
    tonic_service_impl.target_generic("T");
    tonic_service_impl.impl_trait("tonic::codegen::Service<http::Request<B>>");
    tonic_service_impl.bound(
        format!("{server_module}::{service_name}Server<T>"),
        "tonic::codegen::Service<http::Request<B>>",
    );
    tonic_service_impl.associate_type(
        "Response",
        format!(
            "<{server_module}::{service_name}Server<T> as tonic::codegen::Service<http::Request<B>>>::Response"
        ),
    );
    tonic_service_impl.associate_type(
        "Error",
        format!(
            "<{server_module}::{service_name}Server<T> as tonic::codegen::Service<http::Request<B>>>::Error"
        ),
    );
    tonic_service_impl.associate_type(
        "Future",
        format!(
            "<{server_module}::{service_name}Server<T> as tonic::codegen::Service<http::Request<B>>>::Future"
        ),
    );

    let poll_ready_fn = tonic_service_impl.new_fn("poll_ready");
    poll_ready_fn.arg_mut_self();
    poll_ready_fn.arg("cx", "&mut Context<'_>");
    poll_ready_fn.ret("Poll<Result<(), Self::Error>>");
    poll_ready_fn.line("self.inner.poll_ready(cx)");

    let call_fn = tonic_service_impl.new_fn("call");
    call_fn.arg_mut_self();
    call_fn.arg("req", "http::Request<B>");
    call_fn.ret("Self::Future");
    call_fn.line("self.inner.call(req)");

    let named_service_impl = scope.new_impl(format!("{service_name}Server"));
    named_service_impl.generic("T");
    named_service_impl.target_generic("T");
    named_service_impl.impl_trait("tonic::server::NamedService");
    named_service_impl.associate_const(
        "NAME",
        "&'static str",
        format!("{server_module}::SERVICE_NAME"),
        "",
    );

    scope
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
