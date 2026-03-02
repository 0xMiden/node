use std::path::Path;
use std::process::Command;

use codegen::{Scope, *};
use fs_err as fs;
use miden_node_proto_build::{
    block_producer_api_descriptor,
    remote_prover_api_descriptor,
    rpc_api_descriptor,
    store_api_descriptor,
    validator_api_descriptor,
};
use miette::{Context, IntoDiagnostic};
use prost_types::{MethodDescriptorProto, ServiceDescriptorProto};
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

    generate_mod_rs(&server_dst_dir)
        .into_diagnostic()
        .wrap_err("generating server mod.rs")?;

    // generate_server_modules(&descriptor_sets, &server_dst_dir)?;
    generate_mod_rs(&dst_dir).into_diagnostic().wrap_err("generating mod.rs")?;

    rustfmt_generated(&dst_dir)?;
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

fn rustfmt_generated(dir: &Path) -> miette::Result<()> {
    let mut rs_files = Vec::new();
    collect_rs_files(dir, &mut rs_files)?;

    if rs_files.is_empty() {
        return Ok(());
    }

    let status = Command::new("rustfmt")
        .args(&rs_files)
        .status()
        .into_diagnostic()
        .wrap_err("running rustfmt on generated files")?;

    if !status.success() {
        miette::bail!("rustfmt failed with status: {status}");
    }

    Ok(())
}

fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> miette::Result<()> {
    for entry in fs_err::read_dir(dir).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Generate `mod.rs` which includes all files in the folder as submodules.
fn generate_mod_rs(dst_dir: impl AsRef<Path>) -> std::io::Result<()> {
    let mut scope = Scope::new();

    for entry in fs::read_dir(dst_dir.as_ref())? {
        let entry = entry?;
        let path = entry.path();

        let name = if path.is_file() {
            path.file_stem().and_then(|f| f.to_str()).expect("Could not get file name")
        } else if path.is_dir() {
            path.file_name().and_then(|f| f.to_str()).expect("Could not get directory name")
        } else {
            continue;
        };

        scope.raw(format!("pub mod {name};"));
    }

    fs::write(dst_dir.as_ref().join("mod.rs"), scope.to_string())
}

/// Generate server facade modules (one per service) from the provided descriptor sets.
fn generate_server_modules(
    descriptor_sets: &[FileDescriptorSet],
    dst_dir: &Path,
) -> miette::Result<()> {
    for fds in descriptor_sets {
        for file in &fds.file {
            let package = file.package.as_deref().unwrap_or_default();
            let package = package.replace('.', "_");

            for service in &file.service {
                let service_name = service.name.as_deref().unwrap_or("Service");
                let service_name = to_snake_case(service_name);
                let module_name = format!("{}_{}", &package, service_name);

                let contents = Service::from_descriptor(service).generate().scope().to_string();

                let path = dst_dir.join(format!("{module_name}.rs"));
                fs::write(path, contents).into_diagnostic().wrap_err("writing server module")?;
            }
        }
    }

    Ok(())
}

struct Service {
    name: String,
    methods: Vec<Method>,
}

struct Method {
    name: String,
    request: String,
    response: String,
}

impl Service {
    fn from_descriptor(descriptor: &ServiceDescriptorProto) -> Self {
        let name = descriptor.name().to_string();
        let methods = descriptor.method.iter().map(Method::from_descriptor).collect();

        Self { name, methods }
    }

    /// Generates a module containing the service's interface and implementation, including the
    /// methods.
    fn generate(&self) -> Module {
        let mut module = Module::new(&self.name);

        module.import("crate::server", "GrpcInterface");
        module.import("crate::server", "GrpcUnary");
        module.import("crate::server", "handle_unary");

        module.push_trait(self.service_trait());
        module.push_impl(self.blanket_impl());

        for method in &self.methods {
            module.push_struct(method.marker_struct());
            module.push_impl(method.grpc_interface_impl());
        }

        module
    }

    /// The trait describing the service's interface.
    ///
    /// This is a super trait consisting of all the gRPC method traits for this service.
    ///
    /// ```rust
    /// trait <Self::name()Service>:
    ///   GrpcUnary<Self::method[0]::marker_struct> +
    ///   GrpcUnary<Self::method[1]::marker_struct> +
    ///   ...
    ///   GrpcUnary<Self::method[N]::marker_struct>,
    /// {}
    /// ```
    fn service_trait(&self) -> Trait {
        let mut ret = Trait::new(format!("{}Service", &self.name));
        ret.vis("pub");

        for method in &self.methods {
            ret.parent(method.unary_trait().ty());
        }

        ret
    }

    /// The blanket implementation of the the service's trait, for all `T` that implement all
    /// required gRPC methods.
    ///
    /// ```rust
    /// impl<T> <Self::service_trait()> for T
    /// where T:
    ///   GrpcUnary<Self::method[0]::marker_struct> +
    ///   GrpcUnary<Self::method[1]::marker_struct> +
    ///   ...
    ///   GrpcUnary<Self::method[N]::marker_struct>,
    /// {}
    /// ```
    fn blanket_impl(&self) -> Impl {
        let mut ret = Impl::new("T");
        ret.generic("T").impl_trait(self.service_trait().ty());

        for method in &self.methods {
            ret.bound("T", method.unary_trait().ty());
        }

        ret
    }
}

impl Method {
    fn from_descriptor(descriptor: &MethodDescriptorProto) -> Self {
        let name = descriptor.name().to_string();

        let request = Self::grpc_path_to_generated(descriptor.input_type());
        let response = Self::grpc_path_to_generated(descriptor.output_type());

        Self { name, request, response }
    }

    /// This [`Method`]'s marker struct.
    ///
    /// ```rust
    /// pub struct <Self::name>;
    /// ```
    fn marker_struct(&self) -> Struct {
        let mut ret = Struct::new(&self.name);
        ret.vis("pub");
        ret
    }

    /// Returns this method's unary trait concrete type.
    ///
    /// ```rust
    /// GrpcUnary<Self::marker_struct()>
    /// ```
    fn unary_trait(&self) -> Trait {
        let mut ret = Trait::new("GrpcUnary");
        ret.generic(&self.name);
        ret
    }

    /// This method's implementation of the `GrpcInterface` trait.
    fn grpc_interface_impl(&self) -> Impl {
        let mut ret = Impl::new(&self.name);
        ret.impl_trait("GrpcInterface")
            .associate_type("Request", &self.request)
            .associate_type("Response", &self.response);

        ret
    }

    /// Translates a gRPC protobuf path to the corresponding generated Rust path. This is used to
    /// translate the protobuf type definitions to their tonic generated Rust types.
    ///
    /// i.e. `.x.y.z` -> `crate::generated::x::y::z`
    ///
    /// It also handles the case where the path is `.google.protobuf.Empty` by returning `()`.
    fn grpc_path_to_generated(path: &str) -> String {
        if path == ".google.protobuf.Empty" {
            return "()".to_string();
        }

        let path = path.trim_start_matches('.').replace('.', "::");
        format!("crate::generated::{path}")
    }
}

/// Converts a string to snake_case.
fn to_snake_case(s: &str) -> String {
    let mut ret = String::new();

    for c in s.chars() {
        if c.is_uppercase() {
            if !ret.is_empty() {
                ret.push('_');
            }
        }
        ret.push(c.to_ascii_lowercase());
    }

    ret
}
