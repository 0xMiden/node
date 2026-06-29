use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use codegen::{Function, Impl, Module, Trait, Type};
use fs_err as fs;
use miden_node_proto_build::{
    ntx_builder_api_descriptor,
    remote_prover_api_descriptor,
    rpc_api_descriptor,
    sequencer_api_descriptor,
    validator_api_descriptor,
};
use miette::{Context, IntoDiagnostic};
use prost_types::{MethodDescriptorProto, ServiceDescriptorProto};
use tonic_prost_build::FileDescriptorSet;

/// Generates Rust protobuf bindings using `miden-node-proto-build`.
fn main() -> miette::Result<()> {
    let dst_dir = build_rs::input::out_dir().join("generated");

    // Remove all existing files.
    let _ = fs::remove_dir_all(&dst_dir);
    fs::create_dir(&dst_dir)
        .into_diagnostic()
        .wrap_err("creating destination folder")?;

    let descriptor_sets = [
        rpc_api_descriptor(),
        remote_prover_api_descriptor(),
        validator_api_descriptor(),
        ntx_builder_api_descriptor(),
        sequencer_api_descriptor(),
    ];

    for file_descriptors in &descriptor_sets {
        generate_bindings(file_descriptors, &dst_dir)?;
    }

    let server_dst_dir = dst_dir.join("server");
    fs::create_dir_all(&server_dst_dir)
        .into_diagnostic()
        .wrap_err("creating server destination folder")?;

    generate_server_modules(&descriptor_sets, &server_dst_dir)?;

    generate_mod_rs(&server_dst_dir)
        .into_diagnostic()
        .wrap_err("generating server mod.rs")?;

    generate_mod_rs(&dst_dir).into_diagnostic().wrap_err("generating mod.rs")?;

    rustfmt_generated(&dst_dir)?;
    Ok(())
}

/// Generates protobuf bindings from the given file descriptor set and stores them in the given
/// destination directory.
fn generate_bindings(file_descriptors: &FileDescriptorSet, dst_dir: &Path) -> miette::Result<()> {
    let mut prost_config = tonic_prost_build::Config::new();
    prost_config.skip_debug(["AccountId", "Digest"]);

    // Generate the stub of the user facing server from its proto file
    tonic_prost_build::configure()
        .server_mod_attribute(".", "#[allow(deprecated, clippy::mixed_attributes_style)]")
        .server_attribute(
            ".",
            r#"#[deprecated(note = "use the service constructors in `miden_node_proto::server` instead")]"#,
        )
        .out_dir(dst_dir)
        .compile_fds_with_config(file_descriptors.clone(), prost_config)
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

    // Just ignore output and exit status. The `rustfmt` binary is part of the Rust toolchain even
    // if the `rustfmt` component is not installed, and it will print a warning and exit with status
    // code 1. We don't actually care about formatting in this case, so we can just ignore the
    // error.
    let _output = Command::new("rustfmt")
        .args(["--edition", "2024"])
        .args(&rs_files)
        .output()
        .into_diagnostic()
        .wrap_err("running rustfmt on generated files")?;

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
    // I couldn't find any `codegen::` function for `mod <module>;`, so we generate it manually.
    let mut modules = Vec::new();

    for entry in fs::read_dir(dst_dir.as_ref())? {
        let entry = entry?;
        let path = entry.path();

        let module = if path.is_file() {
            path.file_stem().and_then(|f| f.to_str()).expect("Could not get file name")
        } else if path.is_dir() {
            path.file_name().and_then(|f| f.to_str()).expect("Could not get directory name")
        } else {
            continue;
        };

        modules.push(format!("pub mod {module};"));
    }

    modules.sort();
    fs::write(dst_dir.as_ref().join("mod.rs"), modules.join("\n"))
}

/// Generate server facade modules (one per service) from the provided descriptor sets.
fn generate_server_modules(
    descriptor_sets: &[FileDescriptorSet],
    dst_dir: &Path,
) -> miette::Result<()> {
    let mut generated: HashSet<(String, String)> = HashSet::new();

    for fds in descriptor_sets {
        for file in &fds.file {
            let package = file.package.as_deref().unwrap_or_default();
            let package = package.replace('.', "_");

            for service in &file.service {
                let service_name = service.name.as_deref().unwrap_or("Service");
                let key = (package.clone(), service_name.to_string());
                if !generated.insert(key) {
                    continue;
                }

                let service_name = to_snake_case(service_name);
                let module_name = format!("{}_{}", &package, service_name);

                let contents =
                    Service::from_descriptor(service, &package)?.generate().scope().to_string();

                let path = dst_dir.join(format!("{module_name}.rs"));
                fs::write(path, contents).into_diagnostic().wrap_err("writing server module")?;
            }
        }
    }

    Ok(())
}

struct Service {
    name: String,
    package: String,
    unary_methods: Vec<UnaryMethod>,
    server_streams: Vec<ServerStream>,
}

struct UnaryMethod {
    name: String,
    request: String,
    response: String,
}

struct ServerStream {
    name: String,
    request: String,
    response: String,
}

impl Service {
    fn from_descriptor(descriptor: &ServiceDescriptorProto, package: &str) -> miette::Result<Self> {
        let name = descriptor.name().to_string();
        let unary_methods = descriptor
            .method
            .iter()
            .filter(|method| !method.client_streaming() && !method.server_streaming())
            .map(UnaryMethod::from_descriptor)
            .collect();
        let server_streams = descriptor
            .method
            .iter()
            .filter(|method| method.server_streaming())
            .map(ServerStream::from_descriptor)
            .collect();
        let package = package.to_string();

        // We don't have any client streams, so no need to support them.
        miette::ensure!(
            !descriptor.method.iter().any(MethodDescriptorProto::client_streaming),
            "client streams are not supported"
        );

        Ok(Self {
            name,
            package,
            unary_methods,
            server_streams,
        })
    }

    /// Generates a module containing the service's interface and implementation, including the
    /// methods.
    fn generate(&self) -> Module {
        let mut module = Module::new(&self.name);

        module.push_fn(self.service_constructor());
        module.push_fn(self.service_name());
        module.push_trait(self.service_trait());
        module.push_impl(self.blanket_impl());
        module.push_impl(self.tonic_impl());

        for method in &self.unary_methods {
            module.push_trait(method.as_trait());
        }

        for stream in &self.server_streams {
            module.push_trait(stream.as_trait());
        }

        module
    }

    /// The trait describing the service's interface.
    ///
    /// This is a super trait consisting of all the gRPC method traits for this service.
    ///
    /// ```rust
    /// trait <Self::name()Service>:
    ///   method[0]::trait() +
    ///   method[1]::trait() +
    ///   ...
    ///   method[N]::trait(),
    /// {}
    /// ```
    fn service_trait(&self) -> Trait {
        let mut ret = Trait::new(format!("{}Service", &self.name));
        ret.vis("pub");

        for method in &self.unary_methods {
            ret.parent(method.as_trait().ty());
        }

        for stream in &self.server_streams {
            ret.parent(stream.as_trait().ty());
        }

        ret
    }

    /// The blanket implementation of the the service's trait, for all `T` that implement all
    /// required gRPC methods.
    ///
    /// ```rust
    /// impl<T> <Self::service_trait()> for T
    /// where T:
    ///   method[0]::trait() +
    ///   method[1]::trait() +
    ///   ...
    ///   method[N]::trait(),
    /// {}
    /// ```
    fn blanket_impl(&self) -> Impl {
        let mut ret = Impl::new("T");
        ret.generic("T").impl_trait(self.service_trait().ty());

        for method in &self.unary_methods {
            ret.bound("T", method.as_trait().ty());
        }

        for stream in &self.server_streams {
            ret.bound("T", stream.as_trait().ty());
        }

        ret
    }

    /// Blanket implementation for all T that implement our service trait, for the tonic generated
    /// trait.
    ///
    /// ```rust
    /// #[tonic::async_trait]
    /// impl<T> tonic::generated::service_trait for T
    /// where T:
    ///     <Self::service_trait()> + Send + Sync + 'static {
    ///
    ///     async fn tonic_method[0](request) -> response {
    ///         <T as method[0].trait>::full(self, request.into_inner()).await.map(tonic::Response::new)
    ///     }
    ///
    ///     ...
    /// }
    /// ```
    fn tonic_impl(&self) -> Impl {
        let tonic_path = self.tonic_trait_path();

        let mut ret = Impl::new("T");
        ret.generic("T")
            .bound("T", self.service_trait().ty())
            .bound("T", "Send")
            .bound("T", "Sync")
            .bound("T", "'static")
            .impl_trait(tonic_path)
            .r#macro("#[tonic::async_trait]");

        for method in &self.unary_methods {
            ret.push_fn(method.tonic_impl());
        }

        for stream in &self.server_streams {
            ret.push_fn(stream.tonic_impl());
            ret.associate_type(stream.associated_type().0, stream.associated_type().1);
        }

        ret
    }

    /// Constructs the underlying tonic server for this service behind an opaque tower service type.
    fn service_constructor(&self) -> Function {
        let mut ret = Function::new("service");
        ret.vis("pub")
            .attr("allow(deprecated)")
            .generic("T")
            .arg("service", "T")
            .ret(
                "impl tower::Service<
    http::Request<tonic::body::Body>,
    Response = http::Response<tonic::body::Body>,
    Error = std::convert::Infallible,
    Future: Send + 'static,
> + tonic::server::NamedService
  + Clone
  + Send
  + Sync
  + 'static",
            )
            .bound("T", self.service_trait().ty())
            .bound("T", "Send")
            .bound("T", "Sync")
            .bound("T", "'static")
            .line(format!("{}::new(service)", self.tonic_server_path()));

        ret
    }

    /// Returns the gRPC service name used by tonic routing and health reporting.
    fn service_name(&self) -> Function {
        let mut ret = Function::new("service_name");
        ret.vis("pub").attr("allow(deprecated)").ret("&'static str").line(format!(
            "<{}::<()> as tonic::server::NamedService>::NAME",
            self.tonic_server_path()
        ));

        ret
    }

    /// Returns the full path to the service's trait.
    fn tonic_trait_path(&self) -> String {
        format!(
            "crate::generated::{}::{}_server::{}",
            self.package,
            to_snake_case(&self.name),
            self.name
        )
    }

    /// Returns the full path to the generated server struct.
    fn tonic_server_path(&self) -> String {
        format!("{}Server", self.tonic_trait_path())
    }
}

impl UnaryMethod {
    fn from_descriptor(descriptor: &MethodDescriptorProto) -> Self {
        let name = descriptor.name().to_string();

        let request = grpc_path_to_generated(descriptor.input_type());
        let response = grpc_path_to_generated(descriptor.output_type());

        Self { name, request, response }
    }

    /// Function invoking the method handler and mapping from/to tonic's request/response.
    ///
    /// ```rust
    /// async fn <Method::name::snake_case>(
    ///     request: tonic::Request<<Method::request>>,
    /// ) -> tonic::Result<tonic::Response<<Method::response>>> {
    ///     <T as <<Method::name>>::full(self, request).await.map(tonic::Response::new)
    /// }
    /// ```
    fn tonic_impl(&self) -> Function {
        let mut ret = Function::new(to_snake_case(&self.name));
        ret.set_async(true)
            .arg_ref_self()
            .arg("request", format!("tonic::Request<{}>", self.request))
            .ret(format!("tonic::Result<tonic::Response<{}>>", self.response))
            .line("#[allow(clippy::unit_arg)]")
            .line(format!(
                "<T as {}>::full(self, request).await.map(tonic::Response::new)",
                self.name
            ));

        ret
    }

    /// This method's trait definition.
    ///
    /// ```rust
    /// trait <Method::name> {
    ///     type Input;
    ///     type Output;
    ///
    ///     fn decode(request: <Method::request>) -> tonic::Result<Self::Input>;
    ///     fn encode(output: Self::Output) -> tonic::Result<Method::response>;
    ///     async fn handle(&self, input: Self::Input) -> tonic::Result<Self::Output>;
    ///
    ///     async fn full(
    ///         &self,
    ///         request: tonic::Request<<Method::Request>>,
    ///     ) -> tonic::Result<<Method::response>> {
    ///         let input = Self::decode(request.into_inner())?;
    ///         let output = self.handle(input).await?;
    ///         Self::encode(output)
    ///     }
    /// }
    // /// ```
    fn as_trait(&self) -> Trait {
        let mut ret = Trait::new(&self.name);
        ret.vis("pub");
        ret.attr("tonic::async_trait");
        ret.associated_type("Input");
        ret.associated_type("Output");

        ret.new_fn("decode")
            .arg("request", &self.request)
            .ret("tonic::Result<Self::Input>");

        ret.new_fn("encode")
            .arg("output", "Self::Output")
            .ret(format!("tonic::Result<{}>", &self.response));

        ret.new_fn("handle")
            .set_async(true)
            .arg_ref_self()
            .arg("input", "Self::Input")
            .ret("tonic::Result<Self::Output>");

        ret.new_fn("full")
            .set_async(true)
            .arg_ref_self()
            .arg("request", format!("tonic::Request<{}>", &self.request))
            .ret(format!("tonic::Result<{}>", &self.response))
            .line("let input = Self::decode(request.into_inner())?;")
            .line("let output = self.handle(input).await?;")
            .line("Self::encode(output)");

        ret
    }
}

impl ServerStream {
    fn from_descriptor(descriptor: &MethodDescriptorProto) -> Self {
        let name = descriptor.name().to_string();

        let request = grpc_path_to_generated(descriptor.input_type());
        let response = grpc_path_to_generated(descriptor.output_type());

        Self { name, request, response }
    }

    /// This stream's per-method trait definition.
    ///
    /// ```rust
    /// trait <Method::name> {
    ///     type Input;
    ///     type Item;
    ///     type ItemStream: Stream<Item = tonic::Result<Self::Item>> + Send + 'static;
    ///
    ///     fn decode(request: <Method::request>) -> tonic::Result<Self::Input>;
    ///     fn encode(item: Self::Item) -> tonic::Result<Method::response>;
    ///     async fn handle(&self, input: Self::Input) -> tonic::Result<Self::ItemStream>;
    ///
    ///     async fn full(&self, request: tonic::Request<<Method::request>>) -> tonic::Result<Pin<Box<dyn Stream<...>>>> {
    ///         use tokio_stream::StreamExt as _;
    ///         let input = Self::decode(request.into_inner())?;
    ///         let stream = self.handle(input).await?;
    ///         Ok(Box::pin(stream.map(|item| item.and_then(|i| Self::encode(i)))))
    ///     }
    /// }
    /// ```
    fn as_trait(&self) -> Trait {
        let stream_bound =
            "tonic::codegen::tokio_stream::Stream<Item = tonic::Result<Self::Item>>".to_string();
        let boxed_stream = format!(
            "std::pin::Pin<Box<dyn tonic::codegen::tokio_stream::Stream<Item = tonic::Result<{}>> + Send + 'static>>",
            self.response
        );

        let mut ret = Trait::new(&self.name);
        ret.vis("pub");
        ret.attr("tonic::async_trait");
        ret.associated_type("Input");
        ret.associated_type("Item");
        ret.associated_type("ItemStream")
            .bound(&stream_bound)
            .bound("Send")
            .bound("'static");

        ret.new_fn("decode")
            .arg("request", &self.request)
            .ret("tonic::Result<Self::Input>");

        ret.new_fn("encode")
            .arg("item", "Self::Item")
            .ret(format!("tonic::Result<{}>", &self.response));

        ret.new_fn("handle")
            .set_async(true)
            .arg_ref_self()
            .arg("input", "Self::Input")
            .ret("tonic::Result<Self::ItemStream>");

        ret.new_fn("full")
            .set_async(true)
            .arg_ref_self()
            .arg("request", format!("tonic::Request<{}>", &self.request))
            .ret(format!("tonic::Result<{boxed_stream}>"))
            .line("use tonic::codegen::tokio_stream::StreamExt as _;")
            .line("let input = Self::decode(request.into_inner())?;")
            .line("let stream = self.handle(input).await?;")
            .line("Ok(Box::pin(stream.map(|item| item.and_then(|i| Self::encode(i)))))");

        ret
    }

    fn tonic_impl(&self) -> Function {
        let mut ret = Function::new(to_snake_case(&self.name));
        ret.set_async(true)
            .arg_ref_self()
            .arg("request", format!("tonic::Request<{}>", self.request))
            .ret(format!("tonic::Result<tonic::Response<Self::{}>>", self.associated_type().0))
            .line("#[allow(clippy::unit_arg)]")
            .line(format!(
                "<T as {}>::full(self, request).await.map(tonic::Response::new)",
                self.name
            ));

        ret
    }

    fn associated_type(&self) -> (String, Type) {
        (
            format!("{}Stream", self.name),
            Type::new(format!(
                "std::pin::Pin<Box<dyn tonic::codegen::tokio_stream::Stream<Item = tonic::Result<{}>> + Send + 'static>>",
                self.response
            )),
        )
    }
}

/// Converts a string to `snake_case`.
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
