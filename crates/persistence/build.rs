use protox::file::{ChainFileResolver, DescriptorSetFileResolver, IncludeFileResolver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/persistence.proto");
    let mut resolver = ChainFileResolver::new();
    resolver.add(IncludeFileResolver::new("proto".into()));
    resolver.add(DescriptorSetFileResolver::decode(miden_objects::FILE_DESCRIPTOR_SET)?);
    let mut compiler = protox::Compiler::with_file_resolver(resolver);
    compiler.include_imports(true).open_file("proto/persistence.proto")?;
    let descriptors = compiler.file_descriptor_set();
    let mut config = prost_build::Config::new();
    for &(proto, rust) in miden_objects::EXTERN_PATHS {
        config.extern_path(proto, rust);
    }
    let names: Vec<_> = descriptors
        .file
        .iter()
        .filter(|file| file.package() == "persistence")
        .flat_map(|file| {
            file.message_type
                .iter()
                .map(|message| format!("persistence.{}", message.name()))
        })
        .collect();
    miden_protobuf::build::configure_proto_decode_fields(
        &mut config,
        &descriptors,
        names.iter().map(String::as_str),
    )?;
    config.compile_fds(descriptors)?;
    Ok(())
}
