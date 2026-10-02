use protox::Compiler;
use protox::file::DescriptorSetFileResolver;

#[test]
fn canonical_imports_resolve_without_source_files() {
    let resolver = DescriptorSetFileResolver::decode(miden_objects::FILE_DESCRIPTOR_SET).unwrap();
    let mut compiler = Compiler::with_file_resolver(resolver);
    compiler.include_imports(true);
    compiler.open_file("block.proto").unwrap();
    let descriptors = compiler.file_descriptor_set();
    assert!(descriptors.file.iter().any(|file| file.name() == "block.proto"));
    for file in &descriptors.file {
        for dependency in &file.dependency {
            assert!(descriptors.file.iter().any(|import| import.name() == dependency));
        }
    }
}
