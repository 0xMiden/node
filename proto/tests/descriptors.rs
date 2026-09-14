use std::collections::BTreeSet;

#[test]
fn descriptors_embed_their_dependencies() {
    let descriptors = [
        miden_node_proto_build::rpc_api_descriptor(),
        miden_node_proto_build::remote_prover_api_descriptor(),
        #[cfg(feature = "internal")]
        miden_node_proto_build::ntx_builder_api_descriptor(),
        #[cfg(feature = "internal")]
        miden_node_proto_build::sequencer_api_descriptor(),
        #[cfg(feature = "internal")]
        miden_node_proto_build::validator_api_descriptor(),
    ];

    for descriptor in &descriptors {
        let file_names = descriptor
            .file
            .iter()
            .filter_map(|file| file.name.as_deref())
            .collect::<BTreeSet<_>>();

        for file in &descriptor.file {
            for dependency in &file.dependency {
                assert!(
                    file_names.contains(dependency.as_str()),
                    "{} does not embed dependency {dependency}",
                    file.name(),
                );
            }
        }
    }
}
