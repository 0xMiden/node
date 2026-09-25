use std::collections::BTreeSet;

#[test]
fn methods_have_dedicated_request_and_response_messages() {
    let descriptors = [
        miden_node_proto_build::rpc_api_descriptor(),
        miden_node_proto_build::remote_prover_api_descriptor(),
        miden_node_proto_build::note_transport_api_descriptor(),
        #[cfg(feature = "internal")]
        miden_node_proto_build::ntx_builder_api_descriptor(),
        #[cfg(feature = "internal")]
        miden_node_proto_build::sequencer_api_descriptor(),
        #[cfg(feature = "internal")]
        miden_node_proto_build::validator_api_descriptor(),
    ];
    let mut services = BTreeSet::new();
    let mut messages = BTreeSet::new();

    for descriptor in &descriptors {
        for file in &descriptor.file {
            for service in &file.service {
                let service_name = format!("{}.{}", file.package(), service.name());
                if !services.insert(service_name.clone()) {
                    continue;
                }
                for method in &service.method {
                    for (message, suffix) in
                        [(method.input_type(), "Request"), (method.output_type(), "Response")]
                    {
                        let prefix = format!(".{}.", file.package());
                        assert!(
                            message.starts_with(&prefix),
                            "{service_name}.{} must own its {suffix} message: {message}",
                            method.name(),
                        );
                        assert!(
                            message.ends_with(&format!("{}{suffix}", method.name())),
                            "{service_name}.{} must name its {suffix} message after the method: {message}",
                            method.name(),
                        );
                        assert!(
                            messages.insert(message.to_owned()),
                            "{service_name}.{} shares endpoint message {message}",
                            method.name(),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn public_descriptors_exclude_internal_services() {
    for descriptor in [
        miden_node_proto_build::rpc_api_descriptor(),
        miden_node_proto_build::remote_prover_api_descriptor(),
        miden_node_proto_build::note_transport_api_descriptor(),
    ] {
        for file in &descriptor.file {
            if !file.service.is_empty() {
                assert!(
                    matches!(file.package(), "rpc" | "remote_prover" | "note_transport"),
                    "public reflection exposes {}",
                    file.package(),
                );
            }
        }
    }
}

#[test]
fn descriptors_embed_their_dependencies() {
    let descriptors = [
        miden_node_proto_build::rpc_api_descriptor(),
        miden_node_proto_build::remote_prover_api_descriptor(),
        miden_node_proto_build::note_transport_api_descriptor(),
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
