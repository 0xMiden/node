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
                    matches!(
                        file.package(),
                        "miden.node.v1" | "miden.remote_prover.v1" | "miden.note_transport.v1"
                    ),
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

#[test]
fn note_transport_fetch_bounds_are_message_fields() {
    let descriptor = miden_node_proto_build::note_transport_api_descriptor();
    let file = descriptor
        .file
        .iter()
        .find(|file| {
            file.package() == "miden.note_transport.v1"
                && file.message_type.iter().any(|message| message.name() == "FetchNotesRequest")
        })
        .unwrap();
    for (name, number) in [("FetchNotesRequest", 3), ("FetchNotesResponse", 4)] {
        let message = file.message_type.iter().find(|message| message.name() == name).unwrap();
        let field = message.field.iter().find(|field| field.name() == "sync_to").unwrap();
        assert_eq!(field.number(), number);
        assert_eq!(field.type_name(), ".miden.note_transport.v1.FetchNotesCursor");
    }
}
