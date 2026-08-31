use std::collections::BTreeSet;

use prost_types::field_descriptor_proto::Type;
use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto};
use tonic_prost_build::FileDescriptorSet;

const CANONICAL_OBJECT_FILES: [&str; 10] = [
    "account.proto",
    "batch.proto",
    "block.proto",
    "block_number.proto",
    "note.proto",
    "partial_blockchain.proto",
    "primitives.proto",
    "protocol_config.proto",
    "transaction.proto",
    "transaction_inputs.proto",
];

const NODE_OWNED_FILES: [&str; 7] = [
    "rpc.proto",
    "remote_prover.proto",
    "internal/ntx_builder.proto",
    "internal/sequencer.proto",
    "internal/validator.proto",
    "types/block_proving.proto",
    "types/submission.proto",
];

fn service_descriptor<'a>(
    descriptor: &'a FileDescriptorSet,
    package: &str,
) -> &'a FileDescriptorProto {
    descriptor
        .file
        .iter()
        .find(|file| file.package() == package)
        .unwrap_or_else(|| panic!("missing {package} service descriptor"))
}

fn method_type(
    descriptor: &FileDescriptorSet,
    package: &str,
    method_name: &str,
    input: bool,
) -> String {
    let service = service_descriptor(descriptor, package)
        .service
        .iter()
        .find(|service| service.name() == "Api")
        .unwrap_or_else(|| panic!("missing {package}.Api service"));
    let method = service
        .method
        .iter()
        .find(|method| method.name() == method_name)
        .unwrap_or_else(|| panic!("missing {package}.Api.{method_name}"));

    if input {
        method.input_type.clone().expect("method input type")
    } else {
        method.output_type.clone().expect("method output type")
    }
}

fn message_field_type(
    descriptor: &FileDescriptorSet,
    package: &str,
    message_name: &str,
    field_name: &str,
) -> String {
    message_field(descriptor, package, message_name, field_name)
        .type_name
        .clone()
        .expect("message field type")
}

fn message_descriptor<'a>(
    descriptor: &'a FileDescriptorSet,
    package: &str,
    message_name: &str,
) -> &'a DescriptorProto {
    let mut messages = &service_descriptor(descriptor, package).message_type;
    let mut message = None;
    for name in message_name.split('.') {
        message = messages.iter().find(|candidate| candidate.name() == name);
        let found = message.unwrap_or_else(|| panic!("missing {package}.{message_name}"));
        messages = &found.nested_type;
    }
    message.expect("message name has at least one component")
}

fn message_field<'a>(
    descriptor: &'a FileDescriptorSet,
    package: &str,
    message_name: &str,
    field_name: &str,
) -> &'a FieldDescriptorProto {
    message_descriptor(descriptor, package, message_name)
        .field
        .iter()
        .find(|field| field.name() == field_name)
        .unwrap_or_else(|| panic!("missing {package}.{message_name}.{field_name}"))
}

fn collect_byte_fields(
    package: &str,
    parent: &str,
    messages: &[DescriptorProto],
    fields: &mut BTreeSet<String>,
) {
    for message in messages {
        let name = if parent.is_empty() {
            message.name().to_string()
        } else {
            format!("{parent}.{}", message.name())
        };

        for field in &message.field {
            if field.r#type == Some(Type::Bytes as i32) {
                fields.insert(format!("{package}.{name}.{}", field.name()));
            }
        }

        collect_byte_fields(package, &name, &message.nested_type, fields);
    }
}

#[test]
fn service_descriptors_use_canonical_protocol_messages() {
    let rpc = miden_node_proto_build::rpc_api_descriptor();
    let remote_prover = miden_node_proto_build::remote_prover_api_descriptor();
    let sequencer = miden_node_proto_build::sequencer_api_descriptor();
    let validator = miden_node_proto_build::validator_api_descriptor();

    assert_eq!(
        method_type(&rpc, "rpc", "SubmitProvenTx", true),
        ".submission.ProvenTransactionSubmission"
    );
    assert_eq!(
        method_type(&rpc, "rpc", "SubmitProvenTxBatch", true),
        ".submission.TransactionBatch"
    );
    assert_eq!(
        message_field_type(&sequencer, "sequencer", "AuthenticatedTransaction", "transaction"),
        ".transaction.ProvenTransactionData"
    );
    assert_eq!(
        message_field_type(
            &sequencer,
            "sequencer",
            "AuthenticatedTransactionBatch",
            "proposed_batch",
        ),
        ".transaction.ProposedBatch"
    );
    assert_eq!(
        method_type(&validator, "validator", "SubmitProvenTransaction", true),
        ".submission.ProvenTransactionSubmission"
    );
    assert_eq!(
        method_type(&validator, "validator", "SignBlock", true),
        ".block_proving.BlockProofRequest"
    );
    assert_eq!(
        method_type(&validator, "validator", "SignBlock", false),
        ".blockchain.SignedBlock"
    );

    assert_eq!(
        message_field_type(&remote_prover, "remote_prover", "ProofRequest", "transaction"),
        ".transaction.TransactionInputs"
    );
    assert_eq!(
        message_field_type(&remote_prover, "remote_prover", "ProofRequest", "batch"),
        ".transaction.ProposedBatch"
    );
    assert_eq!(
        message_field_type(&remote_prover, "remote_prover", "ProofRequest", "block"),
        ".block_proving.BlockProofRequest"
    );
    assert_eq!(
        message_field_type(&remote_prover, "remote_prover", "Proof", "transaction"),
        ".transaction.ProvenTransactionData"
    );
    assert_eq!(
        message_field_type(&remote_prover, "remote_prover", "Proof", "batch"),
        ".transaction.ProvenBatch"
    );
    assert_eq!(
        message_field_type(&remote_prover, "remote_prover", "Proof", "block"),
        ".primitives.ExecutionProof"
    );

    assert_eq!(
        message_field_type(&rpc, "rpc", "BlockSubscriptionResponse", "block"),
        ".blockchain.SignedBlock"
    );
    assert_eq!(
        message_field_type(&rpc, "rpc", "ProofSubscriptionResponse", "proof"),
        ".primitives.ExecutionProof"
    );
    assert_eq!(
        message_field_type(&rpc, "rpc", "AccountResponse.AccountDetails", "code",),
        ".account.AccountCode"
    );
    assert_eq!(
        message_field_type(&validator, "validator", "BlockSubscriptionResponse", "block",),
        ".blockchain.SignedBlock"
    );

    for descriptor in [&rpc, &remote_prover, &sequencer, &validator] {
        let file_names = descriptor
            .file
            .iter()
            .filter_map(|file| file.name.as_deref())
            .collect::<Vec<_>>();
        for legacy in [
            "types/account.proto",
            "types/blockchain.proto",
            "types/note.proto",
            "types/primitives.proto",
            "types/transaction.proto",
        ] {
            assert!(
                !file_names.contains(&legacy),
                "descriptor unexpectedly contains legacy {legacy}"
            );
        }
    }
}

#[test]
fn remote_prover_variants_belong_to_their_oneofs() {
    let descriptor = miden_node_proto_build::remote_prover_api_descriptor();

    for (message_name, oneof_name, fields) in [
        ("ProofRequest", "request", ["transaction", "batch", "block"]),
        ("Proof", "proof", ["transaction", "batch", "block"]),
    ] {
        let message = message_descriptor(&descriptor, "remote_prover", message_name);
        assert_eq!(message.oneof_decl.len(), 1);
        assert_eq!(message.oneof_decl[0].name(), oneof_name);

        for field_name in fields {
            assert_eq!(
                message_field(&descriptor, "remote_prover", message_name, field_name).oneof_index,
                Some(0),
                "{message_name}.{field_name} must belong to {oneof_name}",
            );
        }
    }
}

#[test]
fn descriptors_embed_their_canonical_imports() {
    let descriptors = [
        miden_node_proto_build::rpc_api_descriptor(),
        miden_node_proto_build::remote_prover_api_descriptor(),
        miden_node_proto_build::ntx_builder_api_descriptor(),
        miden_node_proto_build::sequencer_api_descriptor(),
        miden_node_proto_build::validator_api_descriptor(),
    ];
    let mut embedded_canonical_files = BTreeSet::new();

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

        embedded_canonical_files.extend(
            CANONICAL_OBJECT_FILES.iter().copied().filter(|file| file_names.contains(file)),
        );
    }

    assert_eq!(
        embedded_canonical_files,
        BTreeSet::from(CANONICAL_OBJECT_FILES),
        "service descriptors must embed every canonical object descriptor they expose",
    );
}

#[test]
fn node_owned_bytes_fields_are_limited_to_encryption_payloads() {
    let descriptors = [
        miden_node_proto_build::rpc_api_descriptor(),
        miden_node_proto_build::remote_prover_api_descriptor(),
        miden_node_proto_build::ntx_builder_api_descriptor(),
        miden_node_proto_build::sequencer_api_descriptor(),
        miden_node_proto_build::validator_api_descriptor(),
    ];
    let mut byte_fields = BTreeSet::new();

    for descriptor in descriptors {
        for file in descriptor.file {
            if NODE_OWNED_FILES.contains(&file.name()) {
                collect_byte_fields(file.package(), "", &file.message_type, &mut byte_fields);
            }
        }
    }

    assert_eq!(
        byte_fields,
        BTreeSet::from([
            "submission.NextTransactionEncryptionKey.key_id".to_string(),
            "submission.NextTransactionEncryptionKey.public_key".to_string(),
            "submission.SealedTransactionInputs.ciphertext".to_string(),
            "submission.SealedTransactionInputs.key_id".to_string(),
            "submission.TransactionEncryptionKey.key_id".to_string(),
            "submission.TransactionEncryptionKey.public_key".to_string(),
        ]),
    );
}
