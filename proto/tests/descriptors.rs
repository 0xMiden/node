use prost_types::FileDescriptorProto;
use tonic_prost_build::FileDescriptorSet;

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
    let mut messages = &service_descriptor(descriptor, package).message_type;
    let mut message = None;
    for name in message_name.split('.') {
        message = messages.iter().find(|candidate| candidate.name() == name);
        let found = message.unwrap_or_else(|| panic!("missing {package}.{message_name}"));
        messages = &found.nested_type;
    }
    let message = message.expect("message name has at least one component");
    message
        .field
        .iter()
        .find(|field| field.name() == field_name)
        .unwrap_or_else(|| panic!("missing {package}.{message_name}.{field_name}"))
        .type_name
        .clone()
        .expect("message field type")
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
