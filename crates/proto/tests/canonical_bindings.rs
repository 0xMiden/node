use miden_node_proto::generated;
use miden_objects::proto;

#[test]
fn generated_service_fields_accept_canonical_object_messages_directly() {
    let block_header = proto::blockchain::BlockHeader::default();
    let response = generated::rpc::BlockHeaderByNumberResponse {
        block_header: Some(block_header),
        ..Default::default()
    };

    let transaction = proto::transaction::ProvenTransactionData::default();
    let request = generated::sequencer::AuthenticatedTransaction {
        transaction: Some(transaction),
        ..Default::default()
    };

    let transaction_inputs = proto::transaction::TransactionInputs::default();
    let proof_request = generated::remote_prover::ProofRequest {
        request: Some(generated::remote_prover::proof_request::Request::Transaction(
            transaction_inputs,
        )),
    };

    assert!(response.block_header.is_some());
    assert!(request.transaction.is_some());
    assert!(proof_request.request.is_some());
}

#[test]
fn generated_canonical_modules_are_exact_reexports() {
    fn accept_word(_: proto::primitives::Word) {}
    fn accept_account_id(_: proto::account::AccountId) {}

    accept_word(generated::primitives::Word::default());
    accept_account_id(generated::account::AccountId::default());
}
