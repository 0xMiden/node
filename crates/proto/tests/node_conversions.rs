use std::collections::BTreeMap;

use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_node_proto::domain::submission::{
    ProvenTransactionSubmission,
    TransactionBatchSubmission,
};
use miden_node_proto::generated;
use miden_objects::proto;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::batch::{BatchId, OrderedBatches, ProvenBatch};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::transaction::{
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    PartialBlockchain,
};
use miden_protocol::vm::ExecutionProof;

fn private_account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

fn empty_block_inputs() -> BlockInputs {
    let partial_blockchain = PartialBlockchain::default();
    BlockInputs::new(
        BlockHeader::mock(0, Some(partial_blockchain.peaks().hash_peaks()), None, &[]),
        partial_blockchain,
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    )
}

fn block_request_message() -> generated::block_proving::BlockProofRequest {
    let block_inputs = empty_block_inputs();
    let timestamp = block_inputs.prev_block_header().timestamp() + 1;
    let request = BlockProofRequest {
        tx_batches: OrderedBatches::new(Vec::new()),
        block_header: BlockHeader::mock(1, None, None, &[]),
        block_inputs,
    };

    let mut message: generated::block_proving::BlockProofRequest = request.into();
    message.timestamp = timestamp;
    message
}

fn empty_batch(reference_block_num: u32) -> ProvenBatch {
    ProvenBatch::new_unchecked(
        BatchId::from_ids([]),
        Word::from([reference_block_num, 1, 0, 0]),
        BlockNumber::from(reference_block_num),
        BTreeMap::new(),
        InputNotes::<InputNoteCommitment>::default(),
        Vec::new(),
        BlockNumber::from(reference_block_num + 1),
        OrderedTransactionHeaders::new_unchecked(Vec::new()),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}

#[test]
fn block_proof_request_rejects_missing_block_inputs() {
    let error = BlockProofRequest::try_from(generated::block_proving::BlockProofRequest {
        block_inputs: None,
        ..Default::default()
    })
    .unwrap_err();

    assert!(error.to_string().contains("block_inputs"));
}

#[test]
fn block_proof_request_rejects_duplicate_requested_account_ids() {
    let requested_id = private_account_id(7);
    let witness = AccountWitness::new(
        private_account_id(8),
        Word::empty(),
        SparseMerklePath::from_parts(u64::MAX, Vec::new()).unwrap(),
    )
    .unwrap();
    let duplicate = generated::block_proving::AccountWitnessRecord {
        account_id: Some(requested_id.into()),
        witness: Some(witness.into()),
    };
    let mut message = block_request_message();
    message.block_inputs.as_mut().unwrap().account_witnesses = vec![duplicate.clone(), duplicate];

    let error = BlockProofRequest::try_from(message).unwrap_err();

    assert!(error.to_string().contains("duplicate requested account ID"));
}

#[test]
fn block_proof_request_preserves_requested_account_id_separately_from_witness_id() {
    let requested_id = private_account_id(7);
    let witness_id = private_account_id(8);
    let witness = AccountWitness::new(
        witness_id,
        Word::empty(),
        SparseMerklePath::from_parts(u64::MAX, Vec::new()).unwrap(),
    )
    .unwrap();
    let mut message = block_request_message();
    message.block_inputs.as_mut().unwrap().account_witnesses =
        vec![generated::block_proving::AccountWitnessRecord {
            account_id: Some(requested_id.into()),
            witness: Some(witness.into()),
        }];

    let decoded = BlockProofRequest::try_from(message).unwrap();

    let decoded_witness = &decoded.block_inputs.account_witnesses()[&requested_id];
    assert_eq!(decoded_witness.id(), witness_id);
}

#[test]
fn block_proof_request_preserves_batch_order() {
    let block_inputs = empty_block_inputs();
    let request = BlockProofRequest {
        tx_batches: OrderedBatches::new(vec![empty_batch(3), empty_batch(7)]),
        block_header: BlockHeader::mock(1, None, None, &[]),
        block_inputs,
    };

    let message: generated::block_proving::BlockProofRequest = request.into();
    let reference_block_nums = message
        .batches
        .into_iter()
        .map(|batch| batch.reference_block_num.unwrap().block_num)
        .collect::<Vec<_>>();

    assert_eq!(reference_block_nums, [3, 7]);
}

#[test]
fn submission_rejects_missing_transaction() {
    let message = generated::submission::ProvenTransactionSubmission {
        transaction: None,
        sealed_transaction_inputs: Some(generated::submission::SealedTransactionInputs {
            key_id: vec![1],
            ciphertext: vec![2],
        }),
    };

    let error = ProvenTransactionSubmission::try_from(message).unwrap_err();

    assert!(error.to_string().contains("transaction"));
}

#[test]
fn batch_submission_rejects_proof_that_does_not_match_proposal() {
    let partial_blockchain = PartialBlockchain::default();
    let reference_header =
        BlockHeader::mock(0, Some(partial_blockchain.peaks().hash_peaks()), None, &[]);
    let message = generated::submission::TransactionBatch {
        batch: Some(proto::transaction::ProvenBatch {
            reference_block_num: Some(BlockNumber::from(1_u32).into()),
            ..Default::default()
        }),
        proposed_batch: Some(proto::transaction::ProposedBatch {
            reference_block_header: Some(reference_header.into()),
            ..Default::default()
        }),
        sealed_transaction_inputs: Vec::new(),
    };

    let error = TransactionBatchSubmission::try_from(message).unwrap_err();

    assert!(error.to_string().contains("does not match proposal"));
}

#[test]
fn canonical_conversion_errors_map_to_invalid_argument() {
    let error = miden_protocol::account::AccountId::try_from(proto::account::AccountId::default())
        .unwrap_err();
    let status: tonic::Status = miden_node_proto::errors::ConversionError::from(error).into();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
