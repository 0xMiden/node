use std::collections::BTreeMap;
use std::error::Error as _;

use miden_node_proto::domain::proof_request::BlockProofRequest;
use miden_node_proto::{BuildUnchecked, DecodeMessage, Verify, generated};
use miden_objects::proto;
use miden_protocol::Word;
use miden_protocol::account::{
    AccountId,
    AccountIdVersion,
    AccountType,
    AccountUpdateDetails,
    AssetCallbackFlag,
};
use miden_protocol::batch::{BatchAccountUpdate, BatchId, OrderedBatches, ProvenBatch};
use miden_protocol::block::account_tree::{AccountTree, AccountWitness};
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{
    BlockHeader,
    BlockInputs,
    BlockNoteIndex,
    BlockNoteTree,
    BlockNumber,
    FeeParameters,
    ProposedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{Note, NoteInclusionProof};
use miden_protocol::protocol_config::NextProtocolConfig;
use miden_protocol::transaction::{
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    PartialBlockchain,
    TransactionHeader,
};
use prost::Message;

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
        miden_protocol::testing::dummy_execution_proof(),
    )
    .unwrap()
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixture includes every block witness and configuration change"
)]
fn nonempty_block_request() -> BlockProofRequest {
    let account_tree: AccountTree = AccountTree::default();
    let nullifier_tree: NullifierTree = NullifierTree::default();
    let partial_blockchain = PartialBlockchain::default();
    let account_ids = [private_account_id(7), private_account_id(3)];
    let notes = [
        Note::mock_noop(Word::from([7_u32, 0, 0, 0])),
        Note::mock_noop(Word::from([3_u32, 0, 0, 0])),
    ];
    let note_tree = BlockNoteTree::with_entries(
        notes
            .iter()
            .enumerate()
            .map(|(index, note)| (BlockNoteIndex::new(0, index).unwrap(), note.header())),
    )
    .unwrap();
    let (_, validator_config) = ValidatorConfig::random_with_signers(1);
    let previous_upgrade =
        NextProtocolConfig::new(BlockNumber::from(20), Word::from([1_u32, 2, 3, 4])).unwrap();
    let prev_block_header = BlockHeader::new(
        Word::empty(),
        BlockNumber::GENESIS,
        partial_blockchain.peaks().hash_peaks(),
        account_tree.root(),
        nullifier_tree.root(),
        note_tree.root(),
        Word::empty(),
        validator_config,
        FeeParameters::new(0),
        Word::from([5_u32, 6, 7, 8]),
        Some(previous_upgrade),
        100,
    );
    let account_witnesses = account_ids
        .iter()
        .map(|account_id| (*account_id, account_tree.open(*account_id)))
        .collect();
    let nullifier_witnesses = notes
        .iter()
        .map(|note| (note.nullifier(), nullifier_tree.open(&note.nullifier())))
        .collect();
    let note_proofs = notes
        .iter()
        .enumerate()
        .map(|(index, note)| {
            let index = BlockNoteIndex::new(0, index).unwrap();
            let proof = NoteInclusionProof::new(
                BlockNumber::GENESIS,
                index.leaf_index_value(),
                note_tree.open(index),
            )
            .unwrap();
            (note.id(), proof)
        })
        .collect();
    let batches = account_ids
        .into_iter()
        .zip(notes)
        .map(|(account_id, note)| {
            let final_state = note.id().as_word();
            let input_notes = InputNotes::new(vec![InputNoteCommitment::from_parts_unchecked(
                note.nullifier(),
                Some(*note.header()),
            )])
            .unwrap();
            let transaction = TransactionHeader::new(
                account_id,
                Word::empty(),
                final_state,
                input_notes.clone(),
                Vec::new(),
            )
            .unwrap();
            let update = BatchAccountUpdate::new(
                account_id,
                Word::empty(),
                final_state,
                AccountUpdateDetails::Private,
            )
            .unwrap();
            ProvenBatch::new(
                prev_block_header.commitment(),
                BlockNumber::GENESIS,
                [update],
                input_notes,
                Vec::new(),
                BlockNumber::from(10),
                OrderedTransactionHeaders::new_unchecked(vec![transaction]),
                miden_protocol::testing::dummy_execution_proof(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let block_inputs = BlockInputs::new(
        prev_block_header,
        partial_blockchain,
        account_witnesses,
        nullifier_witnesses,
        note_proofs,
    );
    let (_, rotated_validators) = ValidatorConfig::random_with_signers(2);
    let next_protocol_config =
        NextProtocolConfig::new(BlockNumber::from(30), Word::from([9_u32, 10, 11, 12])).unwrap();
    let proposed = ProposedBlock::new_at(block_inputs.clone(), batches.clone(), 123)
        .unwrap()
        .with_next_validator_config(rotated_validators)
        .with_next_protocol_config(Some(next_protocol_config));
    let (block_header, _) = proposed.into_header_and_body().unwrap();

    BlockProofRequest {
        tx_batches: OrderedBatches::new(batches),
        block_header,
        block_inputs,
    }
}

#[test]
fn nonempty_block_proof_roundtrip_preserves_header_order_and_witnesses() {
    let request = nonempty_block_request();
    let message = generated::block_proving::BlockProofRequest::from(&request);
    let wire = message.encode_to_vec();
    let decoded = generated::block_proving::BlockProofRequest::decode(wire.as_slice())
        .unwrap()
        .decode_fields()
        .and_then(BuildUnchecked::build_unchecked)
        .unwrap();

    assert_eq!(decoded.block_header, request.block_header);
    assert_eq!(decoded.block_header.commitment(), request.block_header.commitment());
    assert_eq!(decoded.block_header.timestamp(), 123);
    assert_ne!(
        decoded.block_header.validator_config(),
        request.block_inputs.prev_block_header().validator_config(),
    );
    assert_ne!(
        decoded.block_header.next_protocol_config(),
        request.block_inputs.prev_block_header().next_protocol_config(),
    );
    assert_eq!(
        decoded.tx_batches.as_slice().iter().map(ProvenBatch::id).collect::<Vec<_>>(),
        request.tx_batches.as_slice().iter().map(ProvenBatch::id).collect::<Vec<_>>(),
    );
    assert_eq!(
        generated::block_proving::BlockInputs::from(&decoded.block_inputs),
        generated::block_proving::BlockInputs::from(&request.block_inputs),
    );
    assert_eq!(decoded.block_inputs.account_witnesses().len(), 2);
    assert_eq!(decoded.block_inputs.nullifier_witnesses().len(), 2);
    assert_eq!(decoded.block_inputs.unauthenticated_note_proofs().len(), 2);
}

#[test]
fn block_proof_request_can_clear_the_parent_protocol_upgrade() {
    let request = nonempty_block_request();
    let expected = ProposedBlock::new_at(
        request.block_inputs.clone(),
        request.tx_batches.as_slice().to_vec(),
        request.block_header.timestamp(),
    )
    .unwrap()
    .with_next_validator_config(request.block_header.validator_config().clone())
    .with_next_protocol_config(None)
    .into_header_and_body()
    .unwrap()
    .0;
    let mut message = generated::block_proving::BlockProofRequest::from(&request);
    message.next_protocol_config = None;

    let decoded = message.decode_fields().and_then(BuildUnchecked::build_unchecked).unwrap();

    assert!(decoded.block_inputs.prev_block_header().next_protocol_config().is_some());
    assert!(decoded.block_header.next_protocol_config().is_none());
    assert_eq!(decoded.block_header, expected);
}

#[test]
fn block_proof_request_rejects_duplicate_nullifier_witnesses() {
    let mut message = generated::block_proving::BlockProofRequest::from(&nonempty_block_request());
    let witnesses = &mut message.block_inputs.as_mut().unwrap().nullifier_witnesses;
    witnesses.push(witnesses[0].clone());

    let error = message.decode_fields().and_then(BuildUnchecked::build_unchecked).unwrap_err();

    assert!(error.to_string().contains("duplicate nullifier"));
}

#[test]
fn block_proof_request_rejects_duplicate_note_proofs() {
    let mut message = generated::block_proving::BlockProofRequest::from(&nonempty_block_request());
    let proofs = &mut message.block_inputs.as_mut().unwrap().unauthenticated_note_proofs;
    proofs.push(proofs[0].clone());

    let error = message.decode_fields().and_then(BuildUnchecked::build_unchecked).unwrap_err();

    assert!(error.to_string().contains("duplicate note ID"));
}

#[test]
fn malformed_block_batch_preserves_the_canonical_error_source() {
    let mut message = generated::block_proving::BlockProofRequest::from(&nonempty_block_request());
    message.batches[0].reference_block_commitment =
        Some(proto::primitives::Word { encoded: vec![0xff; 32] });

    let error = message.decode_fields().unwrap_err();

    assert!(
        error.to_string().starts_with("batches[0].reference_block_commitment.encoded:"),
        "{error}"
    );
    assert!(
        error
            .source()
            .unwrap()
            .is::<miden_protocol::utils::serde::DeserializationError>()
    );
}

#[test]
fn block_proof_request_rejects_missing_block_inputs() {
    let error =
        generated::block_proving::BlockProofRequest { block_inputs: None, ..Default::default() }
            .decode_fields()
            .and_then(BuildUnchecked::build_unchecked)
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

    let error = message.decode_fields().and_then(BuildUnchecked::build_unchecked).unwrap_err();

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

    let decoded = message.decode_fields().and_then(BuildUnchecked::build_unchecked).unwrap();

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

    let error = message.decode_fields().and_then(BuildUnchecked::build_unchecked).unwrap_err();

    assert!(error.to_string().contains("transaction"));
}

#[test]
fn batch_submission_rejects_proof_that_does_not_match_proposal() {
    let partial_blockchain = PartialBlockchain::default();
    let reference_header =
        BlockHeader::mock(0, Some(partial_blockchain.peaks().hash_peaks()), None, &[]);
    let message = generated::submission::TransactionBatch {
        batch: Some(empty_batch(1).into()),
        proposed_batch: Some(proto::transaction::ProposedBatch {
            reference_block_header: Some(reference_header.into()),
            partial_blockchain: Some((&partial_blockchain).into()),
            ..Default::default()
        }),
        sealed_transaction_inputs: Vec::new(),
    };

    let error = message.decode_fields().and_then(Verify::verify).unwrap_err();

    assert!(error.to_string().contains("does not match proposal"));
}

#[test]
fn canonical_conversion_errors_map_to_invalid_argument() {
    let error = proto::account::AccountId::default().decode_fields().unwrap_err();
    let status = miden_node_proto::errors::conversion_error_to_status(error);

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

fn signing_request() -> miden_node_proto::SignBlockRequest {
    let proof = nonempty_block_request();
    miden_node_proto::SignBlockRequest {
        tx_batches: proof.tx_batches,
        block_header: proof.block_header,
        block_inputs: proof.block_inputs,
        protocol_config: None,
    }
}

#[test]
fn signing_roundtrip_preserves_proposal_and_matches_proving() {
    let request = signing_request();
    let message = generated::validator::SignBlockRequest::from(&request);
    let decoded = miden_node_proto::SignBlockRequest::try_from(
        generated::validator::SignBlockRequest::decode(message.encode_to_vec().as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.block_header, request.block_header);
    assert_eq!(decoded.tx_batches.as_slice(), request.tx_batches.as_slice());
    assert_eq!(
        generated::block_proving::BlockInputs::from(&decoded.block_inputs),
        generated::block_proving::BlockInputs::from(&request.block_inputs)
    );
    assert!(decoded.protocol_config.is_none());
    let proof_message = generated::block_proving::BlockProofRequest {
        batches: message.batches,
        block_inputs: message.block_inputs,
        timestamp: message.timestamp,
        next_validator_config: message.next_validator_config,
        next_protocol_config: message.next_protocol_config,
    };
    let proof = BlockProofRequest::try_from(proof_message).unwrap();
    assert_eq!(decoded.block_header, proof.block_header);
}

#[test]
fn signing_rejects_missing_fields_and_malformed_batches() {
    let message = generated::validator::SignBlockRequest::from(&signing_request());
    for field in ["block_inputs", "next_validator_config"] {
        let mut invalid = message.clone();
        if field == "block_inputs" {
            invalid.block_inputs = None;
        } else {
            invalid.next_validator_config = None;
        }
        let error = miden_node_proto::SignBlockRequest::try_from(invalid).unwrap_err();
        assert!(error.to_string().contains(field));
    }
    let mut invalid = message;
    invalid.batches[0] = proto::transaction::ProvenBatch::default();
    let error = miden_node_proto::SignBlockRequest::try_from(invalid).unwrap_err();
    assert!(error.to_string().contains("batches[0]"));
    assert!(
        error
            .source()
            .unwrap()
            .downcast_ref::<miden_objects::ConversionError>()
            .is_some()
    );
}

#[test]
fn signing_rejects_duplicate_witnesses_and_preserves_absent_next_config() {
    let mut message = generated::validator::SignBlockRequest::from(&signing_request());
    message.next_protocol_config = None;
    let decoded = miden_node_proto::SignBlockRequest::try_from(message.clone()).unwrap();
    assert!(decoded.block_header.next_protocol_config().is_none());
    let witnesses = &mut message.block_inputs.as_mut().unwrap().nullifier_witnesses;
    witnesses.push(witnesses[0].clone());
    let error = miden_node_proto::SignBlockRequest::try_from(message).unwrap_err();
    assert!(error.to_string().contains("duplicate nullifier"));
}

#[test]
fn signing_roundtrip_validates_supplied_active_configuration() {
    use miden_protocol::asset::AssetId;
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;

    let config = ProtocolConfig::current(AssetId::new_fungible(
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
    ))
    .unwrap();
    let proof = block_request_message();
    let mut message = generated::validator::SignBlockRequest {
        batches: proof.batches,
        block_inputs: proof.block_inputs,
        timestamp: proof.timestamp,
        next_validator_config: proof.next_validator_config,
        next_protocol_config: proof.next_protocol_config,
        protocol_config: Some((&config).into()),
    };
    assert!(miden_node_proto::SignBlockRequest::try_from(message.clone()).is_err());
    message
        .block_inputs
        .as_mut()
        .unwrap()
        .prev_block_header
        .as_mut()
        .unwrap()
        .protocol_config_commitment = Some(config.to_commitment().into());
    let decoded = miden_node_proto::SignBlockRequest::try_from(message.clone()).unwrap();
    assert_eq!(decoded.protocol_config, Some(config));
    let encoded = generated::validator::SignBlockRequest::from(decoded);
    assert_eq!(encoded, message);
}
