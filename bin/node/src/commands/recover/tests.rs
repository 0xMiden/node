use std::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::{
    BlockBody,
    BlockHeader,
    BlockSignatures,
    FeeParameters,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::protocol_config::{KernelConfig, ProtocolConfig};
use miden_protocol::transaction::{OrderedTransactionHeaders, PartialBlockchain};
use tokio::sync::mpsc;
use url::Url;

use super::{ProtocolConfigStreamState, RecoveredBlock, coalesce_signatures, next_coalesced_block};

fn signers(count: usize) -> Vec<SigningKey> {
    (0..count).map(|_| SigningKey::new()).collect()
}

fn validator_config(signers: &[SigningKey]) -> ValidatorConfig {
    ValidatorConfig::new(
        signers.iter().map(SigningKey::public_key).collect(),
        u16::try_from(signers.len()).unwrap(),
    )
    .unwrap()
}

fn protocol_configs() -> (ProtocolConfig, ProtocolConfig) {
    let faucet: AccountId = 0xaa00_0000_0000_bc11_0000_bc00_0000_de00u128.try_into().unwrap();
    let first = ProtocolConfig::current(AssetId::new_fungible(faucet)).unwrap();
    let second = ProtocolConfig::new(
        first.fee_asset_id(),
        KernelConfig::new(Word::from([42u32, 0, 0, 0]), vec![]).unwrap(),
        first.batch_kernel().clone(),
        first.block_kernel().clone(),
        first.proof_verification().clone(),
    )
    .unwrap();
    (first, second)
}

#[test]
fn signatures_are_ordered_against_the_validator_set() {
    let commitment = Word::from([1u32, 2, 3, 4]);
    let signers = signers(3);
    let keys = validator_config(&signers);

    // Reversed validator order exercises signature ordering in the recovered block.
    let shuffled = signers.iter().rev().map(|signer| signer.sign(commitment)).collect();

    let coalesced = coalesce_signatures(shuffled, commitment, &keys).unwrap();
    coalesced.verify_against(commitment, &keys).unwrap();
}

#[test]
fn signature_count_mismatch_is_rejected() {
    let commitment = Word::from([1u32, 2, 3, 4]);
    let signers = signers(3);
    let keys = validator_config(&signers);

    let missing_one = signers.iter().take(2).map(|signer| signer.sign(commitment)).collect();

    let err = coalesce_signatures(missing_one, commitment, &keys).unwrap_err();
    assert!(err.to_string().contains("collected 2 signatures"), "{err}");
}

#[test]
fn duplicate_validator_signature_is_rejected() {
    let commitment = Word::from([1u32, 2, 3, 4]);
    let signers = signers(3);
    let keys = validator_config(&signers);

    // Two streams served by the same validator: its signature appears twice and the third
    // validator's signature is missing.
    let duplicated = vec![
        signers[0].sign(commitment),
        signers[0].sign(commitment),
        signers[1].sign(commitment),
    ];

    let err = coalesce_signatures(duplicated, commitment, &keys).unwrap_err();
    assert!(err.to_string().contains("no unmatched signature verifies"), "{err}");
}

#[test]
fn foreign_signature_is_rejected() {
    let commitment = Word::from([1u32, 2, 3, 4]);
    let signers = signers(3);
    let keys = validator_config(&signers);

    // One signature comes from a key outside the validator set.
    let with_foreign = vec![
        signers[0].sign(commitment),
        signers[1].sign(commitment),
        SigningKey::new().sign(commitment),
    ];

    let err = coalesce_signatures(with_foreign, commitment, &keys).unwrap_err();
    assert!(err.to_string().contains("no unmatched signature verifies"), "{err}");
}

#[test]
fn protocol_config_stream_requires_a_baseline() {
    let mut state = ProtocolConfigStreamState::default();

    let err = state
        .accept(Word::from([1u32, 2, 3, 4]), false)
        .expect_err("the first stream response must carry a protocol config");

    assert!(err.to_string().contains("baseline protocol config"), "{err}");
}

#[test]
fn protocol_config_stream_requires_each_transition() {
    let first = Word::from([1u32, 2, 3, 4]);
    let second = Word::from([5u32, 6, 7, 8]);
    let mut state = ProtocolConfigStreamState::default();

    state.accept(first, true).unwrap();
    state.accept(first, false).unwrap();
    let err = state
        .accept(second, false)
        .expect_err("a changed commitment must carry a protocol config");

    assert!(err.to_string().contains("changed protocol config"), "{err}");
}

#[test]
fn rejected_protocol_config_transition_does_not_advance_stream_state() {
    let first = Word::from([1u32, 2, 3, 4]);
    let second = Word::from([5u32, 6, 7, 8]);
    let mut state = ProtocolConfigStreamState::default();

    state.accept(first, true).unwrap();
    state.accept(second, false).unwrap_err();

    state
        .accept(first, false)
        .expect("a rejected transition must preserve the previous commitment");
}

#[tokio::test]
async fn coalescer_rejects_protocol_config_disagreement() {
    let signers = signers(2);
    let validators = validator_config(&signers);
    let (first_config, second_config) = protocol_configs();
    let parent = BlockHeader::new(
        Word::empty(),
        0.into(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        validators.clone(),
        FeeParameters::new(0),
        first_config.to_commitment(),
        None,
        0,
    );
    let body =
        BlockBody::new(vec![], vec![], vec![], OrderedTransactionHeaders::new_unchecked(vec![]))
            .unwrap();
    let header = BlockHeader::new(
        parent.commitment(),
        1.into(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        body.compute_block_note_tree().root(),
        body.transaction_commitment(),
        validators,
        FeeParameters::new(0),
        first_config.to_commitment(),
        None,
        1,
    );
    let mut streams = Vec::new();
    for (index, config) in [first_config, second_config].into_iter().enumerate() {
        let signature = signers[index].sign(header.commitment());
        let block = SignedBlock::new_unchecked(
            header.clone(),
            body.clone(),
            BlockSignatures::new(vec![signature]).unwrap(),
        );
        let (tx, rx) = mpsc::channel(1);
        tx.send(Ok(RecoveredBlock {
            block,
            protocol_config: Some(config),
            proving_inputs: None,
        }))
        .await
        .unwrap();
        streams.push((Url::parse(&format!("http://validator-{index}.test")).unwrap(), rx));
    }

    let err = next_coalesced_block(&mut streams, &parent)
        .await
        .expect_err("validators must agree on the supplied protocol config");

    assert!(err.to_string().contains("protocol config which diverges"), "{err}");
}
use miden_node_proto::BlockProofRequest;
use miden_protocol::block::BlockNumber;

use super::{CancellationToken, State, inputs};

fn empty_recovery_fixture() -> (miden_node_store::GenesisState, BlockProofRequest, SignedBlock) {
    let key = miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey::new();
    let genesis = miden_node_store::GenesisState::new(
        vec![],
        miden_node_utils::fee::test_fee_params(),
        0,
        ValidatorConfig::new(vec![key.public_key()], 1).unwrap(),
        miden_node_utils::fee::test_protocol_config(),
    );
    let parent = genesis.clone().into_block().unwrap().inner().header().clone();
    let block_inputs = miden_protocol::block::BlockInputs::new(
        parent,
        miden_protocol::transaction::PartialBlockchain::default(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );
    let (header, body) =
        miden_protocol::block::ProposedBlock::new_at(block_inputs.clone(), vec![], 1)
            .unwrap()
            .into_header_and_body()
            .unwrap();
    let signatures = BlockSignatures::new(vec![key.sign(header.commitment())]).unwrap();
    let request = BlockProofRequest {
        tx_batches: miden_protocol::batch::OrderedBatches::new(vec![]),
        block_header: header.clone(),
        block_inputs,
    };
    (genesis, request, SignedBlock::new_unchecked(header, body, signatures))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_tip_match_still_recovers_missing_inputs() {
    // Ordinary replication has committed the block without retaining its proving request.
    let (genesis, request, block) = empty_recovery_fixture();
    let directory = tempfile::tempdir().unwrap();
    State::bootstrap(genesis.into_block().unwrap(), directory.path()).await.unwrap();
    let (state, mut writer, proof_writer, task) =
        State::load(directory.path(), miden_node_utils::clap::StorageOptions::default())
            .await
            .unwrap()
            .start(CancellationToken::new());
    writer.apply_block(block.clone(), None).await.unwrap();
    let height = block.header().block_num();
    assert_eq!(inputs::recovery_start(&state, height).await.unwrap(), Some(height));
    inputs::apply_recovered(
        &state,
        &mut writer,
        RecoveredBlock {
            block: block.clone(),
            protocol_config: None,
            proving_inputs: Some(request),
        },
    )
    .await
    .unwrap();
    assert_eq!(state.committed_tip(), height);
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);
    inputs::load_valid_local_inputs(&state, &block).await.unwrap().unwrap();
    assert_eq!(inputs::recovery_start(&state, height).await.unwrap(), None);
    drop(proof_writer);
    writer.stop(task).await;
}

async fn store_for(
    genesis: miden_node_store::GenesisState,
) -> (
    tempfile::TempDir,
    std::sync::Arc<State>,
    miden_node_store::BlockWriter,
    miden_node_store::WriterTask,
) {
    let directory = tempfile::tempdir().unwrap();
    State::bootstrap(genesis.into_block().unwrap(), directory.path()).await.unwrap();
    let (state, writer, proof_writer, task) =
        State::load(directory.path(), miden_node_utils::clap::StorageOptions::default())
            .await
            .unwrap()
            .start(CancellationToken::new());
    drop(proof_writer);
    (directory, state, writer, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_repairs_corrupt_local_inputs() {
    // Recovery detects corrupt local inputs and replaces them with inputs from a validated backup.
    let (genesis, request, block) = empty_recovery_fixture();
    let (directory, state, mut writer, task) = store_for(genesis).await;
    writer.apply_block(block.clone(), None).await.unwrap();
    writer.save_proving_inputs(1.into(), &request).await.unwrap();
    let path = directory.path().join("blocks/0000/inputs_00000001.dat");
    fs_err::write(path, b"corrupt").unwrap();
    assert_eq!(inputs::recovery_start(&state, 1.into()).await.unwrap(), Some(1.into()));
    inputs::apply_recovered(
        &state,
        &mut writer,
        RecoveredBlock {
            block: block.clone(),
            protocol_config: None,
            proving_inputs: Some(request),
        },
    )
    .await
    .unwrap();
    inputs::load_valid_local_inputs(&state, &block).await.unwrap().unwrap();
    assert_eq!(inputs::recovery_start(&state, 1.into()).await.unwrap(), None);
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_preserves_valid_local_inputs() {
    // A backup without proving inputs can supply signatures while preserving the local request byte
    // for byte.
    let (genesis, request, block) = empty_recovery_fixture();
    let (_directory, state, mut writer, task) = store_for(genesis).await;
    writer.apply_block(block.clone(), None).await.unwrap();
    writer.save_proving_inputs(1.into(), &request).await.unwrap();
    let before = state.load_proving_inputs(1.into()).await.unwrap();
    inputs::apply_recovered(
        &state,
        &mut writer,
        RecoveredBlock {
            block,
            protocol_config: None,
            proving_inputs: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(state.load_proving_inputs(1.into()).await.unwrap(), before);
    assert_eq!(state.committed_tip(), 1.into());
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);
    writer.stop(task).await;
}

fn wrong_timestamp(request: BlockProofRequest) -> BlockProofRequest {
    let (header, _) = miden_protocol::block::ProposedBlock::new_at(
        request.block_inputs.clone(),
        vec![],
        request.block_header.timestamp() + 1,
    )
    .unwrap()
    .into_header_and_body()
    .unwrap();
    BlockProofRequest { block_header: header, ..request }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_rejects_wrong_inputs_before_writing() {
    // Recovery rejects mismatched backup inputs without modifying valid local inputs.
    let (genesis, request, block) = empty_recovery_fixture();
    let (_directory, state, mut writer, task) = store_for(genesis).await;
    writer.apply_block(block.clone(), None).await.unwrap();
    writer.save_proving_inputs(1.into(), &request).await.unwrap();
    let before = state.load_proving_inputs(1.into()).await.unwrap();
    assert!(
        inputs::apply_recovered(
            &state,
            &mut writer,
            RecoveredBlock {
                block,
                protocol_config: None,
                proving_inputs: Some(wrong_timestamp(request))
            }
        )
        .await
        .is_err()
    );
    assert_eq!(state.load_proving_inputs(1.into()).await.unwrap(), before);
    assert_eq!(state.committed_tip(), 1.into());
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_rejects_local_chain_divergence() {
    // Recovery preserves the local block and inputs when a valid backup belongs to a different
    // chain.
    let (genesis, request, block) = empty_recovery_fixture();
    let (_, other_request, other_block) = empty_recovery_fixture();
    let (_directory, state, mut writer, task) = store_for(genesis).await;
    writer.apply_block(block, None).await.unwrap();
    writer.save_proving_inputs(1.into(), &request).await.unwrap();
    let before = state.load_block(1.into()).await.unwrap();
    let before_inputs = state.load_proving_inputs(1.into()).await.unwrap();
    let error = inputs::apply_recovered(
        &state,
        &mut writer,
        RecoveredBlock {
            block: other_block,
            protocol_config: None,
            proving_inputs: Some(other_request),
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("diverges"));
    assert_eq!(state.load_block(1.into()).await.unwrap(), before);
    assert_eq!(state.load_proving_inputs(1.into()).await.unwrap(), before_inputs);
    assert_eq!(state.committed_tip(), 1.into());
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_requires_inputs_before_applying_new_block() {
    // Recovery rejects a new block when its proving inputs are unavailable.
    let (genesis, _, block) = empty_recovery_fixture();
    let (_directory, state, mut writer, task) = store_for(genesis).await;
    let error = inputs::apply_recovered(
        &state,
        &mut writer,
        RecoveredBlock {
            block,
            protocol_config: None,
            proving_inputs: None,
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("no proving inputs available for block 1"));
    assert_eq!(state.committed_tip(), BlockNumber::GENESIS);
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);
    assert!(state.load_proving_inputs(1.into()).await.unwrap().is_none());
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_refuses_gap_above_validator_tip() {
    // Recovery rejects missing inputs above the validators' tip before writing to the local store.
    let (genesis, _, block) = empty_recovery_fixture();
    let (_directory, state, mut writer, task) = store_for(genesis).await;
    writer.apply_block(block, None).await.unwrap();
    let error = inputs::recovery_start(&state, BlockNumber::GENESIS).await.unwrap_err();
    assert!(error.to_string().contains("exceed validator recovery tip"));
    assert!(state.load_proving_inputs(1.into()).await.unwrap().is_none());
    assert_eq!(state.committed_tip(), 1.into());
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);
    writer.stop(task).await;
}

async fn input_streams(
    include_first: bool,
    bad_second: bool,
) -> (BlockHeader, Vec<(Url, mpsc::Receiver<anyhow::Result<RecoveredBlock>>)>) {
    let signers = signers(2);
    let genesis = miden_node_store::GenesisState::new(
        vec![],
        miden_node_utils::fee::test_fee_params(),
        0,
        validator_config(&signers),
        miden_node_utils::fee::test_protocol_config(),
    );
    let parent = genesis.into_block().unwrap().inner().header().clone();
    let mut streams = Vec::new();
    for (index, signer) in signers.into_iter().enumerate() {
        let block_inputs = miden_protocol::block::BlockInputs::new(
            parent.clone(),
            PartialBlockchain::default(),
            BTreeMap::default(),
            BTreeMap::default(),
            BTreeMap::default(),
        );
        let (header, body) =
            miden_protocol::block::ProposedBlock::new_at(block_inputs.clone(), vec![], 1)
                .unwrap()
                .into_header_and_body()
                .unwrap();
        let signatures = BlockSignatures::new(vec![signer.sign(header.commitment())]).unwrap();
        let request = BlockProofRequest {
            tx_batches: miden_protocol::batch::OrderedBatches::new(vec![]),
            block_header: header.clone(),
            block_inputs,
        };
        let request = if index == 1 && bad_second {
            wrong_timestamp(request)
        } else {
            request
        };
        let block = SignedBlock::new_unchecked(header, body, signatures);
        let (tx, rx) = mpsc::channel(1);
        tx.send(Ok(RecoveredBlock {
            block,
            protocol_config: None,
            proving_inputs: (index == 1 || include_first).then_some(request),
        }))
        .await
        .unwrap();
        streams.push((Url::parse(&format!("http://validator-{index}.test")).unwrap(), rx));
    }
    (parent, streams)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_uses_one_validator_input_copy() {
    // Every signature is required, but just one validator needs to retain the request.
    let (parent, mut streams) = input_streams(false, false).await;
    let recovered = next_coalesced_block(&mut streams, &parent).await.unwrap();
    recovered.proving_inputs.unwrap().validate_against(&recovered.block).unwrap();
    recovered.block.validate(Some(&parent)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_rejects_a_bad_supplied_copy() {
    // Recovery checks every supplied proving request, even after finding a valid one.
    let (parent, mut streams) = input_streams(true, true).await;
    let error = next_coalesced_block(&mut streams, &parent).await.unwrap_err();
    assert!(error.to_string().contains("validator-1.test"), "{error}");
    assert!(error.to_string().contains("block 1"), "{error}");
}

fn proposal_pair(
    parent: &BlockHeader,
    chain: miden_protocol::transaction::PartialBlockchain,
    next: Option<miden_protocol::protocol_config::NextProtocolConfig>,
    key: &SigningKey,
) -> (SignedBlock, BlockProofRequest) {
    let block_inputs = miden_protocol::block::BlockInputs::new(
        parent.clone(),
        chain,
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );
    let (header, body) = miden_protocol::block::ProposedBlock::new_at(
        block_inputs.clone(),
        vec![],
        parent.timestamp() + 1,
    )
    .unwrap()
    .with_next_protocol_config(next)
    .into_header_and_body()
    .unwrap();
    let signatures = BlockSignatures::new(vec![key.sign(header.commitment())]).unwrap();
    let request = BlockProofRequest {
        tx_batches: miden_protocol::batch::OrderedBatches::new(vec![]),
        block_header: header.clone(),
        block_inputs,
    };
    (SignedBlock::new_unchecked(header, body, signatures), request)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_preserves_scheduled_protocol_transition() {
    // Recovery preserves scheduled protocol upgrades in both blocks and proving requests.
    let key = SigningKey::new();
    let first = miden_node_utils::fee::test_protocol_config();
    let (_, second) = protocol_configs();
    let genesis = miden_node_store::GenesisState::new(
        vec![],
        miden_node_utils::fee::test_fee_params(),
        0,
        ValidatorConfig::new(vec![key.public_key()], 1).unwrap(),
        first.clone(),
    );
    let parent = genesis.clone().into_block().unwrap().inner().header().clone();
    let (_directory, state, mut writer, task) = store_for(genesis).await;
    let next =
        miden_protocol::protocol_config::NextProtocolConfig::new(10.into(), second.to_commitment())
            .unwrap();
    let mut chain = miden_protocol::transaction::PartialBlockchain::default();
    let (block, request) = proposal_pair(&parent, chain.clone(), Some(next.clone()), &key);
    inputs::apply_recovered(
        &state,
        &mut writer,
        RecoveredBlock {
            block: block.clone(),
            protocol_config: Some(first.clone()),
            proving_inputs: Some(request),
        },
    )
    .await
    .unwrap();
    chain.add_block(&parent, false);
    let (second_block, request) = proposal_pair(block.header(), chain, Some(next.clone()), &key);
    inputs::apply_recovered(
        &state,
        &mut writer,
        RecoveredBlock {
            block: second_block.clone(),
            protocol_config: None,
            proving_inputs: Some(request),
        },
    )
    .await
    .unwrap();
    for block in [&block, &second_block] {
        let request = inputs::load_valid_local_inputs(&state, block).await.unwrap().unwrap();
        assert_eq!(request.block_header.next_protocol_config(), Some(&next));
        assert_eq!(
            state
                .view()
                .get_protocol_config_commitment_at(block.header().block_num())
                .await
                .unwrap(),
            Some(first.to_commitment())
        );
    }
    assert_eq!(
        state.view().get_protocol_config(first.to_commitment()).await.unwrap(),
        Some(first)
    );
    assert_eq!(state.committed_tip(), 2.into());
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_uses_active_configuration_after_legacy_activation() {
    // Proving inputs for the child block retain the configuration established by its parent.
    //
    // The proposal builder cannot generate an activation header, so a legacy header models the
    // parent's configuration activation.
    let key = SigningKey::new();
    let first = miden_node_utils::fee::test_protocol_config();
    let (_, second) = protocol_configs();
    let genesis = miden_node_store::GenesisState::new(
        vec![],
        miden_node_utils::fee::test_fee_params(),
        0,
        ValidatorConfig::new(vec![key.public_key()], 1).unwrap(),
        first,
    );
    let parent = genesis.clone().into_block().unwrap().inner().header().clone();
    let (_directory, state, mut writer, task) = store_for(genesis).await;
    let (base, _) = proposal_pair(&parent, PartialBlockchain::default(), None, &key);
    let (base, body, _) = base.into_parts();
    let header = BlockHeader::new(
        base.prev_block_commitment(),
        base.block_num(),
        base.chain_commitment(),
        base.account_root(),
        base.nullifier_root(),
        base.note_root(),
        base.tx_commitment(),
        base.validator_config().clone(),
        base.fee_parameters().clone(),
        second.to_commitment(),
        None,
        base.timestamp(),
    );
    let signatures = BlockSignatures::new(vec![key.sign(header.commitment())]).unwrap();
    let activation = SignedBlock::new_unchecked(header, body, signatures);
    writer.apply_block(activation.clone(), Some(second.clone())).await.unwrap();
    let mut chain = miden_protocol::transaction::PartialBlockchain::default();
    chain.add_block(&parent, false);
    let (block, request) = proposal_pair(activation.header(), chain, None, &key);
    inputs::apply_recovered(
        &state,
        &mut writer,
        RecoveredBlock {
            block: block.clone(),
            protocol_config: Some(second.clone()),
            proving_inputs: Some(request),
        },
    )
    .await
    .unwrap();
    inputs::load_valid_local_inputs(&state, &block).await.unwrap().unwrap();
    assert_eq!(
        state.view().get_protocol_config(second.to_commitment()).await.unwrap(),
        Some(second.clone())
    );
    assert_eq!(
        state.view().get_protocol_config_commitment_at(2.into()).await.unwrap(),
        Some(second.to_commitment())
    );
    assert_eq!(state.committed_tip(), 2.into());
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);
    writer.stop(task).await;
}

#[test]
fn recover_selects_optional_offline_prover() {
    use clap::Parser;

    // A prover URL configures proving but never enables it implicitly.
    let base = [
        "miden-node",
        "recover",
        "--data-directory",
        "node-data",
        "--validator.url",
        "http://127.0.0.1:50101",
    ];
    for (extra, prove, expected_url) in [
        (vec![], false, None),
        (vec!["--prove"], true, None),
        (
            vec!["--prove", "--block-prover.url", "http://127.0.0.1:50051"],
            true,
            Some("http://127.0.0.1:50051/"),
        ),
        (
            vec!["--block-prover.url", "http://127.0.0.1:50051"],
            false,
            Some("http://127.0.0.1:50051/"),
        ),
    ] {
        let cli = crate::Cli::try_parse_from(base.into_iter().chain(extra)).unwrap();
        let crate::commands::Command::Recover(command) = cli.command else {
            panic!("expected recovery command")
        };
        assert_eq!(command.prove, prove);
        assert_eq!(command.block_prover.url.as_ref().map(Url::as_str), expected_url);
    }
}

mod failover;
mod support;
