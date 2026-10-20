use std::collections::BTreeMap;

use miden_node_proto::BlockProofRequest;
use miden_node_store::{GenesisState, State};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{
    BlockInputs,
    BlockSignatures,
    ProposedBlock,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::transaction::PartialBlockchain;

use super::prove_pending_blocks;

fn next_block(
    parent: &miden_protocol::block::BlockHeader,
    chain: PartialBlockchain,
    key: &SigningKey,
) -> (BlockProofRequest, SignedBlock) {
    let inputs = BlockInputs::new(
        parent.clone(),
        chain,
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );
    let (header, body) =
        ProposedBlock::new_at(inputs.clone(), vec![], parent.block_num().child().as_u32())
            .unwrap()
            .into_header_and_body()
            .unwrap();
    let signatures = BlockSignatures::new(vec![key.sign(header.commitment())]).unwrap();
    (
        BlockProofRequest {
            tx_batches: OrderedBatches::new(vec![]),
            block_header: header.clone(),
            block_inputs: inputs,
        },
        SignedBlock::new_unchecked(header, body, signatures),
    )
}

async fn fixture() -> (
    tempfile::TempDir,
    std::sync::Arc<State>,
    miden_node_store::BlockWriter,
    miden_node_store::ProofWriter,
    miden_node_store::WriterTask,
    SigningKey,
    BlockProofRequest,
    SignedBlock,
) {
    let key = SigningKey::new();
    let genesis = GenesisState::new(
        vec![],
        miden_node_utils::fee::test_fee_params(),
        0,
        ValidatorConfig::new(vec![key.public_key()], 1).unwrap(),
        miden_node_utils::fee::test_protocol_config(),
    )
    .into_block()
    .unwrap();
    let (request, block) = next_block(genesis.inner().header(), PartialBlockchain::default(), &key);
    let directory = tempfile::tempdir().unwrap();
    State::bootstrap(genesis, directory.path()).await.unwrap();
    let (state, writer, proofs, task) =
        State::load(directory.path(), miden_node_utils::clap::StorageOptions::default())
            .await
            .unwrap()
            .start(CancellationToken::new());
    (directory, state, writer, proofs, task, key, request, block)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_proving_drains_backlog_without_creating_blocks() {
    // Offline proving processes committed blocks without a fee collector or block production task.
    let (_directory, state, mut writer, mut proofs, task, _key, request, block) = fixture().await;
    writer
        .apply_block_with_proving_inputs(request.tx_batches, request.block_inputs, block)
        .await
        .unwrap();
    let committed = state.committed_tip();
    prove_pending_blocks(
        &state,
        &mut proofs,
        None,
        miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(state.committed_tip(), committed);
    assert_eq!(state.proven_tip(), committed);
    assert!(state.load_proof(committed).await.unwrap().is_some());
    assert!(state.load_proving_inputs(committed).await.unwrap().is_none());
    prove_pending_blocks(
        &state,
        &mut proofs,
        None,
        miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(state.committed_tip(), committed);
    drop(proofs);
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_proving_missing_inputs_does_not_advance_tip() {
    // Missing proving inputs leave both the committed and proven tips unchanged.
    let (_directory, state, mut writer, mut proofs, task, _key, _request, block) = fixture().await;
    writer.apply_block(block, None).await.unwrap();
    let committed = state.committed_tip();
    let proven = state.proven_tip();
    let error = prove_pending_blocks(
        &state,
        &mut proofs,
        None,
        miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("no proving inputs found for block 1"));
    assert_eq!(state.committed_tip(), committed);
    assert_eq!(state.proven_tip(), proven);
    assert!(state.load_proof(committed).await.unwrap().is_none());
    drop(proofs);
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_proving_cancelled_before_start_preserves_inputs() {
    // Cancellation preserves the original request so another invocation can resume.
    let (_directory, state, mut writer, mut proofs, task, _key, request, block) = fixture().await;
    writer
        .apply_block_with_proving_inputs(request.tx_batches, request.block_inputs, block)
        .await
        .unwrap();
    let committed = state.committed_tip();
    let proven = state.proven_tip();
    let bytes = state.load_proving_inputs(committed).await.unwrap();
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    assert!(
        prove_pending_blocks(
            &state,
            &mut proofs,
            None,
            miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
            shutdown
        )
        .await
        .is_err()
    );
    assert_eq!(state.load_proving_inputs(committed).await.unwrap(), bytes);
    assert_eq!(state.committed_tip(), committed);
    assert_eq!(state.proven_tip(), proven);
    assert!(state.load_proof(committed).await.unwrap().is_none());
    drop(proofs);
    writer.stop(task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_proving_preserves_completed_prefix_for_retry() {
    // Completed proofs remain stored when a later block has missing inputs, allowing proving to
    // resume once those inputs are restored.
    let (_directory, state, mut writer, mut proofs, task, key, request, block) = fixture().await;
    let mut chain = PartialBlockchain::default();
    chain.add_block(request.block_inputs.prev_block_header(), false);
    let (second_request, second) = next_block(block.header(), chain, &key);
    writer
        .apply_block_with_proving_inputs(request.tx_batches, request.block_inputs, block)
        .await
        .unwrap();
    writer.apply_block(second, None).await.unwrap();
    let target = state.committed_tip();
    assert!(
        prove_pending_blocks(
            &state,
            &mut proofs,
            None,
            miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
            CancellationToken::new()
        )
        .await
        .is_err()
    );
    assert_eq!(state.proven_tip().as_u32(), 1);
    let first_proof = state.load_proof(1.into()).await.unwrap().unwrap();
    writer.save_proving_inputs(target, &second_request).await.unwrap();
    prove_pending_blocks(
        &state,
        &mut proofs,
        None,
        miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(state.proven_tip(), target);
    assert_eq!(state.committed_tip(), target);
    assert_eq!(state.load_proof(1.into()).await.unwrap().unwrap(), first_proof);
    assert!(state.load_proof(target).await.unwrap().is_some());
    drop(proofs);
    writer.stop(task).await;
}
