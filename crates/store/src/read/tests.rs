use std::sync::Arc;

use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::block::{BlockNumber, ValidatorConfig};
use miden_protocol::testing::random_secret_key::random_secret_key;

use crate::{DatabaseError, GenesisState, State};

pub(crate) async fn state() -> (tempfile::TempDir, Arc<State>, crate::BlockWriter) {
    state_with_pool_size(2).await
}

async fn state_with_pool_size(
    pool_size: usize,
) -> (tempfile::TempDir, Arc<State>, crate::BlockWriter) {
    let directory = tempfile::tempdir().unwrap();
    let signer = random_secret_key();
    let genesis = GenesisState::new(
        vec![],
        test_fee_params(),
        1,
        ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
        test_protocol_config(),
    )
    .into_block()
    .unwrap();
    State::bootstrap(genesis, directory.path()).await.unwrap();
    let (state, writer, _proof_writer, _task) = State::load_with_database_options(
        directory.path(),
        miden_node_utils::clap::StorageOptions::default(),
        crate::DatabaseOptions {
            connection_pool_size: std::num::NonZeroUsize::new(pool_size).unwrap(),
        },
    )
    .await
    .unwrap()
    .start(miden_node_utils::shutdown::CancellationToken::new());
    (directory, state, writer)
}

#[tokio::test]
async fn reads_header_and_configuration_from_the_snapshot() {
    let (_directory, state, _writer) = state().await;
    state
        .read(|view| -> Result<(), DatabaseError> {
            assert_eq!(view.snapshot.block_num, BlockNumber::GENESIS);
            let header = view.tx.select_block_header(view.snapshot.block_num)?.unwrap();
            assert_eq!(view.snapshot.blockchain.as_mmr().get(0).unwrap(), header.commitment());
            let config =
                view.tx.select_protocol_config(header.protocol_config_commitment())?.unwrap();
            assert_eq!(config, test_protocol_config());
            Ok(())
        })
        .await
        .unwrap();
}

/// Builds an empty child block whose roots preserve the current state.
pub(crate) async fn next_block(state: &State) -> miden_protocol::block::SignedBlock {
    use miden_protocol::block::{BlockBody, BlockHeader, BlockSignatures, SignedBlock};
    use miden_protocol::transaction::OrderedTransactionHeaders;

    state
        .read(|view| -> Result<_, DatabaseError> {
            let parent = view.tx.select_block_header(view.snapshot.block_num)?.unwrap();
            let body = BlockBody::new(
                vec![],
                vec![],
                vec![],
                OrderedTransactionHeaders::new_unchecked(vec![]),
            )
            .unwrap();
            let header = BlockHeader::new(
                parent.commitment(),
                parent.block_num().child(),
                view.snapshot.blockchain.commitment(),
                parent.account_root(),
                parent.nullifier_root(),
                body.compute_block_note_tree().root(),
                body.transaction_commitment(),
                parent.validator_config().clone(),
                parent.fee_parameters().clone(),
                parent.protocol_config_commitment(),
                None,
                parent.timestamp() + 1,
            );
            Ok(SignedBlock::new_unchecked(header, body, BlockSignatures::new(vec![]).unwrap()))
        })
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn held_read_stays_consistent_while_a_block_commits() {
    let (_directory, state, mut writer) = state().await;
    let block = next_block(&state).await;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let reader = Arc::clone(&state);
    let read = tokio::spawn(async move {
        reader
            .read(move |view| -> Result<(), DatabaseError> {
                let before = view.tx.select_block_header(view.snapshot.block_num)?.unwrap();
                started_tx.send(()).unwrap();
                resume_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
                let after = view.tx.select_block_header(view.snapshot.block_num)?.unwrap();
                assert_eq!(before, after);
                assert_eq!(view.snapshot.blockchain.chain_tip(), Some(BlockNumber::GENESIS));
                assert_eq!(view.tx.select_block_header(1.into())?, None);
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();
    writer.apply_block(block, None).await.unwrap();
    resume_tx.send(()).unwrap();
    read.await.unwrap().unwrap();
    state
        .read(|view| -> Result<(), DatabaseError> {
            assert_eq!(view.snapshot.block_num, BlockNumber::from(1));
            assert_eq!(
                view.tx.select_block_header(1.into())?.unwrap().block_num(),
                BlockNumber::from(1)
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn caller_error_releases_the_read() {
    let (_directory, state, _writer) = state_with_pool_size(1).await;
    let error = state
        .read(|_| -> Result<(), DatabaseError> {
            Err(DatabaseError::DataCorrupted("caller error".into()))
        })
        .await
        .unwrap_err();
    assert!(matches!(error, DatabaseError::DataCorrupted(message) if message == "caller error"));
    state
        .read(|view| -> Result<(), DatabaseError> {
            assert!(view.tx.select_block_header(view.snapshot.block_num)?.is_some());
            Ok(())
        })
        .await
        .unwrap();
}
