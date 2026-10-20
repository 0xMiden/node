use miden_node_store::{GenesisState, WriterTask};
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::block::ValidatorConfig;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;

use super::*;
use crate::mempool::{Mempool, MempoolConfig};

async fn builder() -> (tempfile::TempDir, BlockBuilder, WriterTask) {
    let directory = tempfile::tempdir().unwrap();
    let key = SigningKey::new();
    let genesis = GenesisState::new(
        Vec::new(),
        test_fee_params(),
        0,
        ValidatorConfig::new(vec![key.public_key()], 1).unwrap(),
        test_protocol_config(),
    )
    .into_block()
    .unwrap();
    State::bootstrap(genesis, directory.path()).await.unwrap();
    let (state, writer, _, task) = State::load(directory.path(), StorageOptions::default())
        .await
        .unwrap()
        .start(CancellationToken::new());
    let validator = BlockProducerValidatorClient::new(
        Vec::new(),
        Duration::from_secs(1),
        miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
    )
    .unwrap();
    let builder = BlockBuilder::new(state, writer, validator, Duration::from_millis(1));
    (directory, builder, task)
}

#[tokio::test(flavor = "multi_thread")]
async fn production_stops_when_mempool_and_store_tips_disagree() {
    let (_directory, builder, writer) = builder().await;
    let mempool = Mempool::shared(BlockNumber::from(1), MempoolConfig::default());

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        builder.run(mempool, CancellationToken::new()),
    )
    .await
    .expect("desynchronization should stop block production")
    .unwrap_err();

    assert!(matches!(
        error.downcast_ref::<BuildBlockError>(),
        Some(BuildBlockError::Desync { local_chain_tip, store_chain_tip })
            if *local_chain_tip == BlockNumber::from(1)
                && *store_chain_tip == BlockNumber::GENESIS
    ));
    writer.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn production_stops_when_mempool_is_poisoned() {
    let (_directory, builder, writer) = builder().await;
    let mempool = Mempool::shared(BlockNumber::GENESIS, MempoolConfig::default());
    let poisoned = mempool.clone();
    let _ = std::thread::spawn(move || {
        let _guard = poisoned.lock().unwrap();
        panic!("poison mempool");
    })
    .join();

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        builder.run(mempool, CancellationToken::new()),
    )
    .await
    .expect("mempool poison should stop block production")
    .unwrap_err();

    assert!(matches!(
        error.downcast_ref::<BuildBlockError>(),
        Some(BuildBlockError::MempoolPoisoned(_))
    ));
    writer.await.unwrap();
}
