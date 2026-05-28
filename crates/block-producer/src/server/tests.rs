use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use miden_node_store::state::State;
use miden_node_store::{GenesisState, Store};
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::fee::test_fee_params;
use miden_protocol::block::BlockNumber;
use miden_protocol::testing::random_secret_key::random_secret_key;
use url::Url;

use crate::{BlockProducer, DEFAULT_MAX_BATCHES_PER_BLOCK, DEFAULT_MAX_TXS_PER_BATCH};

#[tokio::test]
async fn block_producer_starts_with_store_state() {
    let data_directory = tempfile::tempdir().expect("tempdir should be created");
    bootstrap_store(data_directory.path());
    let store = load_state(data_directory.path()).await;

    let block_producer = BlockProducer {
        store,
        validator_url: Url::parse("http://127.0.0.1:0").unwrap(),
        batch_prover_url: None,
        batch_interval: Duration::from_secs(3600),
        block_interval: Duration::from_secs(3600),
        max_txs_per_batch: DEFAULT_MAX_TXS_PER_BATCH,
        max_batches_per_block: DEFAULT_MAX_BATCHES_PER_BLOCK,
        mempool_tx_capacity: NonZeroUsize::new(100).unwrap(),
    }
    .start()
    .await
    .unwrap();

    let status = block_producer.api().status().await;
    assert_eq!(status.status, "connected");
    assert_eq!(status.chain_tip, BlockNumber::GENESIS);
}

fn bootstrap_store(path: &std::path::Path) {
    let signer = random_secret_key();
    let genesis_state = GenesisState::new(vec![], test_fee_params(), 1, 1, signer.public_key());
    let genesis_block = genesis_state.into_block(&signer).expect("genesis block should be created");

    Store::bootstrap(genesis_block, path).expect("store should bootstrap");
}

async fn load_state(path: &std::path::Path) -> Arc<State> {
    let (termination_ask, _termination_signal) = tokio::sync::mpsc::channel(1);
    let (state, _) = State::load(path, StorageOptions::default(), termination_ask)
        .await
        .expect("state should load");
    Arc::new(state)
}
