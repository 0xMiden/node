use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use miden_node_store::state::State;
use miden_node_store::{DatabaseOptions, GenesisState, Store};
use miden_node_utils::clap::{GrpcOptionsInternal, StorageOptions};
use miden_node_utils::fee::test_fee_params;
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_validator::{Validator, ValidatorSigner};
use tokio::net::TcpListener;
use tokio::task;
use tokio::time::sleep;
use url::Url;

use crate::{BlockProducer, DEFAULT_MAX_BATCHES_PER_BLOCK, DEFAULT_MAX_TXS_PER_BATCH};

#[tokio::test(flavor = "multi_thread")]
async fn block_producer_starts_with_shared_state() {
    let validator_addr = {
        let validator_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("failed to bind validator");
        validator_listener.local_addr().expect("failed to get validator address")
    };

    let grpc_options = GrpcOptionsInternal::default();

    // start the validator
    task::spawn(async move {
        let temp_dir = tempfile::tempdir().expect("tempdir should be created");
        let data_directory = temp_dir.path().to_path_buf();
        Validator {
            address: validator_addr,
            grpc_options,
            signer: ValidatorSigner::new_local(random_secret_key()),
            data_directory,
            sqlite_connection_pool_size: NonZeroUsize::new(2).unwrap(),
        }
        .serve()
        .await
        .unwrap();
    });

    let data_directory = tempfile::tempdir().expect("tempdir should be created");
    let state = bootstrap_and_load_state(data_directory.path()).await;
    let validator_url =
        Url::parse(&format!("http://{validator_addr}")).expect("Failed to parse validator URL");
    let block_producer = task::spawn(async move {
        BlockProducer {
            state,
            validator_url,
            batch_prover_url: None,
            batch_interval: Duration::from_millis(500),
            block_interval: Duration::from_millis(500),
            max_txs_per_batch: DEFAULT_MAX_TXS_PER_BATCH,
            max_batches_per_block: DEFAULT_MAX_BATCHES_PER_BLOCK,
            mempool_tx_capacity: NonZeroUsize::new(100).unwrap(),
        }
        .serve()
        .await
        .unwrap();
    });

    sleep(Duration::from_secs(2)).await;
    assert!(
        !block_producer.is_finished(),
        "block producer should keep running with shared state"
    );
}

async fn bootstrap_and_load_state(data_directory: &Path) -> Arc<State> {
    let signer = random_secret_key();
    let genesis_state = GenesisState::new(vec![], test_fee_params(), 1, 1, signer.public_key());
    let genesis_block = genesis_state
        .clone()
        .into_block(&signer)
        .expect("genesis block should be created");
    Store::bootstrap(genesis_block, data_directory).expect("store should bootstrap");

    let (termination_ask, _termination_signal) = tokio::sync::mpsc::channel(1);
    let (state, _proven_tip) = State::load_with_database_options(
        data_directory,
        StorageOptions::bench(),
        DatabaseOptions::default(),
        termination_ask,
    )
    .await
    .expect("state should load");

    Arc::new(state)
}
