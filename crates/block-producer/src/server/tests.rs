use std::num::NonZeroUsize;
use std::time::Duration;

use miden_node_store::{DEFAULT_MAX_CONCURRENT_PROOFS, GenesisState, Store, StoreMode};
use miden_node_utils::clap::{GrpcOptionsInternal, StorageOptions};
use miden_node_utils::fee::test_fee_params;
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_validator::{Validator, ValidatorSigner};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use tokio::{runtime, task};
use url::Url;

use crate::{BlockProducer, DEFAULT_MAX_BATCHES_PER_BLOCK, DEFAULT_MAX_TXS_PER_BATCH};

/// A wrapper around the store runtime and data directory.
///
/// Guarantees that the store runtime is shut down _before_ the data directory is dropped and thus removed.
struct TestStore {
    runtime: Option<runtime::Runtime>,
    _data_directory: tempfile::TempDir,
}

impl Drop for TestStore {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            std::thread::spawn(move || {
                runtime.shutdown_timeout(Duration::from_millis(500));
            })
            .join()
            .expect("store runtime shutdown thread should complete");
        }
    }
}

/// Tests that the block producer starts up correctly even when the store is not initially
/// available. The block producer should retry with exponential backoff until the store becomes
/// available, then start serving requests.
#[tokio::test]
async fn block_producer_startup_is_robust_to_network_failures() {
    // get the addresses for the store and validator
    let store_addr = {
        let store_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("store should bind a port");
        store_listener.local_addr().expect("store should get a local address")
    };

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

    // start the block producer BEFORE the store is available this tests the exponential backoff
    // behavior
    let store_url = Url::parse(&format!("http://{store_addr}")).expect("Failed to parse store URL");
    let validator_url =
        Url::parse(&format!("http://{validator_addr}")).expect("Failed to parse validator URL");
    let block_producer = task::spawn(async move {
        BlockProducer {
            store_url,
            validator_url,
            batch_prover_url: None,
            batch_interval: Duration::from_millis(500),
            block_interval: Duration::from_millis(500),
            max_txs_per_batch: DEFAULT_MAX_TXS_PER_BATCH,
            max_batches_per_block: DEFAULT_MAX_BATCHES_PER_BLOCK,
            mempool_tx_capacity: NonZeroUsize::new(100).unwrap(),
        }
        .start()
        .await
        .unwrap()
    });

    // test: startup should still be waiting because the store is not yet available.
    sleep(Duration::from_millis(100)).await;
    assert!(
        !block_producer.is_finished(),
        "Block producer should wait until the store is started"
    );

    // start the store
    let _store = start_store(store_addr).await;

    let block_producer = timeout(Duration::from_secs(10), block_producer)
        .await
        .expect("block producer should start after store is started")
        .expect("block producer task should not panic");

    // verify the in-process API returns expected status data.
    let status = block_producer.api().status().await;
    assert_eq!(status.status, "connected");
}

/// Starts the store with a fresh genesis state and returns the runtime handle.
async fn start_store(store_addr: std::net::SocketAddr) -> TestStore {
    let data_directory = tempfile::tempdir().expect("tempdir should be created");
    let signer = random_secret_key();
    let genesis_state = GenesisState::new(vec![], test_fee_params(), 1, 1, signer.public_key());
    let genesis_block = genesis_state
        .clone()
        .into_block(&signer)
        .expect("genesis block should be created");
    Store::bootstrap(genesis_block, data_directory.path()).expect("store should bootstrap");

    let dir = data_directory.path().to_path_buf();
    let rpc_listener =
        TcpListener::bind("127.0.0.1:0").await.expect("store should bind the RPC port");
    let block_producer_listener = TcpListener::bind(store_addr)
        .await
        .expect("store should bind the block-producer port");

    // Use a separate runtime so we can kill all store tasks later
    let store_runtime =
        runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
    store_runtime.spawn(async move {
        Store {
            rpc_listener,
            mode: StoreMode::BlockProducer {
                block_producer_listener,
                block_prover_url: None,
                max_concurrent_proofs: DEFAULT_MAX_CONCURRENT_PROOFS,
            },
            data_directory: dir,
            database_options: miden_node_store::DatabaseOptions::default(),
            grpc_options: GrpcOptionsInternal::bench(),
            storage_options: StorageOptions::bench(),
        }
        .serve()
        .await
        .expect("store should start serving");
    });
    TestStore {
        runtime: Some(store_runtime),
        _data_directory: data_directory,
    }
}
