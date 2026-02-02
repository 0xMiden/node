use std::num::NonZeroUsize;
use std::time::Duration;

use miden_node_proto::generated::block_producer::api_client as block_producer_client;
use miden_node_store::{GenesisState, Store};
use miden_node_utils::fee::test_fee_params;
use miden_node_validator::Validator;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::testing::random_signer::RandomBlockSigner as _;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio::{runtime, task};
use tonic::transport::{Channel, Endpoint};
use url::Url;

use crate::{BlockProducer, DEFAULT_MAX_BATCHES_PER_BLOCK, DEFAULT_MAX_TXS_PER_BATCH};

/// Tests that the block producer starts up correctly even when the store is not initially
/// available. The block producer should retry with exponential backoff until the store becomes
/// available, then start serving requests.
#[tokio::test]
async fn block_producer_startup_is_robust_to_network_failures() {
    // get the addresses for the store and block producer
    let store_addr = {
        let store_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("store should bind a port");
        store_listener.local_addr().expect("store should get a local address")
    };
    let block_producer_addr = {
        let block_producer_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("failed to bind block-producer");
        block_producer_listener
            .local_addr()
            .expect("Failed to get block-producer address")
    };

    let validator_addr = {
        let validator_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("failed to bind validator");
        validator_listener.local_addr().expect("failed to get validator address")
    };

    let grpc_timeout = Duration::from_secs(30);

    // start the validator
    task::spawn(async move {
        Validator {
            address: validator_addr,
            grpc_timeout,
            signer: SecretKey::random(),
        }
        .serve()
        .await
        .unwrap();
    });

    // start the block producer BEFORE the store is available
    // this tests the exponential backoff behavior
    let store_url = Url::parse(&format!("http://{store_addr}")).expect("Failed to parse store URL");
    let validator_url =
        Url::parse(&format!("http://{validator_addr}")).expect("Failed to parse validator URL");
    task::spawn(async move {
        BlockProducer {
            block_producer_address: block_producer_addr,
            store_url,
            validator_url,
            batch_prover_url: None,
            batch_interval: Duration::from_millis(500),
            block_interval: Duration::from_millis(500),
            max_txs_per_batch: DEFAULT_MAX_TXS_PER_BATCH,
            max_batches_per_block: DEFAULT_MAX_BATCHES_PER_BLOCK,
            grpc_timeout,
            mempool_tx_capacity: NonZeroUsize::new(100).unwrap(),
        }
        .serve()
        .await
        .unwrap();
    });

    // test: connecting to the block producer should fail because the store is not yet started
    // (and therefore the block producer is not yet listening)
    let block_producer_endpoint =
        Endpoint::try_from(format!("http://{block_producer_addr}")).expect("valid url");
    let block_producer_client =
        block_producer_client::ApiClient::connect(block_producer_endpoint.clone()).await;
    assert!(
        block_producer_client.is_err(),
        "Block producer should not be available before store is started"
    );

    // start the store
    let data_directory = tempfile::tempdir().expect("tempdir should be created");
    let store_runtime = start_store(store_addr, data_directory.path()).await;

    // wait for the block producer's exponential backoff to connect to the store
    // use a retry loop since CI environments may be slower
    let block_producer_client = {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match block_producer_client::ApiClient::connect(block_producer_endpoint.clone()).await {
                Ok(client) => break client,
                Err(_) if attempts < 30 => {
                    sleep(Duration::from_millis(200)).await;
                },
                Err(e) => panic!(
                    "block producer client should connect after store is started (after {attempts} attempts): {e}"
                ),
            }
        }
    };

    // test: status request against block-producer should succeed
    let response = send_status_request(block_producer_client).await;
    assert!(response.is_ok(), "Status request should succeed, got: {:?}", response.err());

    // verify the response contains expected data
    let status = response.unwrap().into_inner();
    assert_eq!(status.status, "connected");

    // Shutdown the store before data_directory is dropped to allow the database to flush properly
    shutdown_store(store_runtime).await;
}

/// Starts the store with a fresh genesis state and returns the runtime handle.
async fn start_store(
    store_addr: std::net::SocketAddr,
    data_directory: &std::path::Path,
) -> runtime::Runtime {
    let genesis_state = GenesisState::new(vec![], test_fee_params(), 1, 1, SecretKey::random());
    Store::bootstrap(genesis_state.clone(), data_directory).expect("store should bootstrap");

    let dir = data_directory.to_path_buf();
    let rpc_listener =
        TcpListener::bind("127.0.0.1:0").await.expect("store should bind the RPC port");
    let ntx_builder_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind store ntx-builder gRPC endpoint");
    let block_producer_listener = TcpListener::bind(store_addr)
        .await
        .expect("store should bind the block-producer port");

    // Use a separate runtime so we can kill all store tasks later
    let store_runtime =
        runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
    store_runtime.spawn(async move {
        Store {
            rpc_listener,
            ntx_builder_listener,
            block_producer_listener,
            block_prover_url: None,
            data_directory: dir,
            grpc_timeout: Duration::from_secs(30),
        }
        .serve()
        .await
        .expect("store should start serving");
    });
    store_runtime
}

/// Shuts down the store runtime properly to allow the database to flush before the temp directory
/// is deleted.
async fn shutdown_store(store_runtime: runtime::Runtime) {
    task::spawn_blocking(move || store_runtime.shutdown_timeout(Duration::from_millis(500)))
        .await
        .expect("shutdown should complete");
}

/// Sends a status request to the block producer to verify connectivity.
async fn send_status_request(
    mut client: block_producer_client::ApiClient<Channel>,
) -> Result<tonic::Response<miden_node_proto::generated::rpc::BlockProducerStatus>, tonic::Status> {
    client.status(()).await
}
