use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use http::header::{ACCEPT, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue};
use miden_node_proto::clients::{Builder, GrpcClient, Interceptor, RpcClient};
use miden_node_proto::generated::rpc::api_client::ApiClient as ProtoClient;
use miden_node_proto::generated::{self as proto};
use miden_node_store::genesis::config::GenesisConfig;
use miden_node_store::{DEFAULT_MAX_CONCURRENT_PROOFS, Store, StoreMode};
use miden_node_utils::clap::{GrpcOptionsExternal, GrpcOptionsInternal, StorageOptions};
use miden_node_utils::fee::test_fee;
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNoteTagLimit,
    QueryParamNullifierPrefixLimit,
};
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_protocol::Word;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountDelta,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{ProvenTransaction, TxAccountUpdate};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::vm::ExecutionProof;
use miden_standards::account::wallets::BasicWallet;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::runtime::{self, Runtime};
use tokio::task;
use tokio::time::sleep;
use url::Url;

use crate::Rpc;

/// A wrapper around the store runtime and data directory.
///
/// Guarantees that the store runtime is shut down _before_ the data directory is dropped and thus removed.
struct TestStore {
    runtime: Option<Runtime>,
    data_directory: Option<TempDir>,
    genesis_commitment: Word,
    store_addr: SocketAddr,
}

impl TestStore {
    fn genesis_commitment(&self) -> Word {
        self.genesis_commitment
    }

    fn store_addr(&self) -> SocketAddr {
        self.store_addr
    }

    fn data_directory_path(&self) -> &std::path::Path {
        self.data_directory.as_ref().expect("data_directory should be set").path()
    }

    async fn shutdown(mut self) -> TempDir {
        if let Some(runtime) = self.runtime.take() {
            shutdown_store_runtime(runtime).await;
        }
        self.data_directory.take().expect("data_directory should be set")
    }

    async fn start(store_listener: TcpListener) -> Self {
        let data_directory = tempfile::tempdir().expect("tempdir should be created");
        let genesis_commitment = Self::bootstrap(data_directory.path());
        Self::start_without_bootstrap(data_directory, genesis_commitment, store_listener).await
    }

    fn bootstrap(path: &std::path::Path) -> Word {
        let config = GenesisConfig::default();
        let signer = SigningKey::new();
        let (genesis_state, _) = config.into_state(signer.public_key()).unwrap();
        let genesis_block = genesis_state
            .clone()
            .into_block(&signer)
            .expect("genesis block should be created");
        let genesis_commitment = genesis_block.inner().header().commitment();

        Store::bootstrap(genesis_block, path).expect("store should bootstrap");

        genesis_commitment
    }

    async fn start_without_bootstrap(
        data_directory: TempDir,
        genesis_commitment: Word,
        store_listener: TcpListener,
    ) -> Self {
        let dir = data_directory.path().to_path_buf();
        let store_addr =
            store_listener.local_addr().expect("store listener should get a local address");
        let rpc_listener = store_listener;
        let ntx_builder_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind store ntx-builder gRPC endpoint");
        let block_producer_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("store should bind a port");

        // In order to later kill the store, we need to spawn a new runtime and run the store on it.
        // That allows us to kill all the tasks spawned by the store when we kill the runtime.
        let store_runtime =
            runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
        store_runtime.spawn(async move {
            Store {
                rpc_listener,
                mode: StoreMode::BlockProducer {
                    block_producer_listener,
                    ntx_builder_listener,
                    block_prover_url: None,
                    max_concurrent_proofs: DEFAULT_MAX_CONCURRENT_PROOFS,
                },
                data_directory: dir,
                database_options: miden_node_store::DatabaseOptions::default(),
                grpc_options: GrpcOptionsInternal::test(),
                storage_options: StorageOptions::default(),
            }
            .serve()
            .await
            .expect("store should start serving");
        });

        Self {
            runtime: Some(store_runtime),
            data_directory: Some(data_directory),
            genesis_commitment,
            store_addr,
        }
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            shutdown_store_runtime_blocking(runtime);
        }
    }
}

/// Shuts down the store runtime properly to allow `RocksDB` to flush before the temp directory is
/// deleted.
async fn shutdown_store_runtime(store_runtime: Runtime) {
    spawn_blocking_in_current_span(move || shutdown_store_runtime_blocking(store_runtime))
        .await
        .expect("shutdown should complete");
}

fn shutdown_store_runtime_blocking(store_runtime: Runtime) {
    std::thread::spawn(move || {
        store_runtime.shutdown_timeout(Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(200));
    })
    .join()
    .expect("store runtime shutdown thread should complete");
}

/// Byte offset of the account delta commitment in serialized `ProvenTransaction`. Layout:
/// `AccountId` (15) + `initial_commitment` (32) + `final_commitment` (32) = 79
const DELTA_COMMITMENT_BYTE_OFFSET: usize = 15 + 32 + 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Creates a minimal account and its delta for testing proven transaction building.
fn build_test_account(seed: [u8; 32]) -> (Account, AccountDelta) {
    let account = AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(vec![])
        .with_component(BasicWallet)
        .with_auth_component(NoopAuthComponent)
        .build_existing()
        .unwrap();

    let delta: AccountDelta = account.clone().try_into().unwrap();
    (account, delta)
}

/// Creates a minimal proven transaction for testing.
///
/// This uses `ExecutionProof::new_dummy()` and is intended for tests that
/// need to test validation logic.
fn build_test_proven_tx(
    account: &Account,
    delta: &AccountDelta,
    genesis: Word,
) -> ProvenTransaction {
    let account_id = AccountId::dummy(
        [0; 15],
        AccountIdVersion::Version1,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    );

    let account_update = TxAccountUpdate::new(
        account_id,
        [8; 32].try_into().unwrap(),
        account.to_commitment(),
        delta.to_commitment(),
        AccountUpdateDetails::Delta(delta.clone()),
    )
    .unwrap();

    ProvenTransaction::new(
        account_update,
        Vec::<miden_protocol::transaction::InputNoteCommitment>::new(),
        Vec::<miden_protocol::transaction::OutputNote>::new(),
        0.into(),
        genesis,
        test_fee(),
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}

/// Same as `build_test_proven_tx` but lets the caller supply the `AccountId`. Uses a non-empty
/// `initial_state_commitment` so the result is a post-deployment tx.
fn build_test_proven_tx_with_id(
    account_id: AccountId,
    account: &Account,
    delta: &AccountDelta,
    genesis: Word,
) -> ProvenTransaction {
    let account_update = TxAccountUpdate::new(
        account_id,
        [8; 32].try_into().unwrap(),
        account.to_commitment(),
        delta.to_commitment(),
        AccountUpdateDetails::Delta(delta.clone()),
    )
    .unwrap();

    ProvenTransaction::new(
        account_update,
        Vec::<miden_protocol::transaction::InputNoteCommitment>::new(),
        Vec::<miden_protocol::transaction::OutputNote>::new(),
        0.into(),
        genesis,
        test_fee(),
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}

#[tokio::test]
async fn rpc_server_accepts_requests_without_accept_header() {
    // Start the RPC.
    let (_, rpc_addr, store_listener) = start_rpc().await;
    let _store = TestStore::start(store_listener).await;

    // Override the client so that the ACCEPT header is not set.
    let mut rpc_client = {
        let endpoint = tonic::transport::Endpoint::try_from(format!("http://{rpc_addr}")).unwrap();

        ProtoClient::connect(endpoint).await.unwrap()
    };

    // Send any request to the RPC.
    let request = proto::rpc::BlockHeaderByNumberRequest {
        block_num: Some(0),
        include_mmr_proof: None,
    };
    let response = rpc_client.get_block_header_by_number(request).await;

    // Assert that the server did not reject our request.
    assert!(response.is_ok());
}

#[tokio::test]
async fn rpc_rate_limits_per_ip() {
    let grpc_options = GrpcOptionsExternal {
        burst_size: NonZeroU32::new(8).unwrap(),
        replenish_n_per_second_per_ip: NonZeroU64::new(1).unwrap(),
        ..GrpcOptionsExternal::test()
    };
    let (_, rpc_addr, store_listener) = start_rpc_with_options(grpc_options).await;
    let _store = TestStore::start(store_listener).await;

    let url = rpc_addr.to_string();
    let url = Url::parse(format!("http://{}", &url).as_str()).unwrap();
    let mut rpc_client = connect_rpc(url.clone(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST))).await;

    let mut results = Vec::new();
    let mut last_error = None;
    for _ in 0..256 {
        let result = send_request(&mut rpc_client).await;
        if let Err(err) = &result {
            last_error = Some(err.code());
        }
        results.push(result);
    }

    assert!(results.iter().any(std::result::Result::is_ok));
    assert!(
        last_error.is_some_and(|code| code == tonic::Code::ResourceExhausted),
        "expected rate limit error but got: {last_error:?}"
    );
}

#[tokio::test]
async fn rpc_server_accepts_requests_with_accept_header() {
    // Start the RPC.
    let (mut rpc_client, _, store_listener) = start_rpc().await;
    let _store = TestStore::start(store_listener).await;

    // Send any request to the RPC.
    let response = send_request(&mut rpc_client).await;

    // Assert the server does not reject our request on the basis of missing accept header.
    assert!(response.is_ok());
}

#[tokio::test]
async fn rpc_server_rejects_requests_with_accept_header_invalid_version() {
    for version in ["1.9.0", "0.8.1", "0.8.0", "0.999.0", "99.0.0"] {
        // Start the RPC.
        let (_, rpc_addr, store_listener) = start_rpc().await;
        let _store = TestStore::start(store_listener).await;

        // Recreate the RPC client with an invalid version.
        let url = rpc_addr.to_string();
        // SAFETY: The rpc_addr is always valid as it is created from a `SocketAddr`.
        let url = Url::parse(format!("http://{}", &url).as_str()).unwrap();
        let mut rpc_client: RpcClient = Builder::new(url)
            .without_tls()
            .with_timeout(Duration::from_secs(10))
            .with_metadata_version(version.to_string())
            .without_metadata_genesis()
            .without_otel_context_injection()
            .connect::<RpcClient>()
            .await
            .unwrap();

        // Send any request to the RPC.
        let response = send_request(&mut rpc_client).await;

        // Assert the server does not reject our request on the basis of missing accept header.
        assert!(response.is_err());
        assert_eq!(response.as_ref().err().unwrap().code(), tonic::Code::InvalidArgument);
        assert!(response.as_ref().err().unwrap().message().contains("server does not support"),);
    }
}

#[tokio::test]
async fn rpc_startup_is_robust_to_network_failures() {
    // This test starts the store and RPC components and verifies that they successfully connect to
    // each other on startup and that they reconnect after the store is restarted.

    // Start the RPC.
    let (mut rpc_client, _, store_listener) = start_rpc().await;

    // Test: requests against RPC api should fail immediately
    let response = send_request(&mut rpc_client).await;
    assert!(response.is_err());

    // Start the store.
    let store = TestStore::start(store_listener).await;

    // Test: send request against RPC api and should succeed
    let response = send_request_until_success(&mut rpc_client).await;
    assert!(response.unwrap().into_inner().block_header.is_some());

    // Test: shutdown the store and should fail
    let store_addr = store.store_addr();
    let genesis_commitment = store.genesis_commitment();
    let data_directory = store.shutdown().await;
    let response = send_request(&mut rpc_client).await;
    assert!(response.is_err());

    // Test: restart the store and request should succeed
    let store_listener = TcpListener::bind(store_addr).await.expect("Failed to bind store");
    let _store =
        TestStore::start_without_bootstrap(data_directory, genesis_commitment, store_listener)
            .await;
    let response = send_request_until_success(&mut rpc_client).await;
    assert_eq!(response.unwrap().into_inner().block_header.unwrap().block_num, 0);
}

#[tokio::test]
async fn rpc_server_has_web_support() {
    // Start server
    let (_, rpc_addr, store_listener) = start_rpc().await;
    let _store = TestStore::start(store_listener).await;

    // Send a status request
    let client = reqwest::Client::new();

    let mut headers = HeaderMap::new();
    let accept_header = concat!("application/vnd.miden; version=", env!("CARGO_PKG_VERSION"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc-web+proto"));
    headers.insert(ACCEPT, HeaderValue::from_static(accept_header));

    // An empty message with header format:
    //   - A byte indicating uncompressed (0)
    //   - A u32 indicating the data length (0)
    //
    // Originally described here:
    // https://github.com/hyperium/tonic/issues/1040#issuecomment-1191832200
    let mut message = Vec::new();
    message.push(0);
    message.extend_from_slice(&0u32.to_be_bytes());

    let response = client
        .post(format!("http://{rpc_addr}/rpc.Api/Status"))
        .headers(headers)
        .body(message)
        .send()
        .await
        .unwrap();
    let headers = response.headers();

    // CORS headers are usually set when `tonic_web` is enabled.
    //
    // This was deduced by manually checking, and isn't formally described
    // in any documentation.
    assert!(headers.get("access-control-allow-credentials").is_some());
    assert!(headers.get("access-control-expose-headers").is_some());
    assert!(headers.get("vary").is_some());
}

#[tokio::test]
async fn rpc_server_rejects_proven_transactions_with_invalid_commitment() {
    // Start the RPC.
    let (_, rpc_addr, store_listener) = start_rpc().await;
    let store = TestStore::start(store_listener).await;
    let genesis = store.genesis_commitment();

    // Wait for the store to be ready before sending requests.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Override the client so that the ACCEPT header is not set.
    let mut rpc_client =
        miden_node_proto::clients::Builder::new(Url::parse(&format!("http://{rpc_addr}")).unwrap())
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .with_metadata_genesis(genesis.to_hex())
            .without_otel_context_injection()
            .connect_lazy::<miden_node_proto::clients::RpcClient>();

    // Build a valid proven transaction
    let (account, account_delta) = build_test_account([0; 32]);
    let tx = build_test_proven_tx(&account, &account_delta, genesis);

    // Create an incorrect delta commitment from a different account
    let (other_account, _) = build_test_account([1; 32]);
    let incorrect_delta: AccountDelta = other_account.try_into().unwrap();
    let incorrect_commitment_bytes = incorrect_delta.to_commitment().as_bytes();

    // Corrupt the transaction bytes with the incorrect delta commitment
    let mut tx_bytes = tx.to_bytes();
    tx_bytes[DELTA_COMMITMENT_BYTE_OFFSET..DELTA_COMMITMENT_BYTE_OFFSET + 32]
        .copy_from_slice(&incorrect_commitment_bytes);

    let request = proto::transaction::ProvenTransaction {
        transaction: tx_bytes,
        transaction_inputs: None,
    };

    let response = rpc_client.submit_proven_tx(request).await;

    // Assert that the server rejected our request.
    assert!(response.is_err());

    // Assert that the error is due to the invalid account delta commitment.
    let err = response.as_ref().unwrap_err().message();
    assert!(
        err.contains("failed to validate account delta in transaction account update"),
        "expected error message to contain delta commitment error but got: {err}"
    );
}

#[tokio::test]
async fn rpc_server_rejects_proven_transactions_with_invalid_reference_block() {
    // Start the RPC.
    let (_, rpc_addr, store_listener) = start_rpc().await;
    let store = TestStore::start(store_listener).await;
    let genesis = store.genesis_commitment();

    // Wait for the store to be ready before sending requests.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Override the client so that the ACCEPT header is not set.
    let mut rpc_client =
        miden_node_proto::clients::Builder::new(Url::parse(&format!("http://{rpc_addr}")).unwrap())
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .with_metadata_genesis(genesis.to_hex())
            .without_otel_context_injection()
            .connect_lazy::<miden_node_proto::clients::RpcClient>();

    // Build a valid proven transaction but with the incorrect hash (empty).
    let invalid = Word::empty();
    let (account, account_delta) = build_test_account([0; 32]);
    let tx = build_test_proven_tx(&account, &account_delta, invalid);

    let request = proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        transaction_inputs: None,
    };

    let response = rpc_client.submit_proven_tx(request).await;

    // Assert that the server rejected our request.
    assert!(response.is_err());

    // Rejection should be from invalid reference block.
    let err = response.as_ref().unwrap_err().message();
    assert!(
        err.contains("does not match the chain's commitment of"),
        "expected error message to contain reference block error but got: {err}"
    );
}

#[tokio::test]
async fn rpc_rejects_post_deployment_network_account_tx() {
    let (_, rpc_addr, store_listener) = start_rpc().await;
    let store = TestStore::start(store_listener).await;
    let genesis = store.genesis_commitment();

    // Wait for the store to be ready before sending requests.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Build a client that advertises the right `application/vnd.miden` content type so
    // tx-submission requests reach the handler.
    let mut rpc_client =
        miden_node_proto::clients::Builder::new(Url::parse(&format!("http://{rpc_addr}")).unwrap())
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .with_metadata_genesis(genesis.to_hex())
            .without_otel_context_injection()
            .connect_lazy::<miden_node_proto::clients::RpcClient>();

    // Seed a row marking a known AccountId as a network account directly in the store's SQLite DB.
    // The store uses WAL mode so a secondary connection is safe.
    let network_account_id = AccountId::dummy(
        [7u8; 15],
        AccountIdVersion::Version1,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    );
    miden_node_store::test_support::seed_network_account(
        &store.data_directory_path().join("miden-store.sqlite3"),
        network_account_id,
    );

    // Build a non-deployment tx for that account.
    let (account, account_delta) = build_test_account([0; 32]);
    let tx = build_test_proven_tx_with_id(network_account_id, &account, &account_delta, genesis);
    let request = proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        transaction_inputs: None,
    };

    let response = rpc_client.submit_proven_tx(request).await;
    assert!(response.is_err());
    let err = response.as_ref().unwrap_err().message();
    assert!(
        err.contains("Network transactions may not be submitted by users yet"),
        "expected the network-tx gate error, got: {err}"
    );
}

// Batch-path coverage for the network-account gate is provided manually. Building a valid
// `ProposedBatch` + `ProvenBatch` in this test harness would require duplicating LocalBatchProver
// setup. The query layer is covered by the unit test in store::db::tests, and the gRPC wiring is
// the same as `submit_proven_transaction` (covered by
// `rpc_rejects_post_deployment_network_account_tx`).

#[tokio::test]
async fn rpc_server_rejects_tx_submissions_without_genesis() {
    // Start the RPC.
    let (_, rpc_addr, store_listener) = start_rpc().await;
    let store = TestStore::start(store_listener).await;
    let genesis = store.genesis_commitment();

    // Override the client so that the ACCEPT header is not set.
    let mut rpc_client =
        miden_node_proto::clients::Builder::new(Url::parse(&format!("http://{rpc_addr}")).unwrap())
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection()
            .connect_lazy::<miden_node_proto::clients::RpcClient>();

    let (account, account_delta) = build_test_account([0; 32]);
    let tx = build_test_proven_tx(&account, &account_delta, genesis);

    let request = proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        transaction_inputs: None,
    };

    let response = rpc_client.submit_proven_tx(request).await;

    // Assert that the server rejected our request.
    assert!(response.is_err());

    // Assert that the error is due to the invalid account delta commitment.
    let err = response.as_ref().unwrap_err().message();
    assert!(
        err.contains(
            "server does not support any of the specified application/vnd.miden content types"
        ),
        "expected error message to reference incompatible content media types but got: {err:?}"
    );
}

/// Sends an arbitrary / irrelevant request to the RPC.
async fn send_request(
    rpc_client: &mut RpcClient,
) -> std::result::Result<tonic::Response<proto::rpc::BlockHeaderByNumberResponse>, tonic::Status> {
    let request = proto::rpc::BlockHeaderByNumberRequest {
        block_num: Some(0),
        include_mmr_proof: None,
    };
    rpc_client.get_block_header_by_number(request).await
}

async fn send_request_until_success(
    rpc_client: &mut RpcClient,
) -> std::result::Result<tonic::Response<proto::rpc::BlockHeaderByNumberResponse>, tonic::Status> {
    let mut attempts = 0;
    loop {
        attempts += 1;

        match send_request(rpc_client).await {
            Ok(response) => return Ok(response),
            Err(err) if attempts < 30 => {
                sleep(Duration::from_millis(200)).await;
                tracing::warn!(%attempts, %err, "RPC request failed, retrying");
            },
            Err(err) => return Err(err),
        }
    }
}

async fn connect_rpc(url: Url, local_address: Option<IpAddr>) -> RpcClient {
    let mut endpoint = tonic::transport::Endpoint::from_shared(url.to_string())
        .expect("Url type always results in valid endpoint")
        .timeout(REQUEST_TIMEOUT);
    if let Some(local_address) = local_address {
        endpoint = endpoint.local_address(Some(local_address));
    }
    let channel = endpoint.connect().await.expect("Failed to build channel");
    let interceptor = Interceptor::default();
    RpcClient::with_interceptor(channel, interceptor)
}

/// Binds a socket on an available port, runs the RPC server on it, and returns a client to talk to
/// the server, along with the socket address.
async fn start_rpc() -> (RpcClient, std::net::SocketAddr, TcpListener) {
    start_rpc_with_options(GrpcOptionsExternal::test()).await
}

async fn start_rpc_with_options(
    grpc_options: GrpcOptionsExternal,
) -> (RpcClient, std::net::SocketAddr, TcpListener) {
    let store_listener = TcpListener::bind("127.0.0.1:0").await.expect("store should bind a port");
    let store_addr = store_listener.local_addr().expect("store should get a local address");
    let block_producer_addr = {
        let block_producer_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind block-producer");
        block_producer_listener
            .local_addr()
            .expect("Failed to get block-producer address")
    };

    // Start the rpc component.
    let rpc_listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind rpc");
    let rpc_addr = rpc_listener.local_addr().expect("Failed to get rpc address");
    task::spawn(async move {
        // SAFETY: The store_addr is always valid as it is created from a `SocketAddr`.
        let store_url = Url::parse(&format!("http://{store_addr}")).unwrap();
        // SAFETY: The block_producer_addr is always valid as it is created from a `SocketAddr`.
        let block_producer_url = Url::parse(&format!("http://{block_producer_addr}")).unwrap();
        // SAFETY: Using dummy validator URL for test - not actually contacted in this test
        let validator_url = Url::parse("http://127.0.0.1:0").unwrap();
        Rpc {
            listener: rpc_listener,
            store_url,
            block_producer_url: Some(block_producer_url),
            validator_url,
            ntx_builder_url: None,
            grpc_options,
        }
        .serve()
        .await
        .expect("Failed to start serving store");
    });
    let url = rpc_addr.to_string();
    // SAFETY: The rpc_addr is always valid as it is created from a `SocketAddr`.
    let url = Url::parse(format!("http://{}", &url).as_str()).unwrap();
    let rpc_client = connect_rpc(url, None).await;

    (rpc_client, rpc_addr, store_listener)
}

#[tokio::test]
async fn get_limits_endpoint() {
    // Start the RPC and store
    let (mut rpc_client, _rpc_addr, store_listener) = start_rpc().await;
    let _store = TestStore::start(store_listener).await;

    // Call the get_limits endpoint
    let response = rpc_client.get_limits(()).await.expect("get_limits should succeed");
    let limits = response.into_inner();

    // Verify the response contains expected endpoints and limits
    assert!(!limits.endpoints.is_empty(), "endpoints should not be empty");

    let sync_transactions =
        limits.endpoints.get("SyncTransactions").expect("SyncTransactions should exist");
    assert_eq!(
        sync_transactions.parameters.get(QueryParamAccountIdLimit::PARAM_NAME),
        Some(&(QueryParamAccountIdLimit::LIMIT as u32)),
        "SyncTransactions {} limit should be {}",
        QueryParamAccountIdLimit::PARAM_NAME,
        QueryParamAccountIdLimit::LIMIT
    );

    // Verify SyncNullifiers endpoint
    let sync_nullifiers =
        limits.endpoints.get("SyncNullifiers").expect("SyncNullifiers should exist");
    assert_eq!(
        sync_nullifiers.parameters.get(QueryParamNullifierPrefixLimit::PARAM_NAME),
        Some(&(QueryParamNullifierPrefixLimit::LIMIT as u32)),
        "SyncNullifiers {} limit should be {}",
        QueryParamNullifierPrefixLimit::PARAM_NAME,
        QueryParamNullifierPrefixLimit::LIMIT
    );

    // Verify SyncNotes endpoint
    let sync_notes = limits.endpoints.get("SyncNotes").expect("SyncNotes should exist");
    assert_eq!(
        sync_notes.parameters.get(QueryParamNoteTagLimit::PARAM_NAME),
        Some(&(QueryParamNoteTagLimit::LIMIT as u32)),
        "SyncNotes {} limit should be {}",
        QueryParamNoteTagLimit::PARAM_NAME,
        QueryParamNoteTagLimit::LIMIT
    );

    // SyncAccountVault and SyncAccountStorageMaps accept a singular account_id, not a repeated
    // list, so they do not have list parameter limits.
    assert!(
        !limits.endpoints.contains_key("SyncAccountVault"),
        "SyncAccountVault should not have list parameter limits"
    );
    assert!(
        !limits.endpoints.contains_key("SyncAccountStorageMaps"),
        "SyncAccountStorageMaps should not have list parameter limits"
    );

    // Verify GetNotesById endpoint
    let get_notes_by_id = limits.endpoints.get("GetNotesById").expect("GetNotesById should exist");
    assert_eq!(
        get_notes_by_id.parameters.get(QueryParamNoteIdLimit::PARAM_NAME),
        Some(&(QueryParamNoteIdLimit::LIMIT as u32)),
        "GetNotesById {} limit should be {}",
        QueryParamNoteIdLimit::PARAM_NAME,
        QueryParamNoteIdLimit::LIMIT
    );
}

#[tokio::test]
async fn sync_chain_mmr_returns_delta() {
    let (mut rpc_client, _rpc_addr, store_listener) = start_rpc().await;
    let _store = TestStore::start(store_listener).await;

    let request = proto::rpc::SyncChainMmrRequest {
        current_client_block_height: 0,
        finality_level: proto::rpc::FinalityLevel::Committed.into(),
    };
    let response = rpc_client.sync_chain_mmr(request).await.expect("sync_chain_mmr should succeed");
    let response = response.into_inner();

    let mmr_delta = response.mmr_delta.expect("mmr_delta should exist");
    assert_eq!(mmr_delta.forest, 0);
    assert!(mmr_delta.data.is_empty());
}

#[test]
fn sync_chain_mmr_block_header_matches_chain_commitment() {
    use miden_protocol::block::BlockHeader;
    use miden_protocol::crypto::merkle::mmr::{Forest, Mmr, MmrPeaks, PartialMmr};

    // Build 5 blocks, each with chain_commitment = MMR peaks hash before the block was added.
    let mut server_mmr = Mmr::new();
    let mut headers = Vec::new();
    for i in 0..5u32 {
        let chain_commitment = server_mmr.peaks().hash_peaks();
        let header = BlockHeader::mock(i, Some(chain_commitment), None, &[], Word::default());
        server_mmr.add(header.commitment()).unwrap();
        headers.push(header);
    }

    // Client bootstraps with genesis.
    let mut client_mmr =
        PartialMmr::from_peaks(MmrPeaks::new(Forest::new(0).unwrap(), vec![]).unwrap());
    client_mmr.add(headers[0].commitment(), false).unwrap();

    // First delta: block_from=0, block_to=2, so from_forest=1, to_forest=2.
    let delta = server_mmr.get_delta(Forest::new(1).unwrap(), Forest::new(2).unwrap()).unwrap();
    client_mmr.apply(delta).unwrap();
    assert_eq!(client_mmr.peaks().hash_peaks(), headers[2].chain_commitment());
    client_mmr.add(headers[2].commitment(), false).unwrap();

    // Second delta: block_from=2, block_to=4, so from_forest=3, to_forest=4.
    let delta = server_mmr.get_delta(Forest::new(3).unwrap(), Forest::new(4).unwrap()).unwrap();
    client_mmr.apply(delta).unwrap();
    assert_eq!(client_mmr.peaks().hash_peaks(), headers[4].chain_commitment());
    client_mmr.add(headers[4].commitment(), false).unwrap();

    assert_eq!(client_mmr.peaks().hash_peaks(), server_mmr.peaks().hash_peaks());
}
