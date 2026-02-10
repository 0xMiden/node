use std::net::SocketAddr;
use std::time::Duration;

use http::header::{ACCEPT, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::generated::rpc::api_client::ApiClient as ProtoClient;
use miden_node_proto::generated::{self as proto};
use miden_node_store::Store;
use miden_node_store::genesis::config::GenesisConfig;
use miden_node_utils::fee::test_fee;
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNullifierLimit,
};
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
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{ProvenTransaction, ProvenTransactionBuilder};
use miden_protocol::utils::Serializable;
use miden_protocol::vm::ExecutionProof;
use miden_standards::account::wallets::BasicWallet;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::runtime::{self, Runtime};
use tokio::task;
use url::Url;

use crate::Rpc;

/// Byte offset of the account delta commitment in serialized `ProvenTransaction`.
/// Layout: `AccountId` (15) + `initial_commitment` (32) + `final_commitment` (32) = 79
const DELTA_COMMITMENT_BYTE_OFFSET: usize = 15 + 32 + 32;

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
fn build_test_proven_tx(account: &Account, delta: &AccountDelta) -> ProvenTransaction {
    let account_id = AccountId::dummy(
        [0; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    );

    ProvenTransactionBuilder::new(
        account_id,
        [8; 32].try_into().unwrap(),
        account.commitment(),
        delta.to_commitment(),
        0.into(),
        Word::default(),
        test_fee(),
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .account_update_details(AccountUpdateDetails::Delta(delta.clone()))
    .build()
    .unwrap()
}

#[tokio::test]
async fn rpc_server_accepts_requests_without_accept_header() {
    // Start the RPC.
    let (_, rpc_addr, store_addr) = start_rpc().await;
    let (store_runtime, _data_directory, _genesis) = start_store(store_addr).await;

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

    // Shutdown to avoid runtime drop error.
    shutdown_store(store_runtime).await;
}

#[tokio::test]
async fn rpc_server_accepts_requests_with_accept_header() {
    // Start the RPC.
    let (mut rpc_client, _, store_addr) = start_rpc().await;
    let (store_runtime, _data_directory, _genesis) = start_store(store_addr).await;

    // Send any request to the RPC.
    let response = send_request(&mut rpc_client).await;

    // Assert the server does not reject our request on the basis of missing accept header.
    assert!(response.is_ok());

    // Shutdown to avoid runtime drop error.
    shutdown_store(store_runtime).await;
}

#[tokio::test]
async fn rpc_server_rejects_requests_with_accept_header_invalid_version() {
    for version in ["1.9.0", "0.8.1", "0.8.0", "0.999.0", "99.0.0"] {
        // Start the RPC.
        let (_, rpc_addr, store_addr) = start_rpc().await;
        let (store_runtime, _data_directory, _genesis) = start_store(store_addr).await;

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

        // Shutdown to avoid runtime drop error.
        shutdown_store(store_runtime).await;
    }
}

#[tokio::test]
async fn rpc_startup_is_robust_to_network_failures() {
    // This test starts the store and RPC components and verifies that they successfully
    // connect to each other on startup and that they reconnect after the store is restarted.

    // Start the RPC.
    let (mut rpc_client, _, store_addr) = start_rpc().await;

    // Test: requests against RPC api should fail immediately
    let response = send_request(&mut rpc_client).await;
    assert!(response.is_err());

    // Start the store.
    let (store_runtime, data_directory, _genesis) = start_store(store_addr).await;

    // Test: send request against RPC api and should succeed
    let response = send_request(&mut rpc_client).await;
    assert!(response.unwrap().into_inner().block_header.is_some());

    // Test: shutdown the store and should fail
    shutdown_store(store_runtime).await;
    let response = send_request(&mut rpc_client).await;
    assert!(response.is_err());

    // Test: restart the store and request should succeed
    let store_runtime = restart_store(store_addr, data_directory.path()).await;
    let response = send_request(&mut rpc_client).await;
    assert_eq!(response.unwrap().into_inner().block_header.unwrap().block_num, 0);

    // Shutdown the store before data_directory is dropped to allow RocksDB to flush properly
    shutdown_store(store_runtime).await;
}

#[tokio::test]
async fn rpc_server_has_web_support() {
    // Start server
    let (_, rpc_addr, store_addr) = start_rpc().await;
    let (store_runtime, _data_directory, _genesis) = start_store(store_addr).await;

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
    shutdown_store(store_runtime).await;
}

#[tokio::test]
async fn rpc_server_rejects_proven_transactions_with_invalid_commitment() {
    // Start the RPC.
    let (_, rpc_addr, store_addr) = start_rpc().await;
    let (store_runtime, _data_directory, genesis) = start_store(store_addr).await;

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
    let tx = build_test_proven_tx(&account, &account_delta);

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

    let response = rpc_client.submit_proven_transaction(request).await;

    // Assert that the server rejected our request.
    assert!(response.is_err());

    // Assert that the error is due to the invalid account delta commitment.
    let err = response.as_ref().unwrap_err().message();
    assert!(
        err.contains("failed to validate account delta in transaction account update"),
        "expected error message to contain delta commitment error but got: {err}"
    );

    // Shutdown to avoid runtime drop error.
    shutdown_store(store_runtime).await;
}

#[tokio::test]
async fn rpc_server_rejects_tx_submissions_without_genesis() {
    // Start the RPC.
    let (_, rpc_addr, store_addr) = start_rpc().await;
    let (store_runtime, _data_directory, _genesis) = start_store(store_addr).await;

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
    let tx = build_test_proven_tx(&account, &account_delta);

    let request = proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        transaction_inputs: None,
    };

    let response = rpc_client.submit_proven_transaction(request).await;

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

    // Shutdown to avoid runtime drop error.
    shutdown_store(store_runtime).await;
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

/// Binds a socket on an available port, runs the RPC server on it, and
/// returns a client to talk to the server, along with the socket address.
async fn start_rpc() -> (RpcClient, std::net::SocketAddr, std::net::SocketAddr) {
    let store_addr = {
        let store_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("store should bind a port");
        store_listener.local_addr().expect("store should get a local address")
    };
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
            grpc_timeout: Duration::from_secs(30),
        }
        .serve()
        .await
        .expect("Failed to start serving store");
    });
    let url = rpc_addr.to_string();
    // SAFETY: The rpc_addr is always valid as it is created from a `SocketAddr`.
    let url = Url::parse(format!("http://{}", &url).as_str()).unwrap();
    let rpc_client: RpcClient = Builder::new(url)
        .without_tls()
        .with_timeout(Duration::from_secs(10))
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect::<RpcClient>()
        .await
        .expect("Failed to build client");

    (rpc_client, rpc_addr, store_addr)
}

async fn start_store(store_addr: SocketAddr) -> (Runtime, TempDir, Word) {
    // Start the store.
    let data_directory = tempfile::tempdir().expect("tempdir should be created");

    let config = GenesisConfig::default();
    let signer = SecretKey::new();
    let (genesis_state, _) = config.into_state(signer).unwrap();
    Store::bootstrap(genesis_state.clone(), data_directory.path()).expect("store should bootstrap");
    let dir = data_directory.path().to_path_buf();
    let rpc_listener = TcpListener::bind(store_addr).await.expect("store should bind a port");
    let ntx_builder_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind store ntx-builder gRPC endpoint");
    let block_producer_listener =
        TcpListener::bind("127.0.0.1:0").await.expect("store should bind a port");
    // In order to later kill the store, we need to spawn a new runtime and run the store on
    // it. That allows us to kill all the tasks spawned by the store when we
    // kill the runtime.
    let store_runtime =
        runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
    store_runtime.spawn(async move {
        Store {
            rpc_listener,
            block_prover_url: None,
            ntx_builder_listener,
            block_producer_listener,
            data_directory: dir,
            grpc_timeout: Duration::from_secs(30),
        }
        .serve()
        .await
        .expect("store should start serving");
    });
    (
        store_runtime,
        data_directory,
        genesis_state.into_block().unwrap().inner().header().commitment(),
    )
}

/// Shuts down the store runtime properly to allow `RocksDB` to flush before the temp directory is
/// deleted.
async fn shutdown_store(store_runtime: Runtime) {
    task::spawn_blocking(move || store_runtime.shutdown_timeout(Duration::from_secs(3)))
        .await
        .expect("shutdown should complete");
    // Give RocksDB time to release its lock file after the runtime shutdown
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Restarts a store using an existing data directory. Returns the runtime handle for shutdown.
async fn restart_store(store_addr: SocketAddr, data_directory: &std::path::Path) -> Runtime {
    let rpc_listener = TcpListener::bind(store_addr).await.expect("Failed to bind store");
    let ntx_builder_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind store ntx-builder gRPC endpoint");
    let block_producer_listener =
        TcpListener::bind("127.0.0.1:0").await.expect("store should bind a port");
    let dir = data_directory.to_path_buf();
    let store_runtime =
        runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
    store_runtime.spawn(async move {
        Store {
            rpc_listener,
            block_prover_url: None,
            ntx_builder_listener,
            block_producer_listener,
            data_directory: dir,
            grpc_timeout: Duration::from_secs(10),
        }
        .serve()
        .await
        .expect("store should start serving");
    });
    store_runtime
}

#[tokio::test]
async fn get_limits_endpoint() {
    // Start the RPC and store
    let (mut rpc_client, _rpc_addr, store_addr) = start_rpc().await;
    let (store_runtime, _data_directory, _genesis) = start_store(store_addr).await;

    // Call the get_limits endpoint
    let response = rpc_client.get_limits(()).await.expect("get_limits should succeed");
    let limits = response.into_inner();

    // Verify the response contains expected endpoints and limits
    assert!(!limits.endpoints.is_empty(), "endpoints should not be empty");

    // Verify CheckNullifiers endpoint
    let check_nullifiers =
        limits.endpoints.get("CheckNullifiers").expect("CheckNullifiers should exist");

    assert_eq!(
        check_nullifiers.parameters.get(QueryParamNullifierLimit::PARAM_NAME),
        Some(&(QueryParamNullifierLimit::LIMIT as u32)),
        "CheckNullifiers {} limit should be {}",
        QueryParamNullifierLimit::PARAM_NAME,
        QueryParamNullifierLimit::LIMIT
    );

    let sync_transactions =
        limits.endpoints.get("SyncTransactions").expect("SyncTransactions should exist");
    assert_eq!(
        sync_transactions.parameters.get(QueryParamAccountIdLimit::PARAM_NAME),
        Some(&(QueryParamAccountIdLimit::LIMIT as u32)),
        "SyncTransactions {} limit should be {}",
        QueryParamAccountIdLimit::PARAM_NAME,
        QueryParamAccountIdLimit::LIMIT
    );

    let sync_account_vault =
        limits.endpoints.get("SyncAccountVault").expect("SyncAccountVault should exist");
    assert_eq!(
        sync_account_vault.parameters.get(QueryParamAccountIdLimit::PARAM_NAME),
        Some(&(QueryParamAccountIdLimit::LIMIT as u32)),
        "SyncAccountVault {} limit should be {}",
        QueryParamAccountIdLimit::PARAM_NAME,
        QueryParamAccountIdLimit::LIMIT
    );

    let sync_account_storage_maps = limits
        .endpoints
        .get("SyncAccountStorageMaps")
        .expect("SyncAccountStorageMaps should exist");
    assert_eq!(
        sync_account_storage_maps.parameters.get(QueryParamAccountIdLimit::PARAM_NAME),
        Some(&(QueryParamAccountIdLimit::LIMIT as u32)),
        "SyncAccountStorageMaps {} limit should be {}",
        QueryParamAccountIdLimit::PARAM_NAME,
        QueryParamAccountIdLimit::LIMIT
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

    // Shutdown to avoid runtime drop error.
    shutdown_store(store_runtime).await;
}

#[tokio::test]
async fn sync_chain_mmr_returns_delta() {
    let (mut rpc_client, _rpc_addr, store_addr) = start_rpc().await;
    let (store_runtime, _data_directory, _genesis) = start_store(store_addr).await;

    let request = proto::rpc::SyncChainMmrRequest {
        block_range: Some(proto::rpc::BlockRange { block_from: 0, block_to: None }),
    };
    let response = rpc_client.sync_chain_mmr(request).await.expect("sync_chain_mmr should succeed");
    let response = response.into_inner();

    let pagination_info = response.pagination_info.expect("pagination_info should exist");
    assert_eq!(pagination_info.chain_tip, 0);
    assert_eq!(pagination_info.block_num, 0);

    let mmr_delta = response.mmr_delta.expect("mmr_delta should exist");
    assert_eq!(mmr_delta.forest, 0);
    assert!(mmr_delta.data.is_empty());

    shutdown_store(store_runtime).await;
}
