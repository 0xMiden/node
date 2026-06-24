use std::net::{IpAddr, Ipv4Addr};
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http::header::{ACCEPT, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue};
use miden_node_block_producer::{BlockProducerApi, BlockProducerApiConfig};
use miden_node_proto::clients::{
    Builder,
    GrpcClient,
    Interceptor,
    NtxBuilderClient,
    RpcClient,
    ValidatorClient,
};
use miden_node_proto::generated::rpc::api_client::ApiClient as ProtoClient;
use miden_node_proto::generated::rpc::api_server::Api;
use miden_node_proto::generated::{self as proto};
use miden_node_proto::server::{ntx_builder_api, rpc_api};
use miden_node_store::genesis::config::GenesisConfig;
use miden_node_store::state::State;
use miden_node_utils::clap::{GrpcOptionsExternal, StorageOptions};
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNoteTagLimit,
    QueryParamNullifierPrefixLimit,
};
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountIdVersion,
    AccountPatch,
    AccountType,
    AccountUpdateDetails,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{ProvenTransaction, TxAccountUpdate};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::vm::ExecutionProof;
use miden_standards::account::wallets::BasicWallet;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use url::Url;

use crate::server::api::RpcService;
use crate::{Rpc, RpcMode};

/// Global registry of temp directories. Held for the lifetime of the test binary so that `RocksDB`
/// can always flush on drop regardless of test outcome or drop ordering.
static TEMP_DIRS: std::sync::OnceLock<std::sync::Mutex<Vec<TempDir>>> = std::sync::OnceLock::new();

/// Creates a temp directory, registers it in the global registry, and returns its path.
fn new_tempdir() -> std::path::PathBuf {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let path = dir.path().to_path_buf();
    TEMP_DIRS
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .push(dir);
    path
}

/// A wrapper around the loaded store state and its backing data directory.
struct TestStore {
    state: Arc<State>,
    genesis_commitment: Word,
    data_directory: std::path::PathBuf,
}

impl TestStore {
    fn genesis_commitment(&self) -> Word {
        self.genesis_commitment
    }

    fn data_directory_path(&self) -> &std::path::Path {
        &self.data_directory
    }

    async fn start() -> Self {
        let data_directory = new_tempdir();
        let genesis_commitment = Self::bootstrap(&data_directory);
        let state = load_state(&data_directory).await;
        Self {
            state,
            genesis_commitment,
            data_directory,
        }
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

        State::bootstrap(genesis_block, path).expect("store should bootstrap");

        genesis_commitment
    }
}

async fn load_state(path: &std::path::Path) -> Arc<State> {
    let state = State::load(path, StorageOptions::default()).await.expect("state should load");
    Arc::new(state)
}

/// Byte offset of the account delta commitment in serialized `ProvenTransaction`. Layout:
/// `AccountId` (15) + `initial_commitment` (32) + `final_commitment` (32) = 79
const DELTA_COMMITMENT_BYTE_OFFSET: usize = 15 + 32 + 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Creates a minimal account and its patch for testing proven transaction building.
fn build_test_account(seed: [u8; 32]) -> (Account, AccountPatch) {
    let account = AccountBuilder::new(seed)
        .account_type(AccountType::Public)
        .with_assets(vec![])
        .with_component(BasicWallet)
        .with_auth_component(NoopAuthComponent)
        .build_existing()
        .unwrap();

    let patch = AccountPatch::try_from(account.clone()).unwrap();
    (account, patch)
}

/// Creates a minimal proven transaction for testing.
///
/// This uses `ExecutionProof::new_dummy()` and is intended for tests that
/// need to test validation logic.
fn build_test_proven_tx(
    account: &Account,
    patch: &AccountPatch,
    genesis: Word,
) -> ProvenTransaction {
    let account_id = AccountId::dummy([0; 15], AccountIdVersion::Version1, AccountType::Public);

    let account_update = TxAccountUpdate::new(
        account_id,
        [8; 32].try_into().unwrap(),
        account.to_commitment(),
        patch.to_commitment(),
        AccountUpdateDetails::Public(patch.clone()),
    )
    .unwrap();

    ProvenTransaction::new(
        account_update,
        Vec::<miden_protocol::transaction::InputNoteCommitment>::new(),
        Vec::<miden_protocol::transaction::OutputNote>::new(),
        0.into(),
        genesis,
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
    genesis: Word,
) -> ProvenTransaction {
    let patch = AccountPatch::empty(account_id);
    let account_update = TxAccountUpdate::new(
        account_id,
        [8; 32].try_into().unwrap(),
        account.to_commitment(),
        patch.to_commitment(),
        AccountUpdateDetails::Public(patch),
    )
    .unwrap();

    ProvenTransaction::new(
        account_update,
        Vec::<miden_protocol::transaction::InputNoteCommitment>::new(),
        Vec::<miden_protocol::transaction::OutputNote>::new(),
        0.into(),
        genesis,
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}

fn assert_beyond_tip(status: &tonic::Status, endpoint: &str) {
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "{endpoint} should reject block_to beyond chain tip with InvalidArgument, got: {status:?}"
    );
    assert!(
        status.message().contains("greater than chain tip"),
        "{endpoint} error message should mention the chain tip, got: {}",
        status.message()
    );
}

#[tokio::test]
async fn rpc_server_accepts_requests_without_accept_header() {
    // Start the RPC.
    let (_, rpc_addr, _store) = start_rpc().await;

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
    let (_, rpc_addr, _store) = start_rpc_with_options(grpc_options).await;

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
    let (mut rpc_client, _, _store) = start_rpc().await;

    // Send any request to the RPC.
    let response = send_request(&mut rpc_client).await;

    // Assert the server does not reject our request on the basis of missing accept header.
    assert!(response.is_ok());
}

#[tokio::test]
async fn rpc_server_rejects_requests_with_accept_header_invalid_version() {
    for version in ["1.9.0", "0.8.1", "0.8.0", "0.999.0", "99.0.0"] {
        // Start the RPC.
        let (_, rpc_addr, _store) = start_rpc().await;

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
async fn rpc_uses_in_process_store_state() {
    let (mut rpc_client, _, _store) = start_rpc().await;
    let response = send_request(&mut rpc_client).await;
    assert!(response.unwrap().into_inner().block_header.is_some());
}

#[tokio::test]
async fn rpc_server_has_web_support() {
    // Start server
    let (_, rpc_addr, _store) = start_rpc().await;

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
    let (_, rpc_addr, store) = start_rpc().await;
    let genesis = store.genesis_commitment();

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
    let (account, account_patch) = build_test_account([0; 32]);
    let tx = build_test_proven_tx(&account, &account_patch, genesis);

    // Create an incorrect patch commitment from a different account
    let (other_account, _) = build_test_account([1; 32]);
    let incorrect_patch: AccountPatch = AccountPatch::try_from(other_account).unwrap();
    let incorrect_commitment_bytes = incorrect_patch.to_commitment().as_bytes();

    // Corrupt the transaction bytes with the incorrect patch commitment
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
        err.contains("failed to validate account patch in transaction account update"),
        "expected error message to contain patch commitment error but got: {err}"
    );
}

#[tokio::test]
async fn rpc_server_rejects_proven_transactions_with_invalid_reference_block() {
    // Start the RPC.
    let (_, rpc_addr, store) = start_rpc().await;
    let genesis = store.genesis_commitment();

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
    let (account, account_patch) = build_test_account([0; 32]);
    let tx = build_test_proven_tx(&account, &account_patch, invalid);

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
    let store = TestStore::start().await;
    let genesis = store.genesis_commitment();

    // Seed a row marking a known AccountId as a network account directly in the store's SQLite DB.
    // The store uses WAL mode so a secondary connection is safe.
    let network_account_id =
        AccountId::dummy([7u8; 15], AccountIdVersion::Version1, AccountType::Public);
    miden_node_store::test_support::seed_network_account(
        &store.data_directory_path().join("miden-store.sqlite3"),
        network_account_id,
    );

    // Build a non-deployment tx for that account.
    let (account, _) = build_test_account([0; 32]);
    let tx = build_test_proven_tx_with_id(network_account_id, &account, genesis);
    let request = proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        transaction_inputs: None,
    };

    let service = RpcService::new(
        Arc::clone(&store.state),
        RpcMode::full_node(source_rpc_client(), 100),
        None,
        NonZeroUsize::new(1_000_000).unwrap(),
        None,
    );

    let response = service.submit_proven_tx(Request::new(request)).await;
    assert!(response.is_err());
    let err = response.as_ref().unwrap_err().message();
    assert!(
        err.contains("Network transactions may not be submitted by users yet"),
        "expected the network-tx gate error, got: {err}"
    );
}

fn source_rpc_client() -> RpcClient {
    Builder::new(Url::parse("http://127.0.0.1:0").unwrap())
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<RpcClient>()
}

#[derive(Clone)]
struct FixedNtxBuilder {
    response: proto::rpc::GetNetworkNoteStatusResponse,
    call_count: Arc<AtomicUsize>,
    last_accept: Arc<std::sync::Mutex<Option<String>>>,
}

#[tonic::async_trait]
impl ntx_builder_api::GetNetworkNoteStatus for FixedNtxBuilder {
    type Input = proto::note::NoteId;
    type Output = proto::rpc::GetNetworkNoteStatusResponse;

    fn decode(request: proto::note::NoteId) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::rpc::GetNetworkNoteStatusResponse> {
        Ok(output)
    }

    async fn handle(&self, _input: Self::Input) -> tonic::Result<Self::Output> {
        Ok(self.response.clone())
    }

    async fn full(
        &self,
        request: Request<proto::note::NoteId>,
    ) -> tonic::Result<proto::rpc::GetNetworkNoteStatusResponse> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let accept = request
            .metadata()
            .get(ACCEPT.as_str())
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        *self.last_accept.lock().expect("last_accept mutex should not be poisoned") = accept;
        self.handle(request.into_inner()).await.and_then(Self::encode)
    }
}

async fn start_ntx_builder(
    response: proto::rpc::GetNetworkNoteStatusResponse,
) -> (NtxBuilderClient, Arc<AtomicUsize>, Arc<std::sync::Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind ntx-builder");
    let addr = listener.local_addr().expect("Failed to get ntx-builder address");
    let call_count = Arc::new(AtomicUsize::new(0));
    let last_accept = Arc::new(std::sync::Mutex::new(None));
    let service = FixedNtxBuilder {
        response,
        call_count: Arc::clone(&call_count),
        last_accept: Arc::clone(&last_accept),
    };

    task::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ntx_builder_api::service(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("Failed to serve ntx-builder");
    });

    let client = Builder::new(Url::parse(&format!("http://{addr}")).unwrap())
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<NtxBuilderClient>();

    (client, call_count, last_accept)
}

async fn start_source_rpc(ntx_builder: NtxBuilderClient) -> (RpcClient, TestStore) {
    let store = TestStore::start().await;
    let block_producer_dir = new_tempdir();
    TestStore::bootstrap(&block_producer_dir);
    let block_producer_state = load_state(&block_producer_dir).await;
    let store_state = Arc::clone(&store.state);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind source RPC");
    let addr = listener.local_addr().expect("Failed to get source RPC address");

    task::spawn(async move {
        let validator_url = Url::parse("http://127.0.0.1:0").unwrap();
        let block_producer = BlockProducerApi::new(
            block_producer_state,
            0.into(),
            BlockProducerApiConfig::default(),
        );
        let validator = Builder::new(validator_url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>();
        let source_rpc = RpcService::new(
            store_state,
            RpcMode::sequencer(block_producer, validator),
            Some(ntx_builder),
            NonZeroUsize::new(1_000_000).unwrap(),
            None,
        );

        tonic::transport::Server::builder()
            .add_service(rpc_api::service(source_rpc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("Failed to serve source RPC");
    });

    let client = Builder::new(Url::parse(&format!("http://{addr}")).unwrap())
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<RpcClient>();

    (client, store)
}

#[tokio::test]
async fn full_node_forwards_get_network_note_status_to_source_rpc() {
    let expected = proto::rpc::GetNetworkNoteStatusResponse {
        status: proto::rpc::NetworkNoteStatus::Discarded.into(),
        last_error: Some("execution failed".to_string()),
        attempt_count: 7,
        last_attempt_block_num: Some(42),
    };
    let (ntx_builder, ntx_builder_call_count, _last_accept) =
        start_ntx_builder(expected.clone()).await;
    let (source_rpc, _source_store) = start_source_rpc(ntx_builder).await;
    let local_store = TestStore::start().await;
    let full_node = RpcService::new(
        Arc::clone(&local_store.state),
        RpcMode::full_node(source_rpc, 100),
        None,
        NonZeroUsize::new(1_000).unwrap(),
        None,
    );

    let response = full_node
        .get_network_note_status(Request::new(Word::empty().into()))
        .await
        .expect("full-node RPC should forward network note status request")
        .into_inner();

    assert_eq!(response, expected);
    assert_eq!(ntx_builder_call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn full_node_preserves_original_accept_metadata_when_forwarding() {
    let expected = proto::rpc::GetNetworkNoteStatusResponse {
        status: proto::rpc::NetworkNoteStatus::Discarded.into(),
        last_error: Some("execution failed".to_string()),
        attempt_count: 7,
        last_attempt_block_num: Some(42),
    };
    let (ntx_builder, _ntx_builder_call_count, last_accept) =
        start_ntx_builder(expected.clone()).await;
    let (source_rpc, source_store) = start_source_rpc(ntx_builder).await;
    let local_store = TestStore::start().await;
    let full_node = RpcService::new(
        Arc::clone(&local_store.state),
        RpcMode::full_node(source_rpc, 100),
        None,
        NonZeroUsize::new(1_000).unwrap(),
        None,
    );

    let original_accept = format!(
        "application/vnd.miden; version={}; genesis={}",
        env!("CARGO_PKG_VERSION"),
        source_store.genesis_commitment().to_hex(),
    );
    let mut request = Request::new(Word::empty().into());
    request.metadata_mut().insert(ACCEPT.as_str(), original_accept.parse().unwrap());

    let response = full_node
        .get_network_note_status(request)
        .await
        .expect("full-node RPC should forward network note status request")
        .into_inner();

    assert_eq!(response, expected);
    assert_eq!(
        *last_accept.lock().expect("last_accept mutex should not be poisoned"),
        Some(original_accept),
    );
}

// Batch-path coverage for the network-account gate is provided manually. Building a valid
// `ProposedBatch` + `ProvenBatch` in this test harness would require duplicating LocalBatchProver
// setup. The query layer is covered by the unit test in store::db::tests, and the RPC handler gate
// is covered by `rpc_rejects_post_deployment_network_account_tx`.

#[tokio::test]
async fn rpc_server_rejects_tx_submissions_without_genesis() {
    // Start the RPC.
    let (_, rpc_addr, store) = start_rpc().await;
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

    let (account, account_patch) = build_test_account([0; 32]);
    let tx = build_test_proven_tx(&account, &account_patch, genesis);

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
async fn start_rpc() -> (RpcClient, std::net::SocketAddr, TestStore) {
    start_rpc_with_options(GrpcOptionsExternal::test()).await
}

async fn start_rpc_with_options(
    grpc_options: GrpcOptionsExternal,
) -> (RpcClient, std::net::SocketAddr, TestStore) {
    let store = TestStore::start().await;
    let block_producer_dir = new_tempdir();
    TestStore::bootstrap(&block_producer_dir);
    let block_producer_state = load_state(&block_producer_dir).await;
    let store_state = Arc::clone(&store.state);

    // Start the rpc component.
    let rpc_listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind rpc");
    let rpc_addr = rpc_listener.local_addr().expect("Failed to get rpc address");
    task::spawn(async move {
        // SAFETY: Using dummy validator URL for test - not actually contacted in this test
        let validator_url = Url::parse("http://127.0.0.1:0").unwrap();
        let block_producer = BlockProducerApi::new(
            block_producer_state,
            0.into(),
            BlockProducerApiConfig::default(),
        );
        let validator = Builder::new(validator_url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>();
        Rpc {
            listener: rpc_listener,
            store: store_state,
            mode: RpcMode::sequencer(block_producer, validator),
            ntx_builder: None,
            grpc_options,
            network_tx_auth: None,
        }
        .serve()
        .await
        .expect("Failed to start serving store");
    });
    let url = rpc_addr.to_string();
    // SAFETY: The rpc_addr is always valid as it is created from a `SocketAddr`.
    let url = Url::parse(format!("http://{}", &url).as_str()).unwrap();
    let rpc_client = connect_rpc(url, None).await;

    (rpc_client, rpc_addr, store)
}

#[tokio::test]
async fn get_limits_endpoint() {
    // Start the RPC and store
    let (mut rpc_client, _rpc_addr, _store) = start_rpc().await;

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
    let (mut rpc_client, _rpc_addr, _store) = start_rpc().await;

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

/// All paginated sync endpoints must reject a `block_to` that is greater than the chain tip.
///
/// After bootstrapping, the chain tip is the genesis block (0), so a range ending at block 1 is
/// beyond the tip. The range `0..=1` is otherwise valid (non-empty, start <= end), which isolates
/// the chain-tip check from the range-validity check.
#[tokio::test]
async fn sync_endpoints_reject_block_to_beyond_chain_tip() {
    let (mut rpc_client, _rpc_addr, _store) = start_rpc().await;

    // A range ending one block past the genesis tip; otherwise valid (non-empty, start <= end).
    let block_range = || Some(proto::rpc::BlockRange { block_from: 0, block_to: 1 });
    // Any public account id works: the chain-tip check happens before the account is queried.
    let account_id =
        || Some(AccountId::dummy([0; 15], AccountIdVersion::Version1, AccountType::Public).into());

    let status = rpc_client
        .sync_nullifiers(proto::rpc::SyncNullifiersRequest {
            block_range: block_range(),
            prefix_len: 16,
            nullifiers: vec![],
        })
        .await
        .expect_err("sync_nullifiers should reject block_to beyond chain tip");
    assert_beyond_tip(&status, "sync_nullifiers");

    let status = rpc_client
        .sync_notes(proto::rpc::SyncNotesRequest {
            block_range: block_range(),
            note_tags: vec![],
        })
        .await
        .expect_err("sync_notes should reject block_to beyond chain tip");
    assert_beyond_tip(&status, "sync_notes");

    let status = rpc_client
        .sync_account_storage_maps(proto::rpc::SyncAccountStorageMapsRequest {
            block_range: block_range(),
            account_id: account_id(),
        })
        .await
        .expect_err("sync_account_storage_maps should reject block_to beyond chain tip");
    assert_beyond_tip(&status, "sync_account_storage_maps");

    let status = rpc_client
        .sync_account_vault(proto::rpc::SyncAccountVaultRequest {
            block_range: block_range(),
            account_id: account_id(),
        })
        .await
        .expect_err("sync_account_vault should reject block_to beyond chain tip");
    assert_beyond_tip(&status, "sync_account_vault");

    let status = rpc_client
        .sync_transactions(proto::rpc::SyncTransactionsRequest {
            block_range: block_range(),
            account_ids: vec![],
        })
        .await
        .expect_err("sync_transactions should reject block_to beyond chain tip");
    assert_beyond_tip(&status, "sync_transactions");
}
