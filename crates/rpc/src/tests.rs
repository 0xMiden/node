use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http::header::{ACCEPT, CONTENT_TYPE};
use http::{Extensions, HeaderMap, HeaderValue};
use miden_node_block_producer::store::TransactionInputs;
use miden_node_block_producer::{
    AuthenticatedTransaction,
    BlockProducerApi,
    BlockProducerApiConfig,
};
use miden_node_proto::clients::{
    Builder,
    GrpcClient,
    Interceptor,
    NtxBuilderClient,
    RpcClient,
    SequencerClient,
    ValidatorClient,
};
use miden_node_proto::generated::rpc::api_client::ApiClient as ProtoClient;
use miden_node_proto::generated::rpc::api_server::Api;
use miden_node_proto::generated::sequencer::api_server::Api as SequencerApi;
use miden_node_proto::generated::{self as proto};
use miden_node_proto::server::{ntx_builder_api, rpc_api, validator_api};
use miden_node_store::genesis::config::GenesisConfig;
use miden_node_store::state::State;
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::limiter::{
    QueryParamAccountIdLimit,
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNoteTagLimit,
    QueryParamNullifierPrefixLimit,
    QueryParamStorageMapKeyTotalLimit,
    QueryParamStorageMapSlotLimit,
};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountIdVersion,
    AccountPatch,
    AccountType,
    AccountUpdateDetails,
    AssetCallbackFlag,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{
    OutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TxAccountUpdate,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::vm::ExecutionProof;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::TxFeeNote;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::metadata::MetadataMap;
use url::Url;

use crate::server::RpcBackend;
use crate::server::api::{
    RpcService,
    SequencerInternalService,
    ensure_transactions_have_fee_notes,
};
use crate::{PreAuthSubmission, Rpc, RpcMode, ValidatorClients};

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

struct TestServerGuard(CancellationToken);

impl Drop for TestServerGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
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
        let (state, ..) = State::for_tests(&data_directory).await;
        Self {
            state,
            genesis_commitment,
            data_directory,
        }
    }

    fn bootstrap(path: &std::path::Path) -> Word {
        let config = GenesisConfig::default();
        let validator_key =
            miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey::read_from_bytes(&[7; 32])
                .expect("test signing key should decode")
                .public_key();
        let validator_keys =
            miden_protocol::block::ValidatorKeys::new(vec![validator_key]).unwrap();
        let (genesis_state, _) = config.into_state(validator_keys).unwrap();
        let genesis_block =
            genesis_state.clone().into_block().expect("genesis block should be created");
        let genesis_commitment = genesis_block.inner().header().commitment();

        State::bootstrap(genesis_block, path).expect("store should bootstrap");

        genesis_commitment
    }
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
        .with_component(NoopAuthComponent)
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
    build_test_proven_tx_with_fee(account, patch, genesis, true)
}

/// Creates a minimal proven transaction, optionally including its canonical fee output note.
fn build_test_proven_tx_with_fee(
    account: &Account,
    patch: &AccountPatch,
    genesis: Word,
    include_fee: bool,
) -> ProvenTransaction {
    let account_id = AccountId::dummy(
        [0; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );

    let account_update = TxAccountUpdate::new(
        account_id,
        [8; 32].try_into().unwrap(),
        account.to_commitment(),
        patch.to_commitment(),
        AccountUpdateDetails::Public(patch.clone()),
    )
    .unwrap();

    let output_notes =
        include_fee.then(|| fee_output_note(account_id)).into_iter().collect::<Vec<_>>();

    ProvenTransaction::new(
        account_update,
        Vec::<miden_protocol::transaction::InputNoteCommitment>::new(),
        output_notes,
        0.into(),
        genesis,
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}

fn fee_output_note(sender: AccountId) -> OutputNote {
    let fee_note = TxFeeNote::builder()
        .sender(sender)
        .serial_number(Word::from([1u32, 2, 3, 4]))
        .asset(FungibleAsset::new(FungibleAsset::mock_issuer(), 1).unwrap())
        .build()
        .unwrap()
        .into();
    OutputNote::Public(PublicOutputNote::new(fee_note).unwrap())
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
        [fee_output_note(account_id)],
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
    let (_, rpc_addr, _store, _server) = start_rpc().await;

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
async fn rpc_server_accepts_requests_with_accept_header() {
    // Start the RPC.
    let (mut rpc_client, _, _store, _server) = start_rpc().await;

    // Send any request to the RPC.
    let response = send_request(&mut rpc_client).await;

    // Assert the server does not reject our request on the basis of missing accept header.
    assert!(response.is_ok());
}

#[tokio::test]
async fn rpc_server_rejects_requests_with_accept_header_invalid_version() {
    // Start the RPC.
    let (_, rpc_addr, _store, _server) = start_rpc().await;
    // SAFETY: The rpc_addr is always valid as it is created from a `SocketAddr`.
    let url = Url::parse(format!("http://{rpc_addr}").as_str()).unwrap();

    for version in ["1.9.0", "0.8.1", "0.8.0", "0.999.0", "99.0.0"] {
        // Recreate the RPC client with an invalid version.
        let mut rpc_client: RpcClient = Builder::new(url.clone())
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

        // Assert the server rejects our request on the basis of an unsupported version.
        assert!(response.is_err());
        assert_eq!(response.as_ref().err().unwrap().code(), tonic::Code::InvalidArgument);
        assert!(response.as_ref().err().unwrap().message().contains("server does not support"),);
    }
}

#[tokio::test]
async fn rpc_uses_in_process_store_state() {
    let (mut rpc_client, _, _store, _server) = start_rpc().await;
    let response = send_request(&mut rpc_client).await;
    assert!(response.unwrap().into_inner().block_header.is_some());
}

#[tokio::test]
async fn rpc_server_has_web_support() {
    // Start server
    let (_, rpc_addr, _store, _server) = start_rpc().await;

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
    let (_, rpc_addr, store, _server) = start_rpc().await;
    let genesis = store.genesis_commitment();

    // Override the client so that the ACCEPT header is not set.
    let mut rpc_client =
        miden_node_proto::clients::Builder::new(Url::parse(&format!("http://{rpc_addr}")).unwrap())
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .with_metadata_genesis(genesis)
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
        sealed_transaction_inputs: None,
    };

    let response = rpc_client.submit_proven_tx(request).await;

    // Assert that the server rejected our request.
    assert!(response.is_err());

    // Assert that the error is due to the invalid account delta commitment.
    let err = response.as_ref().unwrap_err().message();
    assert!(
        err.contains("expected account patch commitment"),
        "expected error message to contain patch commitment error but got: {err}"
    );
}

#[tokio::test]
async fn rpc_server_rejects_proven_transactions_without_fees() {
    let store = TestStore::start().await;
    let genesis = store.genesis_commitment();
    let (account, account_patch) = build_test_account([0; 32]);
    let tx = build_test_proven_tx_with_fee(&account, &account_patch, genesis, false);
    let request = proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        sealed_transaction_inputs: None,
    };

    let service = RpcService::new(
        Arc::clone(&store.state),
        RpcBackend::full_node(source_rpc_client(), None),
        None,
        NonZeroUsize::new(1_000_000).unwrap(),
        None,
    );

    let status = service.submit_proven_tx(Request::new(request)).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(status.details(), &[4]);
    assert!(
        status.message().contains("does not contain a canonical TX_FEE output note"),
        "expected the missing-fee error, got: {status}"
    );
}

#[test]
fn rpc_fee_gate_rejects_a_feeless_transaction_in_a_batch() {
    let (account, patch) = build_test_account([0; 32]);
    let paid = build_test_proven_tx_with_fee(&account, &patch, Word::empty(), true);
    let feeless = build_test_proven_tx_with_fee(&account, &patch, Word::empty(), false);

    let status = ensure_transactions_have_fee_notes([&paid, &feeless]).unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(status.details(), &[4]);
    assert!(status.message().contains(&feeless.id().to_string()));
}

#[tokio::test]
async fn sequencer_authenticated_rpc_rejects_transactions_without_fees() {
    let store = TestStore::start().await;
    let genesis = store.genesis_commitment();
    let (account, account_patch) = build_test_account([0; 32]);
    let tx = build_test_proven_tx_with_fee(&account, &account_patch, genesis, false);
    let inputs = TransactionInputs {
        account_id: tx.account_id(),
        account_commitment: Some(tx.account_update().initial_state_commitment()),
        nullifiers: HashMap::default(),
        found_unauthenticated_notes: HashSet::default(),
        current_block_height: 0.into(),
    };
    let tx = AuthenticatedTransaction::new_unchecked(tx.into(), inputs).unwrap();
    let block_producer = BlockProducerApi::new(
        Arc::clone(&store.state),
        store.state.committed_tip(),
        BlockProducerApiConfig::default(),
        CancellationToken::new(),
    );
    let service = SequencerInternalService {
        state: Arc::clone(&store.state),
        block_producer: block_producer.clone(),
    };

    let status = service
        .submit_authenticated_tx(Request::new(proto::sequencer::AuthenticatedTransaction::from(tx)))
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(status.details(), &[4]);
    assert_eq!(block_producer.status().await.mempool_stats.uncommitted_transactions, 0);
}

#[tokio::test]
async fn rpc_server_rejects_proven_transactions_with_invalid_reference_block() {
    // Start the RPC.
    let (_, rpc_addr, store, _server) = start_rpc().await;
    let genesis = store.genesis_commitment();

    // Override the client so that the ACCEPT header is not set.
    let mut rpc_client =
        miden_node_proto::clients::Builder::new(Url::parse(&format!("http://{rpc_addr}")).unwrap())
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .with_metadata_genesis(genesis)
            .without_otel_context_injection()
            .connect_lazy::<miden_node_proto::clients::RpcClient>();

    // Build a valid proven transaction but with the incorrect hash (empty).
    let invalid = Word::empty();
    let (account, account_patch) = build_test_account([0; 32]);
    let tx = build_test_proven_tx(&account, &account_patch, invalid);

    let request = proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        sealed_transaction_inputs: None,
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
    let network_account_id = AccountId::dummy(
        [7u8; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    miden_node_store::test_support::seed_network_account(
        &store.data_directory_path().join("miden-store.sqlite3"),
        network_account_id,
    );

    // Build a non-deployment tx for that account.
    let (account, _) = build_test_account([0; 32]);
    let tx = build_test_proven_tx_with_id(network_account_id, &account, genesis);
    let request = proto::transaction::ProvenTransaction {
        transaction: tx.to_bytes(),
        sealed_transaction_inputs: None,
    };

    let service = RpcService::new(
        Arc::clone(&store.state),
        RpcBackend::full_node(source_rpc_client(), None),
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

    async fn handle(
        &self,
        _input: Self::Input,
        metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let accept = metadata
            .get(ACCEPT.as_str())
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        *self.last_accept.lock().expect("last_accept mutex should not be poisoned") = accept;

        Ok(self.response.clone())
    }
}

async fn start_ntx_builder(
    response: proto::rpc::GetNetworkNoteStatusResponse,
) -> (
    NtxBuilderClient,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Option<String>>>,
    TestServerGuard,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind ntx-builder");
    let addr = listener.local_addr().expect("Failed to get ntx-builder address");
    let call_count = Arc::new(AtomicUsize::new(0));
    let last_accept = Arc::new(std::sync::Mutex::new(None));
    let service = FixedNtxBuilder {
        response,
        call_count: Arc::clone(&call_count),
        last_accept: Arc::clone(&last_accept),
    };

    let shutdown = CancellationToken::new();
    task::spawn({
        let shutdown = shutdown.clone();
        async move {
            tonic::transport::Server::builder()
                .add_service(ntx_builder_api::service(service))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    shutdown.cancelled_owned(),
                )
                .await
                .expect("Failed to serve ntx-builder");
        }
    });

    let client = Builder::new(Url::parse(&format!("http://{addr}")).unwrap())
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<NtxBuilderClient>();

    (client, call_count, last_accept, TestServerGuard(shutdown))
}

fn dummy_client<T: GrpcClient>() -> T {
    Builder::new(Url::parse("http://127.0.0.1:0").unwrap())
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .with_otel_context_injection()
        .connect_lazy::<T>()
}

async fn start_source_rpc(
    ntx_builder: NtxBuilderClient,
    validator: ValidatorClient,
) -> (RpcClient, TestStore, TestServerGuard) {
    let store = TestStore::start().await;
    let block_producer_dir = new_tempdir();
    TestStore::bootstrap(&block_producer_dir);
    let (block_producer_state, ..) = State::for_tests(&block_producer_dir).await;
    let state = Arc::clone(&store.state);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind source RPC");
    let addr = listener.local_addr().expect("Failed to get source RPC address");
    let shutdown = CancellationToken::new();

    task::spawn({
        let shutdown = shutdown.clone();
        async move {
            let block_producer = BlockProducerApi::new(
                block_producer_state,
                0.into(),
                BlockProducerApiConfig::default(),
                shutdown.clone(),
            );
            let source_rpc = RpcService::new(
                state,
                RpcBackend::sequencer(
                    block_producer,
                    ValidatorClients::new(vec![validator]).unwrap(),
                ),
                Some(ntx_builder),
                NonZeroUsize::new(1_000_000).unwrap(),
                None,
            );

            tonic::transport::Server::builder()
                .add_service(rpc_api::service(source_rpc))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    shutdown.cancelled_owned(),
                )
                .await
                .expect("Failed to serve source RPC");
        }
    });

    let client = Builder::new(Url::parse(&format!("http://{addr}")).unwrap())
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<RpcClient>();

    (client, store, TestServerGuard(shutdown))
}

/// Stub validator gRPC service that serves a fixed transaction encryption key and rejects every
/// other RPC.
#[derive(Clone)]
struct FixedValidator {
    encryption_key: proto::transaction::TransactionEncryptionKey,
    call_count: Arc<AtomicUsize>,
    last_accept: Arc<std::sync::Mutex<Option<String>>>,
}

#[tonic::async_trait]
impl validator_api::GetTransactionEncryptionKey for FixedValidator {
    type Input = ();
    type Output = proto::transaction::TransactionEncryptionKey;

    fn decode(request: ()) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::transaction::TransactionEncryptionKey> {
        Ok(output)
    }

    async fn handle(
        &self,
        _input: Self::Input,
        metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let accept = metadata
            .get(ACCEPT.as_str())
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        *self.last_accept.lock().expect("last_accept mutex should not be poisoned") = accept;

        Ok(self.encryption_key.clone())
    }
}

#[tonic::async_trait]
impl validator_api::Status for FixedValidator {
    type Input = ();
    type Output = proto::validator::ValidatorStatus;

    fn decode(request: ()) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::validator::ValidatorStatus> {
        Ok(output)
    }

    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        Err(tonic::Status::unimplemented("not supported by the stub validator"))
    }
}

#[tonic::async_trait]
impl validator_api::SubmitProvenTransaction for FixedValidator {
    type Input = ();
    type Output = ();

    fn decode(_request: proto::transaction::ProvenTransaction) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(output: Self::Output) -> tonic::Result<()> {
        Ok(output)
    }

    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        Err(tonic::Status::unimplemented("not supported by the stub validator"))
    }
}

#[tonic::async_trait]
impl validator_api::SignBlock for FixedValidator {
    type Input = ();
    type Output = proto::blockchain::SignBlockResponse;

    fn decode(_request: proto::blockchain::ProposedBlock) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::blockchain::SignBlockResponse> {
        Ok(output)
    }

    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        Err(tonic::Status::unimplemented("not supported by the stub validator"))
    }
}

#[tonic::async_trait]
impl validator_api::BlockSubscription for FixedValidator {
    type Input = ();
    type Item = proto::validator::BlockSubscriptionResponse;
    type ItemStream = tokio_stream::Empty<tonic::Result<Self::Item>>;

    fn decode(_request: proto::validator::BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::validator::BlockSubscriptionResponse> {
        Ok(item)
    }

    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        Err(tonic::Status::unimplemented("not supported by the stub validator"))
    }
}

/// Serves a [`FixedValidator`] on an ephemeral port and returns a connected client together with
/// the stub's call counter and the last ACCEPT header it observed.
async fn start_validator(
    encryption_key: proto::transaction::TransactionEncryptionKey,
) -> (
    ValidatorClient,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Option<String>>>,
    TestServerGuard,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind validator");
    let addr = listener.local_addr().expect("Failed to get validator address");
    let call_count = Arc::new(AtomicUsize::new(0));
    let last_accept = Arc::new(std::sync::Mutex::new(None));
    let service = FixedValidator {
        encryption_key,
        call_count: Arc::clone(&call_count),
        last_accept: Arc::clone(&last_accept),
    };

    let shutdown = CancellationToken::new();
    task::spawn({
        let shutdown = shutdown.clone();
        async move {
            tonic::transport::Server::builder()
                .add_service(validator_api::service(service))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    shutdown.cancelled_owned(),
                )
                .await
                .expect("Failed to serve validator");
        }
    });

    let client = Builder::new(Url::parse(&format!("http://{addr}")).unwrap())
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<ValidatorClient>();

    (client, call_count, last_accept, TestServerGuard(shutdown))
}

/// A fixed transaction encryption key response for forwarding tests. The values only need to
/// survive the passthrough unchanged.
fn test_encryption_key() -> proto::transaction::TransactionEncryptionKey {
    proto::transaction::TransactionEncryptionKey {
        scheme: proto::transaction::IesScheme::X25519Xchacha20Poly1305 as i32,
        key_id: vec![0xDE, 0xAD, 0xBE, 0xEF],
        public_key: vec![7; 32],
        attestations: vec![proto::transaction::ValidatorKeyAttestation {
            validator_public_key: vec![8; 33],
            signature: vec![9; 65],
        }],
        next_key: Some(proto::transaction::NextTransactionEncryptionKey {
            scheme: proto::transaction::IesScheme::X25519Xchacha20Poly1305 as i32,
            key_id: vec![0xFE, 0xED],
            public_key: vec![6; 32],
            rotation_block_num: 42,
        }),
    }
}

#[tokio::test]
async fn full_node_with_validator_forwards_get_transaction_encryption_key() {
    let expected = test_encryption_key();
    let (validator, validator_call_count, _last_accept, _validator_server) =
        start_validator(expected.clone()).await;
    let local_store = TestStore::start().await;
    let full_node = RpcService::new(
        Arc::clone(&local_store.state),
        RpcBackend::full_node(
            dummy_client::<RpcClient>(),
            Some(
                PreAuthSubmission::new(vec![validator], dummy_client::<SequencerClient>())
                    .expect("one validator is configured"),
            ),
        ),
        None,
        NonZeroUsize::new(1_000).unwrap(),
        None,
    );

    let response = full_node
        .get_transaction_encryption_key(Request::new(()))
        .await
        .expect("full-node RPC should forward the encryption key request to its validator")
        .into_inner();

    assert_eq!(response, expected);
    assert_eq!(validator_call_count.load(Ordering::SeqCst), 1);

    full_node
        .get_transaction_encryption_key(Request::new(()))
        .await
        .expect("each encryption key request should reach the validator");
    assert_eq!(
        validator_call_count.load(Ordering::SeqCst),
        2,
        "the public RPC must not cache transaction encryption keys",
    );
}

#[tokio::test]
async fn full_node_forwards_get_transaction_encryption_key_to_source_rpc() {
    let expected = test_encryption_key();
    let (validator, validator_call_count, _last_accept, _validator_server) =
        start_validator(expected.clone()).await;
    let (source_rpc, _source_store, _source_server) =
        start_source_rpc(dummy_client::<NtxBuilderClient>(), validator).await;
    let local_store = TestStore::start().await;
    let full_node = RpcService::new(
        Arc::clone(&local_store.state),
        RpcBackend::full_node(source_rpc, None),
        None,
        NonZeroUsize::new(1_000).unwrap(),
        None,
    );

    let response = full_node
        .get_transaction_encryption_key(Request::new(()))
        .await
        .expect("full-node RPC should forward the encryption key request to its source")
        .into_inner();

    assert_eq!(response, expected);
    assert_eq!(validator_call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn full_node_preserves_original_accept_metadata_when_forwarding_encryption_key() {
    let expected = test_encryption_key();
    let (validator, _validator_call_count, last_accept, _validator_server) =
        start_validator(expected.clone()).await;
    let (source_rpc, source_store, _source_server) =
        start_source_rpc(dummy_client::<NtxBuilderClient>(), validator).await;
    let local_store = TestStore::start().await;
    let full_node = RpcService::new(
        Arc::clone(&local_store.state),
        RpcBackend::full_node(source_rpc, None),
        None,
        NonZeroUsize::new(1_000).unwrap(),
        None,
    );

    let original_accept = format!(
        "application/vnd.miden; version={}; genesis={}",
        env!("CARGO_PKG_VERSION"),
        source_store.genesis_commitment().to_hex(),
    );
    let mut request = Request::new(());
    request.metadata_mut().insert(ACCEPT.as_str(), original_accept.parse().unwrap());

    let response = full_node
        .get_transaction_encryption_key(request)
        .await
        .expect("full-node RPC should forward the encryption key request")
        .into_inner();

    assert_eq!(response, expected);
    assert_eq!(
        *last_accept.lock().expect("last_accept mutex should not be poisoned"),
        Some(original_accept),
    );
}

#[tokio::test]
async fn full_node_forwards_get_network_note_status_to_source_rpc() {
    let expected = proto::rpc::GetNetworkNoteStatusResponse {
        status: proto::rpc::NetworkNoteStatus::Discarded.into(),
        last_error: Some("execution failed".to_string()),
        attempt_count: 7,
        last_attempt_block_num: Some(42),
    };
    let (ntx_builder, ntx_builder_call_count, _last_accept, _ntx_builder_server) =
        start_ntx_builder(expected.clone()).await;
    let (source_rpc, _source_store, _source_server) =
        start_source_rpc(ntx_builder, dummy_client::<ValidatorClient>()).await;
    let local_store = TestStore::start().await;
    let full_node = RpcService::new(
        Arc::clone(&local_store.state),
        RpcBackend::full_node(source_rpc, None),
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
    let (ntx_builder, _ntx_builder_call_count, last_accept, _ntx_builder_server) =
        start_ntx_builder(expected.clone()).await;
    let (source_rpc, source_store, _source_server) =
        start_source_rpc(ntx_builder, dummy_client::<ValidatorClient>()).await;
    let local_store = TestStore::start().await;
    let full_node = RpcService::new(
        Arc::clone(&local_store.state),
        RpcBackend::full_node(source_rpc, None),
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
    let (_, rpc_addr, store, _server) = start_rpc().await;
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
        sealed_transaction_inputs: None,
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

async fn connect_rpc(url: Url) -> RpcClient {
    let endpoint = tonic::transport::Endpoint::from_shared(url.to_string())
        .expect("Url type always results in valid endpoint")
        .timeout(REQUEST_TIMEOUT);
    let channel = endpoint.connect().await.expect("Failed to build channel");
    let interceptor = Interceptor::default();
    RpcClient::with_interceptor(channel, interceptor)
}

/// Binds a socket on an available port, runs the RPC server on it, and returns a client to talk to
/// the server, along with the socket address.
async fn start_rpc() -> (RpcClient, std::net::SocketAddr, TestStore, TestServerGuard) {
    let grpc_options = GrpcOptions::test();
    let store = TestStore::start().await;
    let block_producer_dir = new_tempdir();
    TestStore::bootstrap(&block_producer_dir);
    let (block_producer_state, ..) = State::for_tests(&block_producer_dir).await;
    let state = Arc::clone(&store.state);

    // Start the rpc component.
    let rpc_listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind rpc");
    let rpc_addr = rpc_listener.local_addr().expect("Failed to get rpc address");
    let shutdown = CancellationToken::new();
    task::spawn({
        let shutdown = shutdown.clone();
        async move {
            // SAFETY: Using dummy validator URL for test - not actually contacted in this test
            let validator_url = Url::parse("http://127.0.0.1:0").unwrap();
            let block_producer = BlockProducerApi::new(
                block_producer_state,
                0.into(),
                BlockProducerApiConfig::default(),
                shutdown.clone(),
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
                state,
                mode: RpcMode::sequencer(
                    block_producer,
                    ValidatorClients::new(vec![validator]).unwrap(),
                ),
                ntx_builder: None,
                grpc_options,
                network_tx_auth: None,
            }
            .serve(shutdown)
            .await
            .expect("Failed to start serving RPC");
        }
    });
    let url = rpc_addr.to_string();
    // SAFETY: The rpc_addr is always valid as it is created from a `SocketAddr`.
    let url = Url::parse(format!("http://{url}").as_str()).unwrap();
    let rpc_client = connect_rpc(url).await;

    (rpc_client, rpc_addr, store, TestServerGuard(shutdown))
}

#[tokio::test]
async fn get_limits_endpoint() {
    // Start the RPC and store
    let (mut rpc_client, _rpc_addr, _store, _server) = start_rpc().await;

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

    // Verify GetAccount endpoint advertises both the per-key and per-slot storage map limits.
    let get_account = limits.endpoints.get("GetAccount").expect("GetAccount should exist");
    assert_eq!(
        get_account.parameters.get(QueryParamStorageMapKeyTotalLimit::PARAM_NAME),
        Some(&(QueryParamStorageMapKeyTotalLimit::LIMIT as u32)),
        "GetAccount {} limit should be {}",
        QueryParamStorageMapKeyTotalLimit::PARAM_NAME,
        QueryParamStorageMapKeyTotalLimit::LIMIT
    );
    assert_eq!(
        get_account.parameters.get(QueryParamStorageMapSlotLimit::PARAM_NAME),
        Some(&(QueryParamStorageMapSlotLimit::LIMIT as u32)),
        "GetAccount {} limit should be {}",
        QueryParamStorageMapSlotLimit::PARAM_NAME,
        QueryParamStorageMapSlotLimit::LIMIT
    );
}

#[tokio::test]
async fn sync_chain_mmr_returns_delta() {
    let (mut rpc_client, _rpc_addr, _store, _server) = start_rpc().await;

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
    let (mut rpc_client, _rpc_addr, _store, _server) = start_rpc().await;

    // A range ending one block past the genesis tip; otherwise valid (non-empty, start <= end).
    let block_range = || Some(proto::rpc::BlockRange { block_from: 0, block_to: 1 });
    // Any public account id works: the chain-tip check happens before the account is queried.
    let account_id = || {
        Some(
            AccountId::dummy(
                [0; 15],
                AccountIdVersion::Version1,
                AccountType::Public,
                AssetCallbackFlag::Disabled,
            )
            .into(),
        )
    };

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
