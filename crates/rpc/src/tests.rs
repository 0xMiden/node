use std::collections::{BTreeMap, HashMap, HashSet};
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
use miden_node_proto::server::{ntx_builder_api, rpc_api, sequencer_api, validator_api};
use miden_node_proto::{BuildUnchecked, DecodeMessage, Verify};
use miden_node_store::DataDirectory;
use miden_node_store::allowlist::{AccountAllowlist, InvitationCode, InvitationEntry};
use miden_node_store::genesis::GenesisBlock;
use miden_node_store::genesis::config::GenesisConfig;
use miden_node_store::state::State;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
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
use miden_node_utils::testing::{
    deferred_transaction_fixture,
    proof_with_missing_deferred_witness,
};
use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
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
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::{
    BlockSignatures,
    FeeParameters,
    ProvenBlock,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::note::NoteType;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{
    OutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TxAccountUpdate,
};
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::vm::ExecutionProof;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::TxFeeNote;
use miden_testing::{Auth, MockChainBuilder};
use miden_tx::LocalTransactionProver;
use miden_tx_batch::{BatchExecutor, LocalBatchProver};
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
use crate::{AccountAdmission, PreAuthSubmission, Rpc, RpcMode, ValidatorClients};

mod allowlist;

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
    writer: miden_node_store::state::BlockWriter,
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
    fn bootstrap_allowlist(&self) -> Arc<AccountAllowlist> {
        let path = DataDirectory::load(self.data_directory.clone())
            .unwrap()
            .allowlist_database_path();
        AccountAllowlist::bootstrap(&path).unwrap();
        Arc::new(AccountAllowlist::load(path).unwrap())
    }

    fn genesis_commitment(&self) -> Word {
        self.genesis_commitment
    }

    fn data_directory_path(&self) -> &std::path::Path {
        &self.data_directory
    }

    async fn start() -> Self {
        let data_directory = new_tempdir();
        let genesis_commitment = Self::bootstrap(&data_directory);
        let (state, writer, ..) = State::for_tests(&data_directory).await;
        Self {
            state,
            writer,
            genesis_commitment,
            data_directory,
        }
    }

    async fn start_from_mock_genesis(
        genesis_block: &ProvenBlock,
        protocol_config: &ProtocolConfig,
    ) -> Self {
        let data_directory = new_tempdir();
        let genesis_commitment =
            Self::bootstrap_from_mock_genesis(&data_directory, genesis_block, protocol_config);
        let (state, writer, ..) = State::for_tests(&data_directory).await;
        Self {
            state,
            writer,
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
        let validator_config = ValidatorConfig::new(vec![validator_key], 1).unwrap();
        let (genesis_state, _) = config.into_state(validator_config).unwrap();
        let genesis_block =
            genesis_state.clone().into_block().expect("genesis block should be created");
        let genesis_commitment = genesis_block.inner().header().commitment();

        State::bootstrap(genesis_block, path).expect("store should bootstrap");

        genesis_commitment
    }

    fn bootstrap_from_mock_genesis(
        path: &std::path::Path,
        genesis_block: &ProvenBlock,
        protocol_config: &ProtocolConfig,
    ) -> Word {
        let signatures = BlockSignatures::new(Vec::new()).unwrap();
        let signed_block = SignedBlock::new(
            genesis_block.header().clone(),
            genesis_block.body().clone(),
            signatures,
        )
        .expect("mock genesis header and body should be consistent");
        let genesis_block = GenesisBlock::new(signed_block, protocol_config.clone())
            .expect("mock genesis should become a store genesis block after stripping signatures");
        let genesis_commitment = genesis_block.inner().header().commitment();

        State::bootstrap(genesis_block, path).expect("store should bootstrap from mock genesis");

        genesis_commitment
    }
}

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
/// This uses a dummy execution proof and is intended for tests that
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
        miden_protocol::testing::dummy_execution_proof(),
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
        miden_protocol::testing::dummy_execution_proof(),
    )
    .unwrap()
}

fn replace_transaction_proof(
    transaction: &ProvenTransaction,
    proof: ExecutionProof,
) -> ProvenTransaction {
    ProvenTransaction::new(
        transaction.account_update().clone(),
        transaction.input_notes().iter().cloned(),
        transaction.output_notes().iter().cloned(),
        transaction.ref_block_num(),
        transaction.ref_block_commitment(),
        transaction.expiration_block_num(),
        proof,
    )
    .unwrap()
}

struct ValidBatchFixture {
    request: proto::submission::TransactionBatch,
    genesis_block: ProvenBlock,
    protocol_config: ProtocolConfig,
}

async fn build_valid_batch_fixture() -> ValidBatchFixture {
    let mut mock_chain_builder = MockChainBuilder::new();
    let account = mock_chain_builder
        .add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })
        .unwrap();
    let asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
            .unwrap()
            .into();
    let note = mock_chain_builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[asset],
            NoteType::Private,
        )
        .unwrap();
    let mock_chain = mock_chain_builder.build().unwrap();
    let genesis_block = mock_chain.latest_block();
    let protocol_config = mock_chain.protocol_config().clone();

    let tx_context = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
        .unwrap();
    let executed_tx = Box::pin(tx_context.execute()).await.unwrap();
    let tx_inputs = executed_tx.tx_inputs().clone();
    let proven_tx =
        spawn_blocking_in_current_span(move || LocalTransactionProver::default().prove(tx_inputs))
            .await
            .unwrap()
            .unwrap();

    let proposed_batch = ProposedBatch::new(
        vec![Arc::new(proven_tx)],
        mock_chain.latest_block_header(),
        mock_chain.latest_partial_blockchain(),
        BTreeMap::new(),
        miden_protocol::MIN_PROOF_SECURITY_LEVEL,
    )
    .unwrap();
    let proven_batch = spawn_blocking_in_current_span({
        let proposed_batch = proposed_batch.clone();
        move || {
            let executed_batch = BatchExecutor::new().execute(proposed_batch)?;
            LocalBatchProver::default().prove(executed_batch)
        }
    })
    .await
    .unwrap()
    .unwrap();

    let request = proto::submission::TransactionBatch {
        batch: Some((&proven_batch).into()),
        proposed_batch: Some((&proposed_batch).into()),
        sealed_transaction_inputs: vec![proto::submission::SealedTransactionInputs::default()],
    };

    ValidBatchFixture { request, genesis_block, protocol_config }
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
        include_protocol_config: None,
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
    let incorrect_commitment = incorrect_patch.to_commitment();

    // Corrupt the structured account update with the incorrect patch commitment.
    let mut transaction: proto::transaction::ProvenTransaction = (&tx).into();
    transaction.account_update.as_mut().unwrap().account_patch_commitment =
        Some(incorrect_commitment.into());

    let request = proto::submission::ProvenTransactionSubmission {
        transaction: Some(transaction),
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
    let request = proto::submission::ProvenTransactionSubmission {
        transaction: Some((&tx).into()),
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
        account_admission: AccountAdmission::enabled(store.bootstrap_allowlist()),
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
async fn rpc_server_rejects_invalid_deferred_transaction_proofs() {
    let store = TestStore::start().await;
    let genesis = store.genesis_commitment();
    let (account, account_patch) = build_test_account([0; 32]);
    let transaction = build_test_proven_tx(&account, &account_patch, genesis);
    let transaction = replace_transaction_proof(
        &transaction,
        miden_protocol::testing::dummy_deferred_execution_proof(),
    );
    let request = proto::submission::ProvenTransactionSubmission {
        transaction: Some((&transaction).into()),
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
    assert!(status.message().contains("Invalid proof for transaction"));
}

#[tokio::test]
async fn rpc_server_forwards_valid_deferred_proofs_and_rejects_missing_witnesses() {
    let fixture = deferred_transaction_fixture().await;
    let data_directory = new_tempdir();
    let genesis =
        GenesisBlock::new(fixture.genesis.clone(), fixture.inputs.protocol_config().clone())
            .unwrap();
    State::bootstrap(genesis, &data_directory).unwrap();
    let (state, ..) = State::for_tests(&data_directory).await;
    let submissions = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (validator, _, _, _guard) =
        start_validator(test_encryption_key(), Some(Arc::clone(&submissions))).await;
    let block_producer = BlockProducerApi::new(
        Arc::clone(&state),
        state.committed_tip(),
        BlockProducerApiConfig::default(),
        CancellationToken::new(),
    );
    let allowlist_path =
        DataDirectory::load(data_directory.clone()).unwrap().allowlist_database_path();
    AccountAllowlist::bootstrap(&allowlist_path).unwrap();
    let allowlist = Arc::new(AccountAllowlist::load(allowlist_path).unwrap());
    let service = RpcService::new(
        state,
        RpcBackend::sequencer(
            block_producer,
            ValidatorClients::new(vec![validator]).unwrap(),
            AccountAdmission::enabled(allowlist),
        ),
        None,
        NonZeroUsize::new(1_000_000).unwrap(),
        None,
    );
    let request = proto::submission::ProvenTransactionSubmission {
        transaction: Some((&fixture.transaction).into()),
        sealed_transaction_inputs: None,
    };
    let status = service.submit_proven_tx(Request::new(request)).await.unwrap_err();
    // The stub rejects submissions after it records them.
    assert_eq!(status.code(), tonic::Code::Unimplemented, "{status}");
    {
        let submissions = submissions.lock().unwrap();
        assert_eq!(submissions.len(), 1);
        let forwarded: ProvenTransaction = submissions[0]
            .transaction
            .clone()
            .unwrap()
            .decode_fields()
            .unwrap()
            .build_unchecked()
            .unwrap();
        assert_eq!(forwarded.id(), fixture.transaction.id());
        assert_eq!(forwarded.proof(), fixture.transaction.proof());
    }

    let invalid_tx = replace_transaction_proof(
        &fixture.transaction,
        proof_with_missing_deferred_witness(&fixture.transaction),
    );
    let request = proto::submission::ProvenTransactionSubmission {
        transaction: Some((&invalid_tx).into()),
        sealed_transaction_inputs: None,
    };
    let status = service.submit_proven_tx(Request::new(request)).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("Invalid proof for transaction"), "{status}");
    assert_eq!(submissions.lock().unwrap().len(), 1);
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

    let request = proto::submission::ProvenTransactionSubmission {
        transaction: Some((&tx).into()),
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
    let request = proto::submission::ProvenTransactionSubmission {
        transaction: Some((&tx).into()),
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
    start_source_rpc_with_genesis(ntx_builder, validator, None).await
}

async fn start_source_rpc_with_genesis(
    ntx_builder: NtxBuilderClient,
    validator: ValidatorClient,
    genesis_block: Option<(&ProvenBlock, &ProtocolConfig)>,
) -> (RpcClient, TestStore, TestServerGuard) {
    let store = match genesis_block {
        Some((genesis_block, protocol_config)) => {
            TestStore::start_from_mock_genesis(genesis_block, protocol_config).await
        },
        None => TestStore::start().await,
    };
    let allowlist = store.bootstrap_allowlist();
    let block_producer_dir = new_tempdir();
    match genesis_block {
        Some((genesis_block, protocol_config)) => {
            TestStore::bootstrap_from_mock_genesis(
                &block_producer_dir,
                genesis_block,
                protocol_config,
            );
        },
        None => {
            TestStore::bootstrap(&block_producer_dir);
        },
    }
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
                    AccountAdmission::enabled(allowlist),
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

/// Serves a fixed transaction encryption key and accepts transaction validation requests. If a
/// submission recorder is set, records each submission and rejects it. Rejects all other RPCs.
#[derive(Clone)]
struct FixedValidator {
    encryption_key: proto::submission::TransactionEncryptionKey,
    call_count: Arc<AtomicUsize>,
    last_accept: Arc<std::sync::Mutex<Option<String>>>,
    submissions: Option<Arc<std::sync::Mutex<Vec<proto::submission::ProvenTransactionSubmission>>>>,
}

#[tonic::async_trait]
impl validator_api::GetTransactionEncryptionKey for FixedValidator {
    type Input = ();
    type Output = proto::submission::TransactionEncryptionKey;

    fn decode(request: ()) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::submission::TransactionEncryptionKey> {
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
    type Input = proto::submission::ProvenTransactionSubmission;
    type Output = ();

    fn decode(
        request: proto::submission::ProvenTransactionSubmission,
    ) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<()> {
        Ok(output)
    }

    async fn handle(
        &self,
        input: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        if let Some(submissions) = &self.submissions {
            submissions.lock().unwrap().push(input);
            return Err(tonic::Status::unimplemented("not supported by the stub validator"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl validator_api::SignBlock for FixedValidator {
    type Input = ();
    type Output = proto::validator::SignBlockResponse;

    fn decode(_request: proto::validator::SignBlockRequest) -> tonic::Result<Self::Input> {
        Ok(())
    }

    fn encode(output: Self::Output) -> tonic::Result<proto::validator::SignBlockResponse> {
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
    encryption_key: proto::submission::TransactionEncryptionKey,
    submissions: Option<Arc<std::sync::Mutex<Vec<proto::submission::ProvenTransactionSubmission>>>>,
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
        submissions,
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
fn test_encryption_key() -> proto::submission::TransactionEncryptionKey {
    proto::submission::TransactionEncryptionKey {
        scheme: proto::submission::IesScheme::X25519Xchacha20Poly1305 as i32,
        key_id: vec![0xDE, 0xAD, 0xBE, 0xEF],
        public_key: vec![7; 32],
        attestations: vec![proto::submission::ValidatorKeyAttestation {
            validator_public_key: Some(proto::primitives::PublicKey {
                key: Some(proto::primitives::public_key::Key::EcdsaK256Keccak(vec![8; 33])),
            }),
            signature: Some(proto::primitives::Signature {
                signature: Some(proto::primitives::signature::Signature::EcdsaK256Keccak(vec![
                    9;
                    65
                ])),
            }),
        }],
        next_key: Some(proto::submission::NextTransactionEncryptionKey {
            scheme: proto::submission::IesScheme::X25519Xchacha20Poly1305 as i32,
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
        start_validator(expected.clone(), None).await;
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
        start_validator(expected.clone(), None).await;
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
        start_validator(expected.clone(), None).await;
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

#[tokio::test(flavor = "multi_thread")]
async fn full_node_forwards_complete_transaction_batch_to_source_rpc() {
    let fixture = build_valid_batch_fixture().await;
    let (validator, _validator_call_count, _last_accept, _validator_server) =
        start_validator(test_encryption_key(), None).await;
    let (source_rpc, _source_store, _source_server) = start_source_rpc_with_genesis(
        dummy_client::<NtxBuilderClient>(),
        validator,
        Some((&fixture.genesis_block, &fixture.protocol_config)),
    )
    .await;
    let local_store =
        TestStore::start_from_mock_genesis(&fixture.genesis_block, &fixture.protocol_config).await;
    let full_node = RpcService::new(
        Arc::clone(&local_store.state),
        RpcBackend::full_node(source_rpc, None),
        None,
        NonZeroUsize::new(1_000_000).unwrap(),
        None,
    );

    let response = full_node
        .submit_proven_tx_batch(Request::new(fixture.request))
        .await
        .expect("full-node RPC should forward both structured batch fields to its source")
        .into_inner();

    assert_eq!(response.block_num, 0);
}

#[tokio::test]
async fn authenticated_batch_defers_validation_to_async_handler() {
    let request = proto::sequencer::AuthenticatedTransactionBatch {
        proposed_batch: Some(proto::transaction::ProposedBatch::default()),
        auth_inputs: Vec::new(),
    };
    let input =
        <SequencerInternalService as sequencer_api::SubmitAuthenticatedTxBatch>::decode(request)
            .expect(
                "wire decoding should defer proof-bearing batch conversion to the async handler",
            );

    let store = TestStore::start().await;
    let shutdown = CancellationToken::new();
    let block_producer = BlockProducerApi::new(
        Arc::clone(&store.state),
        0.into(),
        BlockProducerApiConfig::default(),
        shutdown,
    );
    let service = SequencerInternalService {
        state: Arc::clone(&store.state),
        block_producer,
        account_admission: AccountAdmission::enabled(store.bootstrap_allowlist()),
    };
    let error = <SequencerInternalService as sequencer_api::SubmitAuthenticatedTxBatch>::handle(
        &service,
        input,
        &MetadataMap::new(),
        &Extensions::new(),
    )
    .await
    .expect_err("the async handler should reject the malformed proposed batch");

    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("invalid proposed_batch"));
}

// Batch-path coverage for the network-account gate is provided manually. The query layer is covered
// by the unit test in store::db::tests, and the RPC handler gate is covered by
// `rpc_rejects_post_deployment_network_account_tx`.

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

    let request = proto::submission::ProvenTransactionSubmission {
        transaction: Some((&tx).into()),
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
        include_protocol_config: None,
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
    let allowlist = store.bootstrap_allowlist();
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
                    AccountAdmission::enabled(allowlist),
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
async fn register_account_validates_input_and_preserves_registrations() {
    let (mut rpc, addr, store, _server) = start_rpc().await;
    let allowlist = AccountAllowlist::load(
        DataDirectory::load(store.data_directory.clone())
            .unwrap()
            .allowlist_database_path(),
    )
    .unwrap();
    let [account, other] = [[0; 15], [1; 15]].map(|bytes| {
        AccountId::dummy(
            bytes,
            AccountIdVersion::Version1,
            AccountType::Private,
            AssetCallbackFlag::Disabled,
        )
    });
    let request = proto::rpc::RegisterAccountRequest {
        invitation_code: "abc".to_owned(),
        account_id: Some(account.into()),
    };
    assert_eq!(
        rpc.register_account(request.clone()).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    rpc = Builder::new(Url::parse(&format!("http://{addr}")).unwrap())
        .without_tls()
        .with_timeout(REQUEST_TIMEOUT)
        .without_metadata_version()
        .with_metadata_genesis(store.genesis_commitment())
        .without_otel_context_injection()
        .connect_lazy::<RpcClient>();
    for invalid in [
        proto::rpc::RegisterAccountRequest {
            invitation_code: String::new(),
            ..request.clone()
        },
        proto::rpc::RegisterAccountRequest { account_id: None, ..request.clone() },
        proto::rpc::RegisterAccountRequest {
            account_id: Some(proto::account::AccountId::default()),
            ..request.clone()
        },
    ] {
        assert_eq!(
            rpc.register_account(invalid).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
    assert_eq!(
        rpc.register_account(request.clone()).await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    let invitation = InvitationCode::from_hex_digest(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    .unwrap();
    allowlist
        .import_invitation(InvitationEntry {
            invitation_code: invitation.clone(),
            account_id: None,
        })
        .await
        .unwrap();
    let imported = allowlist.invitation_info(invitation.clone()).await.unwrap().unwrap();
    rpc.register_account(request.clone()).await.unwrap();
    rpc.register_account(request.clone()).await.unwrap();
    let conflict = proto::rpc::RegisterAccountRequest {
        account_id: Some(other.into()),
        ..request.clone()
    };
    assert_eq!(
        rpc.register_account(conflict).await.unwrap_err().code(),
        tonic::Code::AlreadyExists
    );
    let registered = allowlist.invitation_info(invitation).await.unwrap().unwrap();
    assert_eq!(registered.account_id, Some(account));
    assert_eq!(registered.allowlisted_at, imported.allowlisted_at);
    assert!(!allowlist.contains_account(other).await.unwrap());

    let unused = InvitationCode::new("unused").unwrap();
    allowlist
        .import_invitation(InvitationEntry {
            invitation_code: unused.clone(),
            account_id: None,
        })
        .await
        .unwrap();
    assert_eq!(
        rpc.register_account(proto::rpc::RegisterAccountRequest {
            invitation_code: "unused".to_owned(),
            ..request
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::AlreadyExists
    );
    assert_eq!(allowlist.invitation_info(unused).await.unwrap().unwrap().account_id, None);
}

#[tokio::test]
async fn register_account_database_failures_include_the_cause() {
    let (mut rpc, _addr, store, _server) = start_rpc().await;
    let path = DataDirectory::load(store.data_directory.clone())
        .unwrap()
        .allowlist_database_path();
    fs_err::remove_file(path).unwrap();

    let account = AccountId::dummy(
        [0; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    );
    let mut request = Request::new(proto::rpc::RegisterAccountRequest {
        invitation_code: "abc".to_owned(),
        account_id: Some(account.into()),
    });
    request.metadata_mut().insert(
        ACCEPT.as_str(),
        format!("application/vnd.miden; genesis={}", store.genesis_commitment())
            .parse()
            .unwrap(),
    );

    let error = rpc.register_account(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert!(error.message().contains("unable to open database file"), "{error}");
}

#[tokio::test]
async fn full_nodes_forward_account_registration_to_the_sequencer() {
    let (source_rpc, _addr, source_store, _server) = start_rpc().await;
    let allowlist = AccountAllowlist::load(
        DataDirectory::load(source_store.data_directory.clone())
            .unwrap()
            .allowlist_database_path(),
    )
    .unwrap();
    let store = TestStore::start().await;
    for (index, pre_auth) in [
        None,
        Some(PreAuthSubmission::new(vec![dummy_client()], dummy_client()).unwrap()),
    ]
    .into_iter()
    .enumerate()
    {
        let account = AccountId::dummy(
            [u8::try_from(index).unwrap(); 15],
            AccountIdVersion::Version1,
            AccountType::Private,
            AssetCallbackFlag::Disabled,
        );
        let code = format!(" invitation-\u{e9}-{index}\n");
        let invitation = InvitationCode::new(&code).unwrap();
        let rpc = RpcService::new(
            Arc::clone(&store.state),
            RpcBackend::full_node(source_rpc.clone(), pre_auth),
            None,
            NonZeroUsize::new(1).unwrap(),
            None,
        );
        let registration = proto::rpc::RegisterAccountRequest {
            invitation_code: code,
            account_id: Some(account.into()),
        };
        let request = || {
            let mut request = Request::new(registration.clone());
            request.metadata_mut().insert(
                ACCEPT.as_str(),
                format!("application/vnd.miden; genesis={}", source_store.genesis_commitment())
                    .parse()
                    .unwrap(),
            );
            request
        };
        assert_eq!(
            rpc.register_account(request()).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        allowlist
            .import_invitation(InvitationEntry {
                invitation_code: invitation.clone(),
                account_id: None,
            })
            .await
            .unwrap();
        rpc.register_account(request()).await.unwrap();
        rpc.register_account(request()).await.unwrap();
        assert_eq!(
            allowlist.invitation_info(invitation).await.unwrap().unwrap().account_id,
            Some(account)
        );
    }
    assert!(
        !DataDirectory::load(store.data_directory.clone())
            .unwrap()
            .allowlist_database_path()
            .exists()
    );
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
    use miden_protocol::block::BlockHeader;
    let (mut rpc_client, _rpc_addr, _store, _server) = start_rpc().await;

    let request = proto::rpc::SyncChainMmrRequest {
        current_client_block_height: 0,
        finality_level: proto::rpc::FinalityLevel::Committed.into(),
    };
    let response = rpc_client.sync_chain_mmr(request).await.expect("sync_chain_mmr should succeed");
    let response = response.into_inner();

    let mmr_delta = response.mmr_delta.expect("mmr_delta should exist");
    assert_eq!(mmr_delta.forest, 0);
    assert!(mmr_delta.update_data.is_empty());
    let config: ProtocolConfig = response
        .protocol_config
        .expect("genesis config")
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap();
    let header: BlockHeader = response
        .block_header
        .unwrap()
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .unwrap();
    assert_eq!(config.to_commitment(), header.protocol_config_commitment());
}

#[tokio::test]
async fn header_protocol_config_is_opt_in() {
    use miden_protocol::block::BlockHeader;
    let (mut client, _, _store, _server) = start_rpc().await;
    for include in [None, Some(false), Some(true)] {
        let response = client
            .get_block_header_by_number(proto::rpc::BlockHeaderByNumberRequest {
                block_num: Some(0),
                include_mmr_proof: Some(true),
                include_protocol_config: include,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.protocol_config.is_some(), include == Some(true));
        assert!(response.mmr_path.is_some());
        if let Some(config) = response.protocol_config {
            let config: ProtocolConfig = config.decode_fields().unwrap().verify().unwrap();
            let header: BlockHeader = response
                .block_header
                .unwrap()
                .decode_fields()
                .unwrap()
                .build_unchecked()
                .unwrap();
            assert_eq!(config.to_commitment(), header.protocol_config_commitment());
        }
    }
    let response = client
        .get_block_header_by_number(proto::rpc::BlockHeaderByNumberRequest {
            block_num: Some(1),
            include_mmr_proof: None,
            include_protocol_config: Some(true),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(response.block_header.is_none());
    assert!(response.protocol_config.is_none());
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
        let header = BlockHeader::mock(i, Some(chain_commitment), None, &[]);
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

/// A nullifier prefix that does not fit in the requested 16-bit prefix length must be rejected with
/// `InvalidArgument`. The store narrows prefixes with `prefix as u16`, so without this check 65536
/// would be truncated to 0 and silently query a different prefix than the client requested.
#[tokio::test]
async fn sync_nullifiers_rejects_prefix_above_u16() {
    let (mut rpc_client, _rpc_addr, _store, _server) = start_rpc().await;

    let status = rpc_client
        .sync_nullifiers(proto::rpc::SyncNullifiersRequest {
            block_range: Some(proto::rpc::BlockRange { block_from: 0, block_to: 0 }),
            prefix_len: 16,
            nullifiers: vec![u32::from(u16::MAX) + 1],
        })
        .await
        .expect_err("sync_nullifiers should reject a prefix that does not fit in 16 bits");

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("does not fit"),
        "error should mention the prefix does not fit, got: {}",
        status.message()
    );
}

#[tokio::test]
async fn block_subscription_starts_with_matching_config() {
    let (mut client, _, _store, _server) = start_rpc().await;
    let mut stream = client
        .block_subscription(proto::rpc::BlockSubscriptionRequest { block_from: 0 })
        .await
        .unwrap()
        .into_inner();
    let event = stream.message().await.unwrap().unwrap();
    let block: SignedBlock =
        event.block.unwrap().decode_fields().unwrap().build_unchecked().unwrap();
    let config: ProtocolConfig = event
        .protocol_config
        .expect("initial config")
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(config.to_commitment(), block.header().protocol_config_commitment());
}

async fn next_block_with_protocol_config(
    store: &TestStore,
    config: &ProtocolConfig,
) -> SignedBlock {
    use miden_protocol::block::{BlockBody, BlockHeader};
    use miden_protocol::crypto::merkle::mmr::Mmr;
    use miden_protocol::transaction::OrderedTransactionHeaders;

    let view = store.state.view();
    let (parent, _) = view.get_block_header(None, false).await.unwrap();
    let parent = parent.unwrap();
    let mut mmr = Mmr::new();
    for height in 0..=parent.block_num().as_u32() {
        let (header, _) = view.get_block_header(Some(height.into()), false).await.unwrap();
        mmr.add(header.unwrap().commitment()).unwrap();
    }
    let body =
        BlockBody::new(vec![], vec![], vec![], OrderedTransactionHeaders::new_unchecked(vec![]))
            .unwrap();

    let header = BlockHeader::new(
        parent.commitment(),
        parent.block_num().child(),
        mmr.peaks().hash_peaks(),
        parent.account_root(),
        parent.nullifier_root(),
        body.compute_block_note_tree().root(),
        body.transaction_commitment(),
        parent.validator_config().clone(),
        parent.fee_parameters().clone(),
        config.to_commitment(),
        None,
        parent.timestamp() + 1,
    );
    SignedBlock::new_unchecked(header, body, BlockSignatures::new(vec![]).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn protocol_config_transitions_follow_response_headers() {
    use miden_node_proto::domain::protocol_config::ensure_protocol_config_is_present_and_matches_header;
    use miden_protocol::block::BlockHeader;
    use miden_protocol::protocol_config::KernelConfig;

    let (mut client, _, mut store, _server) = start_rpc().await;
    let (genesis, _) = store.state.view().get_block_header(Some(0.into()), false).await.unwrap();
    let genesis = genesis.unwrap();
    let a = store
        .state
        .view()
        .get_protocol_config(genesis.protocol_config_commitment())
        .await
        .unwrap()
        .unwrap();
    let b = ProtocolConfig::new(
        a.fee_asset_id(),
        KernelConfig::new(Word::from([42u32, 0, 0, 0]), vec![]).unwrap(),
        a.batch_kernel().clone(),
        a.block_kernel().clone(),
        a.proof_verification().clone(),
    )
    .unwrap();

    for config in [&a, &b, &b, &a] {
        let block = next_block_with_protocol_config(&store, config).await;
        store.writer.apply_block(block, Some(config.clone())).await.unwrap();
    }

    for (height, included) in [(0, true), (1, false), (2, true), (3, true), (4, false)] {
        let response = client
            .sync_chain_mmr(proto::rpc::SyncChainMmrRequest {
                current_client_block_height: height,
                finality_level: proto::rpc::FinalityLevel::Committed.into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.protocol_config.is_some(), included);
        let header: BlockHeader = response
            .block_header
            .unwrap()
            .decode_fields()
            .unwrap()
            .build_unchecked()
            .unwrap();
        assert_eq!(header.block_num(), 4.into());
        if included {
            assert_eq!(
                ensure_protocol_config_is_present_and_matches_header(
                    response.protocol_config,
                    &header
                )
                .unwrap(),
                a
            );
        }
    }

    let proven = client
        .sync_chain_mmr(proto::rpc::SyncChainMmrRequest {
            current_client_block_height: 0,
            finality_level: proto::rpc::FinalityLevel::Proven.into(),
        })
        .await
        .unwrap()
        .into_inner();
    let header: BlockHeader =
        proven.block_header.unwrap().decode_fields().unwrap().build_unchecked().unwrap();
    assert_eq!(header.block_num(), 0.into());
    assert_eq!(
        ensure_protocol_config_is_present_and_matches_header(proven.protocol_config, &header)
            .unwrap(),
        a
    );

    for start in [1, 2] {
        let mut stream = client
            .block_subscription(proto::rpc::BlockSubscriptionRequest { block_from: start })
            .await
            .unwrap()
            .into_inner();
        for height in start..=4 {
            let response = stream.message().await.unwrap().unwrap();
            let block: SignedBlock =
                response.block.unwrap().decode_fields().unwrap().build_unchecked().unwrap();
            assert_eq!(block.header().block_num(), height.into());
            let included = height == start || height == 2 || height == 4;
            assert_eq!(response.protocol_config.is_some(), included);
            if included {
                let expected = if height == 2 || height == 3 { &b } else { &a };
                assert_eq!(
                    &ensure_protocol_config_is_present_and_matches_header(
                        response.protocol_config,
                        block.header()
                    )
                    .unwrap(),
                    expected
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_protocol_config_does_not_advance_store() {
    use miden_protocol::asset::AssetId;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;

    let mut store = TestStore::start().await;
    let (header, _) = store.state.view().get_block_header(None, false).await.unwrap();
    let header = header.unwrap();
    let initial = store
        .state
        .view()
        .get_protocol_config(header.protocol_config_commitment())
        .await
        .unwrap()
        .unwrap();
    let config = ProtocolConfig::current(AssetId::new_fungible(
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
    ))
    .unwrap();
    assert_ne!(config.to_commitment(), initial.to_commitment());

    let block = next_block_with_protocol_config(&store, &config).await;

    // Try applying without a matching protocol config
    assert!(store.writer.apply_block(block.clone(), None).await.is_err());
    assert!(store.writer.apply_block(block.clone(), Some(initial)).await.is_err());
    assert_eq!(store.state.committed_tip(), 0.into());
    assert!(store.state.load_block(1.into()).await.unwrap().is_none());
    assert!(
        store
            .state
            .view()
            .get_protocol_config(config.to_commitment())
            .await
            .unwrap()
            .is_none()
    );

    // Then apply with the matching protocol config
    store.writer.apply_block(block, Some(config.clone())).await.unwrap();
    assert_eq!(store.state.committed_tip(), 1.into());
    assert_eq!(
        store.state.view().get_protocol_config(config.to_commitment()).await.unwrap(),
        Some(config)
    );
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
