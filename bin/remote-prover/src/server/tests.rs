use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use miden_node_proto::BlockProofRequest;
use miden_node_proto::generated::remote_prover::api_client::ApiClient;
use miden_node_proto::generated::remote_prover::proof::Proof as ProofVariant;
use miden_node_proto::generated::remote_prover::proof_request::Request;
use miden_node_proto::generated::remote_prover::{Proof, ProofRequest};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::batch::{OrderedBatches, ProposedBatch};
use miden_protocol::block::{BlockHeader, BlockInputs, ProposedBlock};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::{
    ExecutedTransaction,
    PartialBlockchain,
    ProvenTransaction,
    TransactionVerifier,
};
use miden_protocol::vm::ExecutionProof;
use miden_testing::{Auth, MockChainBuilder};
use miden_tx::LocalTransactionProver;
use miden_tx_batch::BatchVerifier;
use serial_test::serial;

use crate::server::Server;
use crate::server::proof_kind::ProofKind;

/// A gRPC client with which to interact with the server.
#[derive(Clone)]
struct Client {
    inner: ApiClient<tonic::transport::Channel>,
}

impl Client {
    async fn connect(port: u16) -> Self {
        let inner = ApiClient::connect(format!("http://127.0.0.1:{port}"))
            .await
            .expect("client should connect");

        Self { inner }
    }

    async fn submit_request(&mut self, request: ProofRequest) -> Result<Proof, tonic::Status> {
        self.inner.prove(request).await.map(tonic::Response::into_inner)
    }
}

trait ProofRequestExt {
    /// Generates a proof request for a transaction using [`MockChain`].
    fn from_tx(tx: &ExecutedTransaction) -> ProofRequest;
    fn from_batch(batch: &ProposedBatch) -> ProofRequest;
    fn for_empty_block() -> ProofRequest;
    async fn mock_tx() -> ExecutedTransaction;
    async fn mock_batch() -> ProposedBatch;
}

impl ProofRequestExt for ProofRequest {
    fn from_tx(tx: &ExecutedTransaction) -> ProofRequest {
        let tx_inputs = tx.tx_inputs().clone();

        ProofRequest {
            request: Some(Request::Transaction(tx_inputs.into())),
        }
    }

    fn from_batch(batch: &ProposedBatch) -> ProofRequest {
        ProofRequest {
            request: Some(Request::Batch(batch.into())),
        }
    }

    fn for_empty_block() -> ProofRequest {
        let partial_blockchain = PartialBlockchain::default();
        let block_inputs = BlockInputs::new(
            BlockHeader::mock(0, Some(partial_blockchain.peaks().hash_peaks()), None, &[]),
            partial_blockchain,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let proposed_block = ProposedBlock::new_at(
            block_inputs.clone(),
            Vec::new(),
            block_inputs.prev_block_header().timestamp() + 1,
        )
        .unwrap();
        let (block_header, _) = proposed_block.into_header_and_body().unwrap();
        let request = BlockProofRequest {
            tx_batches: OrderedBatches::new(Vec::new()),
            block_header,
            block_inputs,
        };

        ProofRequest {
            request: Some(Request::Block(request.into())),
        }
    }

    async fn mock_tx() -> ExecutedTransaction {
        // Create a mock transaction to send to the server
        let mut mock_chain_builder = MockChainBuilder::new();
        let account = mock_chain_builder
            .add_existing_wallet(Auth::BasicAuth {
                auth_scheme: AuthScheme::Falcon512Poseidon2,
            })
            .unwrap();

        let fungible_asset_1: Asset =
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
                .unwrap()
                .into();
        let note_1 = mock_chain_builder
            .add_p2id_note(
                ACCOUNT_ID_SENDER.try_into().unwrap(),
                account.id(),
                &[fungible_asset_1],
                NoteType::Private,
            )
            .unwrap();

        let mock_chain = mock_chain_builder.build().unwrap();

        let tx_context = mock_chain
            .build_transaction(account.id())
            .authenticated_input_note(note_1.id())
            .build()
            .unwrap();

        Box::pin(tx_context.execute()).await.unwrap()
    }

    async fn mock_batch() -> ProposedBatch {
        // Create a mock transaction to send to the server
        let mut mock_chain_builder = MockChainBuilder::new();
        let account = mock_chain_builder
            .add_existing_wallet(Auth::BasicAuth {
                auth_scheme: AuthScheme::Falcon512Poseidon2,
            })
            .unwrap();

        let fungible_asset_1: Asset =
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
                .unwrap()
                .into();
        let note_1 = mock_chain_builder
            .add_p2id_note(
                ACCOUNT_ID_SENDER.try_into().unwrap(),
                account.id(),
                &[fungible_asset_1],
                NoteType::Private,
            )
            .unwrap();

        let mock_chain = mock_chain_builder.build().unwrap();

        let tx = mock_chain
            .build_transaction(account.id())
            .authenticated_input_note(note_1.id())
            .build()
            .unwrap();

        let tx = Box::pin(tx.execute()).await.unwrap();
        let tx = LocalTransactionProver::default().prove(tx.tx_inputs().clone()).unwrap();

        ProposedBatch::new(
            vec![Arc::new(tx)],
            mock_chain.latest_block_header(),
            mock_chain.latest_partial_blockchain(),
            BTreeMap::new(),
            MIN_PROOF_SECURITY_LEVEL,
        )
        .unwrap()
    }
}

// Test helpers for the server.
//
// Note: This is implemented under `#[cfg(test)]`.
impl Server {
    /// A server configured with an arbitrary port (i.e. `port=0`) and the given kind.
    ///
    /// Capacity is set to 10 with a timeout of 60 seconds.
    fn with_arbitrary_port(kind: ProofKind) -> Self {
        Self {
            port: 0,
            kind,
            timeout: Duration::from_mins(1),
            capacity: NonZeroUsize::new(10).unwrap(),
        }
    }

    /// Overrides the capacity of the server.
    ///
    /// # Panics
    ///
    /// Panics if the given capacity is zero.
    fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = NonZeroUsize::new(capacity).unwrap();
        self
    }

    /// Overrides the timeout of the server.
    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Verifies that a capacity of one permits only one concurrent proof request.
///
/// Creates a server with a capacity of one and submits two requests. One request must succeed. The
/// server must reject the other request with a resource exhaustion error.
#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn legacy_behaviour_with_capacity_1() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .with_capacity(1)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let request = ProofRequest::from_tx(&ProofRequest::mock_tx().await);

    let mut client_a = Client::connect(port).await;
    let mut client_b = client_a.clone();

    let a = client_a.submit_request(request.clone());
    let b = client_b.submit_request(request);

    let (first, second) = tokio::join!(a, b);

    // We cannot know which got served and which got rejected. We can only assert that one of them
    // is Ok and the other is Err.
    assert!(first.is_ok() || second.is_ok());
    assert!(first.is_err() || second.is_err());
    // We also expect that the error is a resource exhaustion error.
    let err = first.err().or(second.err()).unwrap();
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    server.abort();
}

/// Test that multiple requests can be queued and capacity is respected.
///
/// Create a server with a capacity of two and submit three requests. Ensure
/// that two succeed and one fails with a resource exhaustion error.
#[ignore = "Proving 3 requests concurrently causes temporary CI resource starvation which results in _sporadic_ timeouts"]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn capacity_is_respected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .with_capacity(2)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let request = ProofRequest::from_tx(&ProofRequest::mock_tx().await);
    let mut client_a = Client::connect(port).await;
    let mut client_b = client_a.clone();
    let mut client_c = client_a.clone();

    let a = client_a.submit_request(request.clone());
    let b = client_b.submit_request(request.clone());
    let c = client_c.submit_request(request);

    let (first, second, third) = tokio::join!(a, b, c);

    // We cannot know which got served and which got rejected. We can only assert that two succeeded
    // and one failed.
    let mut expected = [true, true, false];
    let mut result = [first.is_ok(), second.is_ok(), third.is_ok()];
    expected.sort_unstable();
    result.sort_unstable();
    assert_eq!(expected, result);

    assert_matches!(first.err().or(second.err()).or(third.err()), Some(err) => {
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    });

    server.abort();
}

/// Ensures that the server request timeout is adhered to.
///
/// A blocking proof task cannot stop after proving starts. A queued request can expire. The test
/// uses a ten-nanosecond timeout so at least one request expires.
#[tokio::test(flavor = "multi_thread")]
async fn timeout_is_respected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .with_timeout(Duration::from_nanos(10))
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let request = ProofRequest::from_tx(&ProofRequest::mock_tx().await);

    let mut client_a = Client::connect(port).await;
    let mut client_b = Client::connect(port).await;

    let a = client_a.submit_request(request.clone());
    let b = client_b.submit_request(request);

    let (a, b) = tokio::join!(a, b);

    // At least one of the requests should timeout.
    let err = a.err().or(b.err()).unwrap();

    assert_eq!(err.code(), tonic::Code::Cancelled);
    assert!(err.message().contains("Timeout expired"));

    server.abort();
}

/// Ensures that the server rejects a request with no oneof variant.
///
/// The test checks the status code and message because the status code covers multiple errors.
#[tokio::test(flavor = "multi_thread")]
async fn missing_request_variant_is_rejected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let mut client = Client::connect(port).await;
    let response = client.submit_request(ProofRequest { request: None }).await;
    let err = response.unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("missing proof request"));

    server.abort();
}

/// Ensures that malformed canonical transaction inputs are rejected as client input.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_transaction_inputs_are_rejected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let request = ProofRequest {
        request: Some(Request::Transaction(
            miden_node_proto::generated::transaction::TransactionInputs::default(),
        )),
    };
    let mut client = Client::connect(port).await;
    let err = client.submit_request(request).await.unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("transaction inputs"));

    server.abort();
}

/// Ensures that malformed canonical batch inputs are rejected as client input.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_batch_inputs_are_rejected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Batch)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let request = ProofRequest {
        request: Some(Request::Batch(
            miden_node_proto::generated::transaction::ProposedBatch::default(),
        )),
    };
    let mut client = Client::connect(port).await;
    let err = client.submit_request(request).await.unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("proposed batch"));

    server.abort();
}

/// Ensures that malformed canonical block inputs are rejected as client input.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_block_inputs_are_rejected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Block)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let request = ProofRequest {
        request: Some(Request::Block(
            miden_node_proto::generated::block_proving::BlockProofRequest::default(),
        )),
    };
    let mut client = Client::connect(port).await;
    let err = client.submit_request(request).await.unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("block proving inputs"));

    server.abort();
}

/// Ensures that a valid but unsupported proof kind is rejected.
///
/// Submits a transaction proof request to a batch proving server. Checks the status code and
/// message because the status code covers multiple validation errors.
#[tokio::test(flavor = "multi_thread")]
async fn unsupported_proof_kind_is_rejected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Batch)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let request = ProofRequest::from_tx(&ProofRequest::mock_tx().await);

    let mut client = Client::connect(port).await;
    let response = client.submit_request(request).await;
    let err = response.unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("unsupported proof type"));

    server.abort();
}

/// Checks that the a transaction request results in a correct proof.
///
/// The proof is verified and the transaction IDs of request and response must correspond.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn transaction_proof_is_correct() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let tx = ProofRequest::mock_tx().await;
    let request = ProofRequest::from_tx(&tx);

    let mut client = Client::connect(port).await;
    let response = client.submit_request(request).await.unwrap();
    let response = match response.proof.unwrap() {
        ProofVariant::Transaction(transaction) => ProvenTransaction::try_from(transaction).unwrap(),
        other => panic!("expected transaction proof response, got {other:?}"),
    };

    assert_eq!(response.id(), tx.id());
    TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&response).unwrap();

    server.abort();
}

/// Checks that the a batch request results in a correct proof.
///
/// The proof is verified locally, which ensures that the gRPC codec and server code do the
/// correct thing.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn batch_proof_is_correct() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Batch)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let batch = ProofRequest::mock_batch().await;
    let request = ProofRequest::from_batch(&batch);

    let mut client = Client::connect(port).await;
    let response = client.submit_request(request).await.unwrap();
    let response = match response.proof.unwrap() {
        ProofVariant::Batch(proof) => {
            miden_objects::conversion::decode_proven_batch(proof, &batch).unwrap()
        },
        other => panic!("expected batch proof response, got {other:?}"),
    };

    assert_eq!(response.id(), batch.id());
    BatchVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&response).unwrap();

    server.abort();
}

/// Checks that a block request is executed and returns a canonical execution proof.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn block_proof_is_canonical_execution_proof() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Block)
        .spawn(CancellationToken::new())
        .await
        .expect("server should spawn");

    let request = ProofRequest::for_empty_block();
    let mut client = Client::connect(port).await;
    let response = client.submit_request(request).await.unwrap();
    let proof = match response.proof.unwrap() {
        ProofVariant::Block(proof) => ExecutionProof::try_from(proof).unwrap(),
        other => panic!("expected block proof response, got {other:?}"),
    };

    assert!(!proof.to_bytes().is_empty());

    server.abort();
}
