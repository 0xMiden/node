use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction};
use miden_testing::{Auth, MockChainBuilder};
use miden_tx::LocalTransactionProver;
use miden_tx::utils::{Deserializable, Serializable};
use miden_tx_batch_prover::LocalBatchProver;

use crate::generated::api_client::ApiClient;
use crate::generated::{Proof, ProofRequest, ProofType};
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

impl ProofRequest {
    /// Generates a proof request for a transaction using [`MockChain`].
    fn from_tx(tx: &ExecutedTransaction) -> Self {
        let tx_inputs = tx.tx_inputs().clone();

        Self {
            proof_type: ProofType::Transaction as i32,
            payload: tx_inputs.to_bytes(),
        }
    }

    fn from_batch(batch: &ProposedBatch) -> Self {
        Self {
            proof_type: ProofType::Batch as i32,
            payload: batch.to_bytes(),
        }
    }

    async fn mock_tx() -> ExecutedTransaction {
        // Create a mock transaction to send to the server
        let mut mock_chain_builder = MockChainBuilder::new();
        let account = mock_chain_builder.add_existing_wallet(Auth::BasicAuth).unwrap();

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
            .build_tx_context(account.id(), &[note_1.id()], &[])
            .unwrap()
            .disable_debug_mode()
            .build()
            .unwrap();

        Box::pin(tx_context.execute()).await.unwrap()
    }

    async fn mock_batch() -> ProposedBatch {
        // Create a mock transaction to send to the server
        let mut mock_chain_builder = MockChainBuilder::new();
        let account = mock_chain_builder.add_existing_wallet(Auth::BasicAuth).unwrap();

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
            .build_tx_context(account.id(), &[note_1.id()], &[])
            .unwrap()
            .disable_debug_mode()
            .build()
            .unwrap();

        let tx = Box::pin(tx.execute()).await.unwrap();
        let tx = tokio::task::block_in_place(|| {
            LocalTransactionProver::default().prove(tx.tx_inputs().clone()).unwrap()
        });

        ProposedBatch::new(
            vec![Arc::new(tx)],
            mock_chain.latest_block_header(),
            mock_chain.latest_partial_blockchain(),
            BTreeMap::new(),
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
            timeout: Duration::from_secs(60),
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

/// This test ensures that the legacy behaviour can still be configured.
///
/// The original prover worker refused to process multiple requests concurrently.
/// This test ensures that the redesign behaves the same when limited to a capacity of 1.
///
/// Create a server with a capacity of one and submit two requests. Ensure
/// that one succeeds and one fails with a resource exhaustion error.
#[tokio::test(flavor = "multi_thread")]
async fn legacy_behaviour_with_capacity_1() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .with_capacity(1)
        .spawn()
        .await
        .expect("server should spawn");

    let request = ProofRequest::from_tx(&ProofRequest::mock_tx().await);

    let mut client_a = Client::connect(port).await;
    let mut client_b = client_a.clone();

    let a = client_a.submit_request(request.clone());
    let b = client_b.submit_request(request);

    let (first, second) = tokio::join!(a, b);

    // We cannot know which got served and which got rejected.
    // We can only assert that one of them is Ok and the other is Err.
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
#[tokio::test(flavor = "multi_thread")]
async fn capacity_is_respected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .with_capacity(2)
        .spawn()
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

    // We cannot know which got served and which got rejected.
    // We can only assert that two succeeded and one failed.
    let mut expected = [true, true, false];
    let mut result = [first.is_ok(), second.is_ok(), third.is_ok()];
    expected.sort_unstable();
    result.sort_unstable();
    assert_eq!(expected, result);

    // We also expect that the error is a resource exhaustion error.
    let err = first.err().or(second.err()).or(third.err()).unwrap();
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    server.abort();
}

/// Ensures that the server request timeout is adhered to.
///
/// We cannot actually enforce this for a request that has already being proven as the proof
/// is done in a blocking sync task. We can however check that a second queued request is rejected.
///
/// This is tricky to test properly because we can't easily control the server's response time.
/// Instead we configure the server to have a ridiculously short timeout which should hopefully
/// always timeout.
#[tokio::test(flavor = "multi_thread")]
async fn timeout_is_respected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .with_timeout(Duration::from_nanos(10))
        .spawn()
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

/// Ensures that an invalid proof kind is rejected.
///
/// The error should be an invalid argument error, but since that is fairly broad we also inspect
/// the error message for mention of the invalid proof kind. This is technically an implementation
/// detail, but its the best we have without adding multiple abstraction layers.
#[tokio::test(flavor = "multi_thread")]
async fn invalid_proof_kind_is_rejected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .spawn()
        .await
        .expect("server should spawn");

    let mut request = ProofRequest::from_tx(&ProofRequest::mock_tx().await);
    request.proof_type = i32::MAX;

    let mut client = Client::connect(port).await;
    let response = client.submit_request(request).await;
    let err = response.unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("unknown proof_type value"));

    server.abort();
}

/// Ensures that a valid but unsupported proof kind is rejected.
///
/// Aka submit a transaction proof request to a batch proving server.
///
/// The error should be an invalid argument error, but since that is fairly broad we also inspect
/// the error message for mention of the unsupported proof kind. This is technically an
/// implementation detail, but its the best we have without adding multiple abstraction layers.
#[tokio::test(flavor = "multi_thread")]
async fn unsupported_proof_kind_is_rejected() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Batch)
        .spawn()
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
/// The proof is replicated locally, which ensures that the gRPC codec and server code do the
/// correct thing.
#[tokio::test(flavor = "multi_thread")]
async fn transaction_proof_is_correct() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Transaction)
        .spawn()
        .await
        .expect("server should spawn");

    let tx = ProofRequest::mock_tx().await;
    let request = ProofRequest::from_tx(&tx);

    let mut client = Client::connect(port).await;
    let response = client.submit_request(request).await.unwrap();
    let response = ProvenTransaction::read_from_bytes(&response.payload).unwrap();

    let expected = tokio::task::block_in_place(|| {
        LocalTransactionProver::default().prove(tx.tx_inputs().clone()).unwrap()
    });
    assert_eq!(response, expected);

    server.abort();
}

/// Checks that the a batch request results in a correct proof.
///
/// The proof is replicated locally, which ensures that the gRPC codec and server code do the
/// correct thing.
#[tokio::test(flavor = "multi_thread")]
async fn batch_proof_is_correct() {
    let (server, port) = Server::with_arbitrary_port(ProofKind::Batch)
        .spawn()
        .await
        .expect("server should spawn");

    let batch = ProofRequest::mock_batch().await;
    let request = ProofRequest::from_batch(&batch);

    let mut client = Client::connect(port).await;
    let response = client.submit_request(request).await.unwrap();
    let response = ProvenBatch::read_from_bytes(&response.payload).unwrap();

    let expected = tokio::task::block_in_place(|| {
        LocalBatchProver::new(MIN_PROOF_SECURITY_LEVEL).prove(batch).unwrap()
    });
    assert_eq!(response, expected);

    server.abort();
}
