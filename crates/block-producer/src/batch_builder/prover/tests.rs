use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use miden_node_proto::generated::miden::remote_prover::v1::prove_response::Proof;
use miden_node_proto::generated::miden::remote_prover::v1::{ProveRequest, ProveResponse};
use miden_node_proto::server::miden_remote_prover_v1_prover_service;
use miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE;
use miden_node_utils::testing::deferred_transaction_fixture;
use miden_protocol::testing::dummy_execution_proof;
use tokio::sync::OnceCell;
use tonic::Code;

use super::*;

async fn fixture() -> &'static (ProposedBatch, ProvenBatch) {
    static FIXTURE: OnceCell<(ProposedBatch, ProvenBatch)> = OnceCell::const_new();
    FIXTURE
        .get_or_init(|| async {
            let fixture = deferred_transaction_fixture().await;
            assert!(fixture.transaction.proof().has_precompiles());
            let proposed = ProposedBatch::new(
                vec![Arc::new(fixture.transaction.clone())],
                fixture.inputs.block_header().clone(),
                fixture.inputs.blockchain().clone(),
                BTreeMap::new(),
                MIN_PROOF_SECURITY_LEVEL,
            )
            .unwrap();
            let proven = BatchProver::new().prove(proposed.clone()).await.unwrap();
            (proposed, proven)
        })
        .await
}

#[derive(Clone)]
struct Service {
    requests: Arc<Mutex<Vec<ProveRequest>>>,
    responses: Arc<Mutex<VecDeque<Result<ProveResponse, Code>>>>,
}

#[tonic::async_trait]
impl miden_remote_prover_v1_prover_service::Prove for Service {
    type Input = ProveRequest;
    type Output = ProveResponse;

    fn decode(request: ProveRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }
    fn encode(response: Self::Output) -> tonic::Result<ProveResponse> {
        Ok(response)
    }

    async fn handle(
        &self,
        request: Self::Input,
        _: &tonic::metadata::MetadataMap,
        _: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(Code::InvalidArgument))
            .map_err(|code| tonic::Status::new(code, "prover rejected request"))
    }
}

struct Server {
    url: Url,
    service: Service,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(responses: Vec<Result<ProveResponse, Code>>) -> Self {
        let service = Service {
            requests: Arc::default(),
            responses: Arc::new(Mutex::new(responses.into())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
        let handler = service.clone();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(miden_remote_prover_v1_prover_service::service(handler))
                .serve_with_incoming(miden_node_utils::grpc::tcp_incoming(listener))
                .await
                .unwrap();
        });
        Self { url, service, task }
    }

    fn prover(&self) -> BatchProver {
        BatchProver::remote(self.url.clone(), DEFAULT_MAX_DECODING_MESSAGE_SIZE).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn response(batch: &ProvenBatch) -> ProveResponse {
    ProveResponse { proof: Some(Proof::Batch(batch.into())) }
}

#[tokio::test(flavor = "multi_thread")]
async fn proves_batches_with_deferred_precompiles() {
    let (proposed, proven) = fixture().await;
    assert_eq!(proven.id(), proposed.id());
    assert_eq!(proven.account_updates(), proposed.account_updates());
    assert_eq!(proven.input_notes(), proposed.input_notes());
    assert_eq!(proven.output_notes(), proposed.output_notes());
    BatchVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(proven).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_prover_receives_the_proposal_and_returns_a_verified_batch() {
    let (proposed, proven) = fixture().await;
    let server = Server::start(vec![Ok(response(proven))]).await;
    let result = server.prover().prove(proposed.clone()).await.unwrap();
    assert_eq!(result, *proven);
    assert_eq!(
        *server.service.requests.lock().unwrap(),
        vec![ProveRequest {
            request: Some(Request::Batch(proposed.into())),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn transient_remote_failures_are_retried() {
    let (proposed, proven) = fixture().await;
    let server = Server::start(vec![Err(Code::Unavailable), Ok(response(proven))]).await;
    assert_eq!(server.prover().prove(proposed.clone()).await.unwrap(), *proven);
    assert_eq!(server.service.requests.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_application_errors_are_returned_without_local_fallback() {
    let (proposed, _) = fixture().await;
    let server = Server::start(vec![Err(Code::InvalidArgument)]).await;
    let error = server.prover().prove(proposed.clone()).await.unwrap_err();
    assert!(matches!(error, BuildBatchError::RemoteProvingFailed(status)
        if status.code() == Code::InvalidArgument));
    assert_eq!(server.service.requests.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_responses_must_contain_a_batch_matching_the_proposal() {
    let (proposed, proven) = fixture().await;
    let mut mismatched = response(proven);
    let Some(Proof::Batch(batch)) = mismatched.proof.as_mut() else {
        unreachable!()
    };
    batch.transactions.clear();
    for response in [
        ProveResponse { proof: None },
        ProveResponse {
            proof: Some(Proof::Block(dummy_execution_proof().into())),
        },
        mismatched,
    ] {
        let server = Server::start(vec![Ok(response)]).await;
        assert!(matches!(
            server.prover().prove(proposed.clone()).await,
            Err(BuildBatchError::InvalidRemoteBatch(_))
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_batch_proofs_are_cryptographically_verified() {
    let (proposed, proven) = fixture().await;
    let mut response = response(proven);
    let Some(Proof::Batch(batch)) = response.proof.as_mut() else {
        unreachable!()
    };
    batch.proof = Some(dummy_execution_proof().into());
    let server = Server::start(vec![Ok(response)]).await;
    assert!(matches!(
        server.prover().prove(proposed.clone()).await,
        Err(BuildBatchError::InvalidRemoteBatchProof(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_response_size_obeys_the_configured_limit() {
    let (proposed, proven) = fixture().await;
    let server = Server::start(vec![Ok(response(proven))]).await;
    let limited = BatchProver::remote(server.url.clone(), 512).unwrap();
    let error = limited.prove(proposed.clone()).await.unwrap_err();
    assert!(matches!(error, BuildBatchError::RemoteProvingFailed(status)
        if status.code() == Code::OutOfRange));
}
