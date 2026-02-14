use std::num::NonZeroUsize;

use miden_block_prover::LocalBlockProver;
use miden_node_proto::BlockProofRequest;
use miden_node_utils::ErrorReport;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::block::BlockProof;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::LocalTransactionProver;
use miden_tx_batch_prover::LocalBatchProver;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, MutexGuard, SemaphorePermit};
use tonic::{Request, Response};
use tracing::instrument;

use crate::COMPONENT;
use crate::generated::api_server::Api as ProverApi;
use crate::generated::{self as proto};

/// Specifies the type of proof supported by the remote prover.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ProofKind {
    Transaction,
    Batch,
    Block,
}

impl From<proto::ProofType> for ProofKind {
    fn from(value: proto::ProofType) -> Self {
        match value {
            proto::ProofType::Transaction => ProofKind::Transaction,
            proto::ProofType::Batch => ProofKind::Batch,
            proto::ProofType::Block => ProofKind::Block,
        }
    }
}

impl std::fmt::Display for ProofKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofKind::Transaction => write!(f, "transaction"),
            ProofKind::Batch => write!(f, "batch"),
            ProofKind::Block => write!(f, "block"),
        }
    }
}

impl miden_node_utils::tracing::ToValue for ProofKind {
    fn to_value(&self) -> opentelemetry::Value {
        self.to_string().into()
    }
}

impl std::str::FromStr for ProofKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "transaction" => Ok(ProofKind::Transaction),
            "batch" => Ok(ProofKind::Batch),
            "block" => Ok(ProofKind::Block),
            _ => Err(format!("Invalid proof type: {s}")),
        }
    }
}

/// The prover for the remote prover.
///
/// This enum is used to store the prover for the remote prover.
/// Only one prover is enabled at a time.
enum Prover {
    Transaction(LocalTransactionProver),
    Batch(LocalBatchProver),
    Block(LocalBlockProver),
}

impl Prover {
    fn new(proof_type: ProofKind) -> Self {
        match proof_type {
            ProofKind::Transaction => Self::Transaction(LocalTransactionProver::default()),
            ProofKind::Batch => Self::Batch(LocalBatchProver::new(MIN_PROOF_SECURITY_LEVEL)),
            ProofKind::Block => Self::Block(LocalBlockProver::new(MIN_PROOF_SECURITY_LEVEL)),
        }
    }

    fn prove(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        match self {
            Prover::Transaction(prover) => prover.prove_request(request),
            Prover::Batch(prover) => prover.prove_request(request),
            Prover::Block(prover) => prover.prove_request(request),
        }
    }
}

pub struct ProverService {
    permits: tokio::sync::Semaphore,
    prover: tokio::sync::Mutex<Prover>,
    kind: ProofKind,
}

impl ProverService {
    pub fn with_capacity(kind: ProofKind, capacity: NonZeroUsize) -> Self {
        let permits = tokio::sync::Semaphore::new(capacity.get());
        let prover = Mutex::new(Prover::new(kind));
        Self { permits, prover, kind }
    }

    fn is_supported(&self, kind: ProofKind) -> bool {
        self.kind == kind
    }

    #[instrument(target=COMPONENT, skip_all, err)]
    fn acquire_permit(&self) -> Result<SemaphorePermit<'_>, tonic::Status> {
        self.permits
            .try_acquire()
            .map_err(|_| tonic::Status::resource_exhausted("proof queue is full"))
    }

    #[instrument(target=COMPONENT, skip_all)]
    async fn acquire_prover_lock(&self) -> MutexGuard<'_, Prover> {
        self.prover.lock().await
    }
}

#[async_trait::async_trait]
impl ProverApi for ProverService {
    async fn prove(
        &self,
        request: Request<proto::ProofRequest>,
    ) -> Result<Response<proto::Proof>, tonic::Status> {
        // Record X-Request-ID header for trace correlation
        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        tracing::Span::current().set_attribute("request.id", request_id);

        // Check that the proof type is supported.
        let request = request.into_inner();
        // Protobuf enums return a default value if the enum is set to an unknown value.
        // This round trip checks that the value is valid.
        if request.proof_type() as i32 != request.proof_type {
            return Err(tonic::Status::invalid_argument("unknown proof_type value"));
        }
        let proof_kind = ProofKind::from(request.proof_type());
        tracing::Span::current().set_attribute("request.kind", proof_kind);

        // Reject unsupported proof types early so they don't clog the queue.
        if !self.is_supported(proof_kind) {
            return Err(tonic::Status::invalid_argument("unsupported proof type"));
        }

        // This semaphore acts like a queue, but with a fixed capacity.
        //
        // We need to hold this until our request is processed to ensure that the queue capacity is
        // not exceeded.
        let _permit = self.acquire_permit()?;

        // This mutex is fair and uses FIFO ordering.
        let prover = self.acquire_prover_lock().await;

        // Blocking in place is fairly safe since we guarantee that only a single request is
        // processed at a time.
        tokio::task::block_in_place(|| prover.prove(request)).map(tonic::Response::new)
    }
}

trait ProveRequest {
    type Input: miden_protocol::utils::Deserializable;
    type Output: miden_protocol::utils::Serializable;

    fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status>;

    fn prove_request(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        Self::decode_request(request)
            .and_then(|input| {
                // We cannot #[instrument] the trait's prove method so we do it manually.
                tracing::info_span!("prove", target = COMPONENT).in_scope(|| {
                    self.prove(input).inspect_err(|e| tracing::Span::current().set_error(e))
                })
            })
            .map(|output| Self::encode_response(output))
    }

    #[instrument(target=COMPONENT, skip_all, err)]
    fn decode_request(request: proto::ProofRequest) -> Result<Self::Input, tonic::Status> {
        use miden_protocol::utils::Deserializable;

        Self::Input::read_from_bytes(&request.payload).map_err(|e| {
            tonic::Status::invalid_argument(e.as_report_context("failed to decode request"))
        })
    }

    #[instrument(target=COMPONENT, skip_all)]
    fn encode_response(output: Self::Output) -> proto::Proof {
        use miden_protocol::utils::Serializable;

        proto::Proof { payload: output.to_bytes() }
    }
}

impl ProveRequest for LocalTransactionProver {
    type Input = TransactionInputs;
    type Output = ProvenTransaction;

    fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status> {
        self.prove(input).map_err(|e| {
            tonic::Status::internal(e.as_report_context("failed to prove transaction"))
        })
    }
}

impl ProveRequest for LocalBatchProver {
    type Input = ProposedBatch;
    type Output = ProvenBatch;

    fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status> {
        self.prove(input)
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to prove batch")))
    }
}

impl ProveRequest for LocalBlockProver {
    type Input = BlockProofRequest;
    type Output = BlockProof;

    fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status> {
        let BlockProofRequest { tx_batches, block_header, block_inputs } = input;
        self.prove(tx_batches, &block_header, block_inputs)
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to prove batch")))
    }
}

// TESTS
// ================================================================================================

// #[cfg(test)]
// mod test {
//     use std::time::Duration;

//     use miden_node_utils::cors::cors_for_grpc_web_layer;
//     use miden_protocol::asset::{Asset, FungibleAsset};
//     use miden_protocol::note::NoteType;
//     use miden_protocol::testing::account_id::{
//         ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
//         ACCOUNT_ID_SENDER,
//     };
//     use miden_protocol::transaction::ProvenTransaction;
//     use miden_testing::{Auth, MockChainBuilder};
//     use miden_tx::utils::Serializable;
//     use tokio::net::TcpListener;
//     use tonic::Request;
//     use tonic_web::GrpcWebLayer;

//     use crate::generated::api_client::ApiClient;
//     use crate::generated::api_server::ApiServer;
//     use crate::generated::{self as proto};
//     use crate::server::prover::ProverRpcApi;

//     #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
//     async fn test_prove_transaction() {
//         // Start the server in the background
//         let listener = TcpListener::bind("127.0.0.1:50052").await.unwrap();

//         let proof_type = proto::remote_prover::ProofType::Transaction;

//         let api_service = ApiServer::new(ProverRpcApi::new(proof_type.into()));

//         // Spawn the server as a background task
//         tokio::spawn(async move {
//             tonic::transport::Server::builder()
//                 .accept_http1(true)
//                 .layer(cors_for_grpc_web_layer())
//                 .layer(GrpcWebLayer::new())
//                 .add_service(api_service)
//                 .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
//                 .await
//                 .unwrap();
//         });

//         // Give the server some time to start
//         tokio::time::sleep(Duration::from_secs(1)).await;

//         // Set up a gRPC client to send the request
//         let mut client = ApiClient::connect("http://127.0.0.1:50052").await.unwrap();
//         let mut client_2 = ApiClient::connect("http://127.0.0.1:50052").await.unwrap();

//         // Create a mock transaction to send to the server
//         let mut mock_chain_builder = MockChainBuilder::new();
//         let account = mock_chain_builder.add_existing_wallet(Auth::BasicAuth).unwrap();

//         let fungible_asset_1: Asset =
//             FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
//                 .unwrap()
//                 .into();
//         let note_1 = mock_chain_builder
//             .add_p2id_note(
//                 ACCOUNT_ID_SENDER.try_into().unwrap(),
//                 account.id(),
//                 &[fungible_asset_1],
//                 NoteType::Private,
//             )
//             .unwrap();

//         let mock_chain = mock_chain_builder.build().unwrap();

//         let tx_context = mock_chain
//             .build_tx_context(account.id(), &[note_1.id()], &[])
//             .unwrap()
//             .build()
//             .unwrap();

//         let executed_transaction = Box::pin(tx_context.execute()).await.unwrap();
//         let tx_inputs = executed_transaction.tx_inputs();

//         let request_1 = Request::new(proto::remote_prover::ProofRequest {
//             proof_type: proto::remote_prover::ProofType::Transaction.into(),
//             payload: tx_inputs.to_bytes(),
//         });

//         let request_2 = Request::new(proto::remote_prover::ProofRequest {
//             proof_type: proto::remote_prover::ProofType::Transaction.into(),
//             payload: tx_inputs.to_bytes(),
//         });

//         // Send both requests concurrently
//         let (response_1, response_2) =
//             tokio::join!(client.prove(request_1), client_2.prove(request_2));

//         // Check the success response
//         assert!(response_1.is_ok() || response_2.is_ok());

//         // Check the failure response
//         assert!(response_1.is_err() || response_2.is_err());

//         let response_success = response_1.or(response_2).unwrap();

//         // Cast into a ProvenTransaction
//         let _proven_transaction: ProvenTransaction =
//             response_success.into_inner().try_into().expect("Failed to convert response");
//     }
// }
