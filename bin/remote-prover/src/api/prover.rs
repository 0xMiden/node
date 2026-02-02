use miden_block_prover::LocalBlockProver;
use miden_node_proto::BlockProofRequest;
use miden_node_utils::ErrorReport;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::transaction::TransactionInputs;
use miden_protocol::utils::Serializable;
use miden_tx::LocalTransactionProver;
use miden_tx_batch_prover::LocalBatchProver;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

use crate::COMPONENT;
use crate::generated::api_server::Api as ProverApi;
use crate::generated::{self as proto};

/// Specifies the type of proof supported by the remote prover.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub enum ProofType {
    #[default]
    Transaction,
    Batch,
    Block,
}

impl std::fmt::Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofType::Transaction => write!(f, "transaction"),
            ProofType::Batch => write!(f, "batch"),
            ProofType::Block => write!(f, "block"),
        }
    }
}

impl std::str::FromStr for ProofType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "transaction" => Ok(ProofType::Transaction),
            "batch" => Ok(ProofType::Batch),
            "block" => Ok(ProofType::Block),
            _ => Err(format!("Invalid proof type: {s}")),
        }
    }
}

/// The prover for the remote prover.
///
/// This enum is used to store the prover for the remote prover.
/// Only one prover is enabled at a time.
enum Prover {
    Transaction(Mutex<LocalTransactionProver>),
    Batch(Mutex<LocalBatchProver>),
    Block(Mutex<LocalBlockProver>),
}

impl Prover {
    fn new(proof_type: ProofType) -> Self {
        match proof_type {
            ProofType::Transaction => {
                info!(target: COMPONENT, proof_type = ?proof_type, "Transaction prover initialized");
                Self::Transaction(Mutex::new(LocalTransactionProver::default()))
            },
            ProofType::Batch => {
                info!(target: COMPONENT, proof_type = ?proof_type, security_level = MIN_PROOF_SECURITY_LEVEL, "Batch prover initialized");
                Self::Batch(Mutex::new(LocalBatchProver::new(MIN_PROOF_SECURITY_LEVEL)))
            },
            ProofType::Block => {
                info!(target: COMPONENT, proof_type = ?proof_type, security_level = MIN_PROOF_SECURITY_LEVEL, "Block prover initialized");
                Self::Block(Mutex::new(LocalBlockProver::new(MIN_PROOF_SECURITY_LEVEL)))
            },
        }
    }
}

pub struct ProverRpcApi {
    prover: Prover,
}

impl ProverRpcApi {
    pub fn new(proof_type: ProofType) -> Self {
        let prover = Prover::new(proof_type);

        Self { prover }
    }

    #[allow(clippy::result_large_err)]
    #[instrument(
        target = COMPONENT,
        name = "remote_prover.prove_tx",
        skip_all,
        ret(level = "debug"),
        fields(request_id = %request_id, transaction_id = tracing::field::Empty),
        err
    )]
    pub async fn prove_tx(
        &self,
        tx_inputs: TransactionInputs,
        request_id: &str,
    ) -> Result<Response<proto::remote_prover::Proof>, tonic::Status> {
        let Prover::Transaction(prover) = &self.prover else {
            return Err(Status::unimplemented("Transaction prover is not enabled"));
        };

        let locked_prover = prover
            .try_lock()
            .map_err(|_| Status::resource_exhausted("Server is busy handling another request"))?;

        // Add a small delay to simulate longer proving time for testing
        #[cfg(test)]
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let proof = locked_prover.prove(tx_inputs).map_err(internal_error)?;

        // Record the transaction_id in the current tracing span
        let transaction_id = proof.id();
        tracing::Span::current().record("transaction_id", tracing::field::display(&transaction_id));

        Ok(Response::new(proto::remote_prover::Proof { payload: proof.to_bytes() }))
    }

    #[allow(clippy::result_large_err)]
    #[instrument(
        target = COMPONENT,
        name = "remote_prover.prove_batch",
        skip_all,
        ret(level = "debug"),
        fields(request_id = %request_id, batch_id = tracing::field::Empty),
        err
    )]
    pub fn prove_batch(
        &self,
        proposed_batch: ProposedBatch,
        request_id: &str,
    ) -> Result<Response<proto::remote_prover::Proof>, tonic::Status> {
        let Prover::Batch(prover) = &self.prover else {
            return Err(Status::unimplemented("Batch prover is not enabled"));
        };

        let proven_batch = prover
            .try_lock()
            .map_err(|_| Status::resource_exhausted("Server is busy handling another request"))?
            .prove(proposed_batch)
            .map_err(internal_error)?;

        // Record the batch_id in the current tracing span
        let batch_id = proven_batch.id();
        tracing::Span::current().record("batch_id", tracing::field::display(&batch_id));

        Ok(Response::new(proto::remote_prover::Proof { payload: proven_batch.to_bytes() }))
    }

    #[allow(clippy::result_large_err)]
    #[instrument(
        target = COMPONENT,
        name = "remote_prover.prove_block",
        skip_all,
        ret(level = "debug"),
        fields(request_id = %request_id, block_id = tracing::field::Empty),
        err
    )]
    pub fn prove_block(
        &self,
        proof_request: BlockProofRequest,
        request_id: &str,
    ) -> Result<Response<proto::remote_prover::Proof>, tonic::Status> {
        let Prover::Block(prover) = &self.prover else {
            return Err(Status::unimplemented("Block prover is not enabled"));
        };
        let BlockProofRequest { tx_batches, block_header, block_inputs } = proof_request;

        // Record the commitment of the block in the current tracing span.
        let block_id = block_header.commitment();
        tracing::Span::current().record("block_id", tracing::field::display(&block_id));

        let block_proof = prover
            .try_lock()
            .map_err(|_| Status::resource_exhausted("Server is busy handling another request"))?
            .prove(tx_batches, &block_header, block_inputs)
            .map_err(internal_error)?;

        Ok(Response::new(proto::remote_prover::Proof { payload: block_proof.to_bytes() }))
    }
}

#[async_trait::async_trait]
impl ProverApi for ProverRpcApi {
    #[instrument(
        target = COMPONENT,
        name = "remote_prover.prove",
        skip_all,
        ret(level = "debug"),
        fields(request_id = tracing::field::Empty),
        err
    )]
    async fn prove(
        &self,
        request: Request<proto::remote_prover::ProofRequest>,
    ) -> Result<Response<proto::remote_prover::Proof>, tonic::Status> {
        // Extract X-Request-ID header for trace correlation
        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string(); // Convert to owned string to avoid lifetime issues

        // Record the request_id in the current tracing span
        tracing::Span::current().record("request_id", &request_id);

        // Extract the proof type and payload
        let proof_request = request.into_inner();
        let proof_type = proof_request.proof_type();

        match proof_type {
            proto::remote_prover::ProofType::Transaction => {
                let tx_inputs = proof_request.try_into().map_err(invalid_argument)?;
                self.prove_tx(tx_inputs, &request_id).await
            },
            proto::remote_prover::ProofType::Batch => {
                let proposed_batch = proof_request.try_into().map_err(invalid_argument)?;
                self.prove_batch(proposed_batch, &request_id)
            },
            proto::remote_prover::ProofType::Block => {
                let proof_request = proof_request.try_into().map_err(invalid_argument)?;
                self.prove_block(proof_request, &request_id)
            },
        }
    }
}

// UTILITIES
// ================================================================================================

fn internal_error<E: ErrorReport>(err: E) -> Status {
    Status::internal(err.as_report())
}

fn invalid_argument<E: ErrorReport>(err: E) -> Status {
    Status::invalid_argument(err.as_report())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use std::time::Duration;

    use miden_node_utils::cors::cors_for_grpc_web_layer;
    use miden_protocol::asset::{Asset, FungibleAsset};
    use miden_protocol::note::NoteType;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_SENDER,
    };
    use miden_protocol::transaction::ProvenTransaction;
    use miden_testing::{Auth, MockChainBuilder};
    use miden_tx::utils::Serializable;
    use tokio::net::TcpListener;
    use tonic::Request;
    use tonic_web::GrpcWebLayer;

    use crate::api::ProverRpcApi;
    use crate::generated::api_client::ApiClient;
    use crate::generated::api_server::ApiServer;
    use crate::generated::{self as proto};

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_prove_transaction() {
        // Start the server in the background
        let listener = TcpListener::bind("127.0.0.1:50052").await.unwrap();

        let proof_type = proto::remote_prover::ProofType::Transaction;

        let api_service = ApiServer::new(ProverRpcApi::new(proof_type.into()));

        // Spawn the server as a background task
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .accept_http1(true)
                .layer(cors_for_grpc_web_layer())
                .layer(GrpcWebLayer::new())
                .add_service(api_service)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        // Give the server some time to start
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Set up a gRPC client to send the request
        let mut client = ApiClient::connect("http://127.0.0.1:50052").await.unwrap();
        let mut client_2 = ApiClient::connect("http://127.0.0.1:50052").await.unwrap();

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
            .build()
            .unwrap();

        let executed_transaction = Box::pin(tx_context.execute()).await.unwrap();
        let tx_inputs = executed_transaction.tx_inputs();

        let request_1 = Request::new(proto::remote_prover::ProofRequest {
            proof_type: proto::remote_prover::ProofType::Transaction.into(),
            payload: tx_inputs.to_bytes(),
        });

        let request_2 = Request::new(proto::remote_prover::ProofRequest {
            proof_type: proto::remote_prover::ProofType::Transaction.into(),
            payload: tx_inputs.to_bytes(),
        });

        // Send both requests concurrently
        let (response_1, response_2) =
            tokio::join!(client.prove(request_1), client_2.prove(request_2));

        // Check the success response
        assert!(response_1.is_ok() || response_2.is_ok());

        // Check the failure response
        assert!(response_1.is_err() || response_2.is_err());

        let response_success = response_1.or(response_2).unwrap();

        // Cast into a ProvenTransaction
        let _proven_transaction: ProvenTransaction =
            response_success.into_inner().try_into().expect("Failed to convert response");
    }
}
