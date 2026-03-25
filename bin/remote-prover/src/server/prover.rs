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
use tracing::{Instrument, instrument};

use crate::COMPONENT;
use crate::generated::{self as proto};
use crate::server::proof_kind::ProofKind;

/// An enum representing the different types of provers available.
pub enum Prover {
    Transaction(LocalTransactionProver),
    Batch(LocalBatchProver),
    Block(LocalBlockProver),
}

impl Prover {
    /// Constructs a [`Prover`] of the specified [`ProofKind`].
    pub fn new(proof_type: ProofKind) -> Self {
        match proof_type {
            ProofKind::Transaction => Self::Transaction(LocalTransactionProver::default()),
            ProofKind::Batch => Self::Batch(LocalBatchProver::new(MIN_PROOF_SECURITY_LEVEL)),
            ProofKind::Block => Self::Block(LocalBlockProver::new(MIN_PROOF_SECURITY_LEVEL)),
        }
    }

    /// Proves a [`proto::ProofRequest`] using the appropriate prover implementation as specified
    /// during construction.
    pub async fn prove(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        match self {
            Prover::Transaction(prover) => prover.prove_request(request).await,
            Prover::Batch(prover) => prover.prove_request(request).await,
            Prover::Block(prover) => prover.prove_request(request).await,
        }
    }
}

/// This trait abstracts over proof request handling by providing a common interface for our
/// different provers.
///
/// It standardizes the proving process by providing default implementations for the decoding of
/// requests, and encoding of response. Notably it also standardizes the instrumentation, though
/// implementations should still add attributes that can only be known post-decoding of the request.
///
/// Implementations of this trait only need to provide the input and outputs types, as well as the
/// proof implementation.
#[async_trait::async_trait]
trait ProveRequest: Send + Sync {
    type Input: miden_protocol::utils::serde::Deserializable + Send;
    type Output: miden_protocol::utils::serde::Serializable + Send;

    async fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status>;

    /// Entry-point to the proof request handling.
    ///
    /// Decodes the request, proves it, and encodes the response.
    async fn prove_request(
        &self,
        request: proto::ProofRequest,
    ) -> Result<proto::Proof, tonic::Status> {
        let input = Self::decode_request(request)?;

        let prove_span = tracing::info_span!("prove", target = COMPONENT);
        let result = self.prove(input).instrument(prove_span).await;

        if let Err(e) = &result {
            prove_span.set_error(e);
        }

        result.map(|output| Self::encode_response(output))
    }

    #[instrument(target=COMPONENT, skip_all, err)]
    fn decode_request(request: proto::ProofRequest) -> Result<Self::Input, tonic::Status> {
        use miden_protocol::utils::serde::Deserializable;

        Self::Input::read_from_bytes(&request.payload).map_err(|e| {
            tonic::Status::invalid_argument(e.as_report_context("failed to decode request"))
        })
    }

    #[instrument(target=COMPONENT, skip_all)]
    fn encode_response(output: Self::Output) -> proto::Proof {
        use miden_protocol::utils::serde::Serializable;

        proto::Proof { payload: output.to_bytes() }
    }
}

#[async_trait::async_trait]
impl ProveRequest for LocalTransactionProver {
    type Input = TransactionInputs;
    type Output = ProvenTransaction;

    async fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status> {
        LocalTransactionProver::prove(self, input).await.map_err(|e| {
            tonic::Status::internal(e.as_report_context("failed to prove transaction"))
        })
    }
}

#[async_trait::async_trait]
impl ProveRequest for LocalBatchProver {
    type Input = ProposedBatch;
    type Output = ProvenBatch;

    async fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status> {
        self.prove(input)
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to prove batch")))
    }
}

#[async_trait::async_trait]
impl ProveRequest for LocalBlockProver {
    type Input = BlockProofRequest;
    type Output = BlockProof;

    async fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status> {
        let BlockProofRequest { tx_batches, block_header, block_inputs } = input;
        self.prove(tx_batches, &block_header, block_inputs)
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to prove block")))
    }
}
