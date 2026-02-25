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
use tracing::instrument;

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

    /// Proves a [`proto::ProofRequest`] using the appropriate prover implementation as specified during
    /// construction.
    pub fn prove(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        match self {
            Prover::Transaction(prover) => prover.prove_request(request),
            Prover::Batch(prover) => prover.prove_request(request),
            Prover::Block(prover) => prover.prove_request(request),
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
trait ProveRequest {
    type Input: miden_protocol::utils::Deserializable;
    type Output: miden_protocol::utils::Serializable;

    fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status>;

    /// Entry-point to the proof request handling.
    ///
    /// Decodes the request, proves it, and encodes the response.
    fn prove_request(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        Self::decode_request(request)
            .and_then(|input| {
                // We cannot #[instrument] the trait's prove method because it lacks an
                // implementation, so we do it manually.
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
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to prove block")))
    }
}
