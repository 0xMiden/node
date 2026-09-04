use miden_block_prover::{BlockExecutor, LocalBlockProver};
use miden_node_proto::BlockProofRequest;
use miden_node_proto::generated::remote_prover as proto;
use miden_node_tracing::{ErrorReport, miden_instrument};
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::block::ProposedBlock;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_protocol::vm::ExecutionProof;
use miden_tx::LocalTransactionProver;
use miden_tx_batch::{BatchExecutor, LocalBatchProver};

use crate::COMPONENT;
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
            ProofKind::Batch => Self::Batch(LocalBatchProver::default()),
            ProofKind::Block => Self::Block(LocalBlockProver::default()),
        }
    }

    /// Proves a [`proto::ProofRequest`] using the appropriate prover implementation as specified
    /// during construction.
    pub fn prove(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        match self {
            Prover::Transaction(prover) => prover.prove_request(request),
            Prover::Batch(prover) => prover.prove_request(request),
            Prover::Block(prover) => prover.prove_request(request),
        }
    }

    /// Returns the context attached to failures of the blocking task running this prover.
    pub const fn task_panic_context(&self) -> &'static str {
        match self {
            Prover::Transaction(_) => "transaction prover task panicked",
            Prover::Batch(_) => "batch prover task panicked",
            Prover::Block(_) => "block prover task panicked",
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
trait ProveRequest: Send + Sync {
    type Input: miden_protocol::utils::serde::Deserializable + Send;
    type Output: miden_protocol::utils::serde::Serializable + Send;

    fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status>;

    /// Entry-point to the proof request handling.
    ///
    /// Decodes the request, proves it, and encodes the response.
    #[miden_instrument(
        target=COMPONENT,
        name="prove",
        err,
    )]
    fn prove_request(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        let input = Self::decode_request(request)?;
        self.prove(input).map(|output| Self::encode_response(output))
    }

    #[miden_instrument(
        target=COMPONENT,
        err,
    )]
    fn decode_request(request: proto::ProofRequest) -> Result<Self::Input, tonic::Status> {
        use miden_protocol::utils::serde::Deserializable;

        Self::Input::read_from_bytes(&request.payload).map_err(|e| {
            tonic::Status::invalid_argument(e.as_report_context("failed to decode request"))
        })
    }

    #[miden_instrument(
        target=COMPONENT,
    )]
    fn encode_response(output: Self::Output) -> proto::Proof {
        use miden_protocol::utils::serde::Serializable;

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
        let executed_batch = BatchExecutor::new()
            .execute(input)
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to execute batch")))?;
        self.prove(executed_batch)
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to prove batch")))
    }
}

impl ProveRequest for LocalBlockProver {
    type Input = BlockProofRequest;
    type Output = ExecutionProof;

    fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status> {
        let BlockProofRequest { tx_batches, block_header, block_inputs } = input;
        let proposed_block =
            ProposedBlock::new_at(block_inputs, tx_batches.into_vec(), block_header.timestamp())
                .map_err(|e| {
                    tonic::Status::invalid_argument(
                        e.as_report_context("failed to construct proposed block"),
                    )
                })?
                .with_next_validator_config(block_header.validator_config().clone())
                .with_next_protocol_config(block_header.next_protocol_config().cloned());
        let executed_block = BlockExecutor::new()
            .execute(proposed_block)
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to execute block")))?;

        self.prove(executed_block)
            .map_err(|e| tonic::Status::internal(e.as_report_context("failed to prove block")))
    }
}
