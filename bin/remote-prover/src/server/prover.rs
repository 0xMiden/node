use miden_block_prover::{BlockExecutor, LocalBlockProver};
use miden_node_proto::generated::remote_prover::proof::Proof as ProofVariant;
use miden_node_proto::generated::remote_prover::proof_request::DecodedRequest as Request;
use miden_node_proto::generated::{block_proving, remote_prover as proto, transaction};
use miden_node_proto::{BlockProofRequest, BuildUnchecked, DecodeMessage, Decoded, VerifyWith};
use miden_node_tracing::{ErrorReport, miden_instrument};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::block::ProposedBlock;
use miden_protocol::transaction::TransactionInputs;
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

    /// Proves the structured request matching this worker's configured capability.
    #[miden_instrument(
        target=COMPONENT,
        name="prove",
        err,
    )]
    pub fn prove(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        let request = request
            .decode_fields()
            .map_err(miden_node_proto::errors::conversion_error_to_status)?
            .request;

        let proof = match (self, request) {
            (Self::Transaction(prover), Request::Transaction(input)) => {
                prove_transaction(prover, input)?
            },
            (Self::Batch(prover), Request::Batch(input)) => prove_batch(prover, input)?,
            (Self::Block(prover), Request::Block(input)) => prove_block(prover, input)?,
            _ => return Err(tonic::Status::invalid_argument("unsupported proof type")),
        };

        Ok(proto::Proof { proof: Some(proof) })
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

fn prove_transaction(
    prover: &LocalTransactionProver,
    input: Decoded<transaction::TransactionInputs>,
) -> Result<ProofVariant, tonic::Status> {
    // SAFETY: Construction checks input consistency and note inclusion against supplied headers.
    // This stateless prover cannot authenticate the chain. The submitting node must do that.
    let input: TransactionInputs = input.build_unchecked().map_err(|error| {
        tonic::Status::invalid_argument(
            error.as_report_context("failed to build transaction inputs"),
        )
    })?;
    let transaction = prover.prove(input).map_err(|error| {
        tonic::Status::internal(error.as_report_context("failed to prove transaction"))
    })?;

    Ok(ProofVariant::Transaction(transaction.into()))
}

fn prove_batch(
    prover: &LocalBatchProver,
    input: Decoded<transaction::ProposedBatch>,
) -> Result<ProofVariant, tonic::Status> {
    let input = input.verify_with(MIN_PROOF_SECURITY_LEVEL).map_err(|error| {
        tonic::Status::invalid_argument(error.as_report_context("failed to verify proposed batch"))
    })?;
    let executed_batch = BatchExecutor::new().execute(input).map_err(|error| {
        tonic::Status::internal(error.as_report_context("failed to execute batch"))
    })?;
    let batch = prover.prove(executed_batch).map_err(|error| {
        tonic::Status::internal(error.as_report_context("failed to prove batch"))
    })?;

    Ok(ProofVariant::Batch(batch.into()))
}

fn prove_block(
    prover: &LocalBlockProver,
    input: block_proving::DecodedBlockProofRequest,
) -> Result<ProofVariant, tonic::Status> {
    // SAFETY: This service only produces a proof for the supplied proposal. It does not commit the
    // block. The caller must validate batch contents and authenticate the parent chain.
    //
    // FIXME: Verify batch proofs and contents before block proving. The current batch kernel
    // does not bind the aggregated note contents or expiration.
    let BlockProofRequest { tx_batches, block_header, block_inputs } =
        input.build_unchecked().map_err(|error| {
            tonic::Status::invalid_argument(
                error.as_report_context("failed to decode block proving inputs"),
            )
        })?;
    let proposed_block =
        ProposedBlock::new_at(block_inputs, tx_batches.into_vec(), block_header.timestamp())
            .map_err(|error| {
                tonic::Status::invalid_argument(
                    error.as_report_context("failed to construct proposed block"),
                )
            })?
            .with_next_validator_config(block_header.validator_config().clone())
            .with_next_protocol_config(block_header.next_protocol_config().cloned());
    let executed_block = BlockExecutor::new().execute(proposed_block).map_err(|error| {
        tonic::Status::internal(error.as_report_context("failed to execute block"))
    })?;
    let proof = prover.prove(executed_block).map_err(|error| {
        tonic::Status::internal(error.as_report_context("failed to prove block"))
    })?;

    Ok(ProofVariant::Block(proof.into()))
}
