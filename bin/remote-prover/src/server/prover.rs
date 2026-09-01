use miden_block_prover::{BlockExecutor, LocalBlockProver};
use miden_node_proto::BlockProofRequest;
use miden_node_proto::generated::remote_prover as proto;
use miden_node_proto::generated::remote_prover::proof::Proof as ProofVariant;
use miden_node_proto::generated::remote_prover::proof_request::Request;
use miden_node_tracing::{ErrorReport, miden_instrument};
use miden_objects::conversion::decode_proposed_batch;
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
            ProofKind::Batch => Self::Batch(LocalBatchProver::new()),
            ProofKind::Block => Self::Block(LocalBlockProver::new(MIN_PROOF_SECURITY_LEVEL)),
        }
    }

    /// Proves the structured request matching this worker's configured capability.
    #[miden_instrument(
        target=COMPONENT,
        name="prove",
        err,
    )]
    pub fn prove(&self, request: proto::ProofRequest) -> Result<proto::Proof, tonic::Status> {
        match (self, request.request) {
            (Self::Transaction(prover), Some(Request::Transaction(input))) => {
                let input = TransactionInputs::try_from(input).map_err(|error| {
                    tonic::Status::invalid_argument(
                        error.as_report_context("failed to decode transaction inputs"),
                    )
                })?;
                let transaction = prover.prove(input).map_err(|error| {
                    tonic::Status::internal(error.as_report_context("failed to prove transaction"))
                })?;

                Ok(proto::Proof {
                    proof: Some(ProofVariant::Transaction(transaction.into())),
                })
            },
            (Self::Batch(prover), Some(Request::Batch(input))) => {
                let input =
                    decode_proposed_batch(input, MIN_PROOF_SECURITY_LEVEL).map_err(|error| {
                        tonic::Status::invalid_argument(
                            error.as_report_context("failed to decode proposed batch"),
                        )
                    })?;
                let executed_batch = BatchExecutor::new().execute(input).map_err(|error| {
                    tonic::Status::internal(error.as_report_context("failed to execute batch"))
                })?;
                let batch = prover.prove(executed_batch).map_err(|error| {
                    tonic::Status::internal(error.as_report_context("failed to prove batch"))
                })?;

                Ok(proto::Proof {
                    proof: Some(ProofVariant::Batch(batch.into())),
                })
            },
            (Self::Block(prover), Some(Request::Block(input))) => {
                let BlockProofRequest { tx_batches, block_header, block_inputs } = input
                    .try_into()
                    .map_err(|error: miden_node_proto::errors::ConversionError| {
                        tonic::Status::invalid_argument(
                            error.as_report_context("failed to decode block proving inputs"),
                        )
                    })?;
                let proposed_block = ProposedBlock::new_at(
                    block_inputs,
                    tx_batches.into_vec(),
                    block_header.timestamp(),
                )
                .map_err(|error| {
                    tonic::Status::invalid_argument(
                        error.as_report_context("failed to construct proposed block"),
                    )
                })?
                .with_next_validator_config(block_header.validator_config().clone())
                .with_next_protocol_config(block_header.next_protocol_config().cloned());
                let executed_block =
                    BlockExecutor::new().execute(proposed_block).map_err(|error| {
                        tonic::Status::internal(error.as_report_context("failed to execute block"))
                    })?;
                let proof = prover.prove(executed_block).map_err(|error| {
                    tonic::Status::internal(error.as_report_context("failed to prove block"))
                })?;

                Ok(proto::Proof {
                    proof: Some(ProofVariant::Block(proof.into())),
                })
            },
            (_, None) => Err(tonic::Status::invalid_argument("missing proof request")),
            _ => Err(tonic::Status::invalid_argument("unsupported proof type")),
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
