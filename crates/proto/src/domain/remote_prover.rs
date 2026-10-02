use miden_protobuf::{ConversionError, ConversionResultExt, Decoded, VerifyWith};
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::vm::ExecutionProof;

use crate::generated as proto;

impl proto::miden::remote_prover::v1::DecodedProveResponse {
    /// Extract the transaction fields without verifying the transaction.
    pub fn into_transaction(
        self,
    ) -> Result<Decoded<proto::transaction::ProvenTransaction>, ConversionError> {
        self.proof.into_transaction().context("proof")
    }

    /// Extract the batch fields without verifying the batch.
    pub fn into_batch(self) -> Result<Decoded<proto::transaction::ProvenBatch>, ConversionError> {
        self.proof.into_batch().context("proof")
    }

    /// Extract the block proof without verifying its statement.
    pub fn into_block(self) -> Result<ExecutionProof, ConversionError> {
        self.proof.into_block().context("proof")
    }
}

impl VerifyWith<&ProposedBatch> for proto::miden::remote_prover::v1::DecodedProveResponse {
    type Verified = ProvenBatch;
    type Error = ConversionError;

    /// Match the returned batch to the supplied proposal. The caller must verify the proposal
    /// first. The caller must verify the execution proof separately.
    fn verify_with(self, proposal: &ProposedBatch) -> Result<Self::Verified, Self::Error> {
        self.into_batch()?.verify_with(proposal).context("proof.batch")
    }
}

#[cfg(test)]
mod tests {
    use miden_protobuf::DecodeMessage;
    use miden_protocol::testing::dummy_execution_proof;

    use super::*;

    fn block_response() -> proto::miden::remote_prover::v1::ProveResponse {
        proto::miden::remote_prover::v1::ProveResponse {
            proof: Some(proto::miden::remote_prover::v1::prove_response::Proof::Block(
                dummy_execution_proof().into(),
            )),
        }
    }

    #[test]
    fn missing_proof_is_rejected() {
        let error = proto::miden::remote_prover::v1::ProveResponse { proof: None }
            .decode_fields()
            .unwrap_err();
        assert!(error.to_string().contains("proof"));
    }

    #[test]
    fn block_response_does_not_satisfy_transaction_or_batch_request() {
        let error = block_response().decode_fields().unwrap().into_transaction().unwrap_err();
        assert!(error.to_string().contains("expected oneof variant `transaction`, got `block`"));
        let error = block_response().decode_fields().unwrap().into_batch().unwrap_err();
        assert!(error.to_string().contains("expected oneof variant `batch`, got `block`"));
    }

    #[test]
    fn block_response_preserves_proof() {
        assert_eq!(
            block_response().decode_fields().unwrap().into_block().unwrap(),
            dummy_execution_proof()
        );
    }

    #[test]
    fn malformed_proof_retains_field_context() {
        let response = proto::miden::remote_prover::v1::ProveResponse {
            proof: Some(proto::miden::remote_prover::v1::prove_response::Proof::Transaction(
                proto::transaction::ProvenTransaction::default(),
            )),
        };
        let error = response.decode_fields().unwrap_err();
        assert!(error.to_string().contains("proof.transaction"));
    }
}
