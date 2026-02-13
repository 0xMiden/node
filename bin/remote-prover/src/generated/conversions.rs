// CONVERSIONS
// ================================================================================================

use miden_node_proto::BlockProofRequest;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::utils::{Deserializable, DeserializationError, Serializable};

use crate::generated as proto;

impl From<ProvenTransaction> for proto::Proof {
    fn from(value: ProvenTransaction) -> Self {
        proto::Proof { payload: value.to_bytes() }
    }
}

impl TryFrom<proto::Proof> for ProvenTransaction {
    type Error = DeserializationError;

    fn try_from(response: proto::Proof) -> Result<Self, Self::Error> {
        ProvenTransaction::read_from_bytes(&response.payload)
    }
}

impl TryFrom<proto::ProofRequest> for TransactionInputs {
    type Error = DeserializationError;

    fn try_from(request: proto::ProofRequest) -> Result<Self, Self::Error> {
        TransactionInputs::read_from_bytes(&request.payload)
    }
}

impl TryFrom<proto::ProofRequest> for ProposedBatch {
    type Error = DeserializationError;

    fn try_from(request: proto::ProofRequest) -> Result<Self, Self::Error> {
        ProposedBatch::read_from_bytes(&request.payload)
    }
}

impl TryFrom<proto::ProofRequest> for BlockProofRequest {
    type Error = DeserializationError;

    fn try_from(request: proto::ProofRequest) -> Result<Self, Self::Error> {
        BlockProofRequest::read_from_bytes(&request.payload)
    }
}
