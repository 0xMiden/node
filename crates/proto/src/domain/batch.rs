use std::collections::BTreeMap;

use miden_protocol::block::BlockHeader;
use miden_protocol::note::{NoteId, NoteInclusionProof};
use miden_protocol::transaction::PartialBlockchain;
use miden_protocol::utils::{Deserializable, Serializable};

use crate::errors::ConversionError;
use crate::generated as proto;

/// Data required for a transaction batch.
#[derive(Clone, Debug)]
pub struct BatchInputs {
    pub batch_reference_block_header: BlockHeader,
    pub note_proofs: BTreeMap<NoteId, NoteInclusionProof>,
    pub partial_block_chain: PartialBlockchain,
}

impl From<BatchInputs> for proto::store::BatchInputs {
    fn from(inputs: BatchInputs) -> Self {
        Self {
            batch_reference_block_header: Some(inputs.batch_reference_block_header.into()),
            note_proofs: inputs.note_proofs.iter().map(Into::into).collect(),
            partial_block_chain: inputs.partial_block_chain.to_bytes(),
        }
    }
}

impl TryFrom<proto::store::BatchInputs> for BatchInputs {
    type Error = ConversionError;

    fn try_from(response: proto::store::BatchInputs) -> Result<Self, ConversionError> {
        let result = Self {
            batch_reference_block_header: response
                .batch_reference_block_header
                .ok_or(ConversionError::missing_field::<proto::store::BatchInputs>("block_header"))?
                .try_into()?,
            note_proofs: response
                .note_proofs
                .iter()
                .map(<(NoteId, NoteInclusionProof)>::try_from)
                .collect::<Result<_, ConversionError>>()?,
            partial_block_chain: PartialBlockchain::read_from_bytes(&response.partial_block_chain)
                .map_err(|source| ConversionError::deserialization("PartialBlockchain", source))?,
        };

        Ok(result)
    }
}
