use std::collections::BTreeMap;

use miden_protocol::block::BlockHeader;
use miden_protocol::note::{NoteId, NoteInclusionProof};
use miden_protocol::transaction::PartialBlockchain;
use miden_protocol::utils::{Deserializable, Serializable};
use thiserror::Error;

use crate::domain::block::BlockConversionError;
use crate::domain::note::NoteConversionError;
use crate::errors::{MissingFieldHelper, ProtoConversionError};
use crate::generated as proto;

// BATCH CONVERSION ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum BatchConversionError {
    #[error(transparent)]
    Proto(#[from] ProtoConversionError),
    #[error(transparent)]
    Block(#[from] BlockConversionError),
    #[error(transparent)]
    Note(#[from] NoteConversionError),
}

impl From<BatchConversionError> for tonic::Status {
    fn from(value: BatchConversionError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}

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
    type Error = BatchConversionError;

    fn try_from(response: proto::store::BatchInputs) -> Result<Self, BatchConversionError> {
        let result = Self {
            batch_reference_block_header: response
                .batch_reference_block_header
                .ok_or(proto::store::BatchInputs::missing_field("block_header"))?
                .try_into()?,
            note_proofs: response
                .note_proofs
                .iter()
                .map(|p| {
                    <(NoteId, NoteInclusionProof)>::try_from(p).map_err(BatchConversionError::from)
                })
                .collect::<Result<_, BatchConversionError>>()?,
            partial_block_chain: PartialBlockchain::read_from_bytes(&response.partial_block_chain)
                .map_err(|source| {
                    ProtoConversionError::deserialization_error("PartialBlockchain", source)
                })?,
        };

        Ok(result)
    }
}
