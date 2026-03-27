use std::collections::BTreeMap;

use miden_protocol::block::BlockHeader;
use miden_protocol::note::{NoteId, NoteInclusionProof};
use miden_protocol::transaction::PartialBlockchain;
use miden_protocol::utils::serde::Serializable;

use crate::errors::{ConversionError, ConversionResultExt, DecodeBytesExt, GrpcDecodeExt};
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
        let decoder = response.decoder();
        let result = Self {
            batch_reference_block_header: decoder
                .decode_field("block_header", response.batch_reference_block_header)?,
            note_proofs: response
                .note_proofs
                .iter()
                .map(<(NoteId, NoteInclusionProof)>::try_from)
                .collect::<Result<_, ConversionError>>()
                .context("note_proofs")?,
            partial_block_chain: PartialBlockchain::decode_bytes(
                &response.partial_block_chain,
                "PartialBlockchain",
            )?,
        };

        Ok(result)
    }
}
