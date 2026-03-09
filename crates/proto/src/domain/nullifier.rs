use miden_protocol::Word;
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_protocol::note::Nullifier;
use thiserror::Error;

use crate::domain::digest::DigestConversionError;
use crate::domain::merkle::MerkleConversionError;
use crate::errors::{MissingFieldHelper, ProtoConversionError};
use crate::generated as proto;

// NULLIFIER CONVERSION ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum NullifierConversionError {
    #[error(transparent)]
    Proto(#[from] ProtoConversionError),
    #[error(transparent)]
    Digest(#[from] DigestConversionError),
    #[error(transparent)]
    Merkle(#[from] MerkleConversionError),
}

impl From<NullifierConversionError> for tonic::Status {
    fn from(value: NullifierConversionError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}

// FROM NULLIFIER
// ================================================================================================

impl From<&Nullifier> for proto::primitives::Digest {
    fn from(value: &Nullifier) -> Self {
        value.as_word().into()
    }
}

impl From<Nullifier> for proto::primitives::Digest {
    fn from(value: Nullifier) -> Self {
        value.as_word().into()
    }
}

// INTO NULLIFIER
// ================================================================================================

impl TryFrom<proto::primitives::Digest> for Nullifier {
    type Error = DigestConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        let digest: Word = value.try_into()?;
        Ok(Nullifier::from_raw(digest))
    }
}

// NULLIFIER WITNESS RECORD
// ================================================================================================

#[derive(Clone, Debug)]
pub struct NullifierWitnessRecord {
    pub nullifier: Nullifier,
    pub proof: SmtProof,
}

impl TryFrom<proto::store::block_inputs::NullifierWitness> for NullifierWitnessRecord {
    type Error = NullifierConversionError;

    fn try_from(
        nullifier_witness_record: proto::store::block_inputs::NullifierWitness,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            nullifier: nullifier_witness_record
                .nullifier
                .ok_or(proto::store::block_inputs::NullifierWitness::missing_field(stringify!(
                    nullifier
                )))?
                .try_into()
                .map_err(NullifierConversionError::from)?,
            proof: nullifier_witness_record
                .opening
                .ok_or(proto::store::block_inputs::NullifierWitness::missing_field(stringify!(
                    opening
                )))?
                .try_into()?,
        })
    }
}

impl From<NullifierWitnessRecord> for proto::store::block_inputs::NullifierWitness {
    fn from(value: NullifierWitnessRecord) -> Self {
        Self {
            nullifier: Some(value.nullifier.into()),
            opening: Some(value.proof.into()),
        }
    }
}
