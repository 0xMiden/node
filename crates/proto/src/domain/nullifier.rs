use miden_protocol::Word;
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_protocol::note::Nullifier;

use crate::errors::ConversionError;
use crate::generated as proto;

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
    type Error = ConversionError;

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
    type Error = ConversionError;

    fn try_from(
        nullifier_witness_record: proto::store::block_inputs::NullifierWitness,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            nullifier: nullifier_witness_record
                .nullifier
                .ok_or(ConversionError::missing_field::<
                    proto::store::block_inputs::NullifierWitness,
                >(stringify!(nullifier)))?
                .try_into()?,
            proof: nullifier_witness_record
                .opening
                .ok_or(ConversionError::missing_field::<
                    proto::store::block_inputs::NullifierWitness,
                >(stringify!(opening)))?
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
