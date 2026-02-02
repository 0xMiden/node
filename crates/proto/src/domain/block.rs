use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use miden_protocol::account::AccountId;
use miden_protocol::block::nullifier_tree::NullifierWitness;
use miden_protocol::block::{
    BlockBody,
    BlockHeader,
    BlockInputs,
    BlockNumber,
    FeeParameters,
    SignedBlock,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::note::{NoteId, NoteInclusionProof};
use miden_protocol::transaction::PartialBlockchain;
use miden_protocol::utils::{Deserializable, Serializable};
use thiserror::Error;

use crate::errors::{ConversionError, MissingFieldHelper};
use crate::{AccountWitnessRecord, NullifierWitnessRecord, generated as proto};

// BLOCK NUMBER
// ================================================================================================

impl From<BlockNumber> for proto::blockchain::BlockNumber {
    fn from(value: BlockNumber) -> Self {
        proto::blockchain::BlockNumber { block_num: value.as_u32() }
    }
}

impl From<proto::blockchain::BlockNumber> for BlockNumber {
    fn from(value: proto::blockchain::BlockNumber) -> Self {
        BlockNumber::from(value.block_num)
    }
}

// BLOCK HEADER
// ================================================================================================

impl From<&BlockHeader> for proto::blockchain::BlockHeader {
    fn from(header: &BlockHeader) -> Self {
        Self {
            version: header.version(),
            prev_block_commitment: Some(header.prev_block_commitment().into()),
            block_num: header.block_num().as_u32(),
            chain_commitment: Some(header.chain_commitment().into()),
            account_root: Some(header.account_root().into()),
            nullifier_root: Some(header.nullifier_root().into()),
            note_root: Some(header.note_root().into()),
            tx_commitment: Some(header.tx_commitment().into()),
            tx_kernel_commitment: Some(header.tx_kernel_commitment().into()),
            validator_key: Some(header.validator_key().into()),
            timestamp: header.timestamp(),
            fee_parameters: Some(header.fee_parameters().into()),
        }
    }
}

impl From<BlockHeader> for proto::blockchain::BlockHeader {
    fn from(header: BlockHeader) -> Self {
        (&header).into()
    }
}

impl TryFrom<&proto::blockchain::BlockHeader> for BlockHeader {
    type Error = ConversionError;

    fn try_from(value: &proto::blockchain::BlockHeader) -> Result<Self, Self::Error> {
        value.try_into()
    }
}

impl TryFrom<proto::blockchain::BlockHeader> for BlockHeader {
    type Error = ConversionError;

    fn try_from(value: proto::blockchain::BlockHeader) -> Result<Self, Self::Error> {
        Ok(BlockHeader::new(
            value.version,
            value
                .prev_block_commitment
                .ok_or(proto::blockchain::BlockHeader::missing_field(stringify!(
                    prev_block_commitment
                )))?
                .try_into()?,
            value.block_num.into(),
            value
                .chain_commitment
                .ok_or(proto::blockchain::BlockHeader::missing_field(stringify!(chain_commitment)))?
                .try_into()?,
            value
                .account_root
                .ok_or(proto::blockchain::BlockHeader::missing_field(stringify!(account_root)))?
                .try_into()?,
            value
                .nullifier_root
                .ok_or(proto::blockchain::BlockHeader::missing_field(stringify!(nullifier_root)))?
                .try_into()?,
            value
                .note_root
                .ok_or(proto::blockchain::BlockHeader::missing_field(stringify!(note_root)))?
                .try_into()?,
            value
                .tx_commitment
                .ok_or(proto::blockchain::BlockHeader::missing_field(stringify!(tx_commitment)))?
                .try_into()?,
            value
                .tx_kernel_commitment
                .ok_or(proto::blockchain::BlockHeader::missing_field(stringify!(
                    tx_kernel_commitment
                )))?
                .try_into()?,
            value
                .validator_key
                .ok_or(proto::blockchain::BlockHeader::missing_field(stringify!(validator_key)))?
                .try_into()?,
            FeeParameters::try_from(value.fee_parameters.ok_or(
                proto::blockchain::FeeParameters::missing_field(stringify!(fee_parameters)),
            )?)?,
            value.timestamp,
        ))
    }
}

// BLOCK BODY
// ================================================================================================

impl From<&BlockBody> for proto::blockchain::BlockBody {
    fn from(body: &BlockBody) -> Self {
        Self { block_body: body.to_bytes() }
    }
}

impl From<BlockBody> for proto::blockchain::BlockBody {
    fn from(body: BlockBody) -> Self {
        (&body).into()
    }
}

impl TryFrom<&proto::blockchain::BlockBody> for BlockBody {
    type Error = ConversionError;

    fn try_from(value: &proto::blockchain::BlockBody) -> Result<Self, Self::Error> {
        value.try_into()
    }
}

impl TryFrom<proto::blockchain::BlockBody> for BlockBody {
    type Error = ConversionError;
    fn try_from(value: proto::blockchain::BlockBody) -> Result<Self, Self::Error> {
        BlockBody::read_from_bytes(&value.block_body)
            .map_err(|source| ConversionError::deserialization_error("BlockBody", source))
    }
}

// SIGNED BLOCK
// ================================================================================================

impl From<&SignedBlock> for proto::blockchain::SignedBlock {
    fn from(block: &SignedBlock) -> Self {
        Self {
            header: Some(block.header().into()),
            body: Some(block.body().into()),
            signature: Some(block.signature().into()),
        }
    }
}

impl From<SignedBlock> for proto::blockchain::SignedBlock {
    fn from(block: SignedBlock) -> Self {
        (&block).into()
    }
}

impl TryFrom<&proto::blockchain::SignedBlock> for SignedBlock {
    type Error = ConversionError;

    fn try_from(value: &proto::blockchain::SignedBlock) -> Result<Self, Self::Error> {
        value.try_into()
    }
}

impl TryFrom<proto::blockchain::SignedBlock> for SignedBlock {
    type Error = ConversionError;
    fn try_from(value: proto::blockchain::SignedBlock) -> Result<Self, Self::Error> {
        let header = value
            .header
            .ok_or(proto::blockchain::SignedBlock::missing_field(stringify!(header)))?
            .try_into()?;
        let body = value
            .body
            .ok_or(proto::blockchain::SignedBlock::missing_field(stringify!(body)))?
            .try_into()?;
        let signature = value
            .signature
            .ok_or(proto::blockchain::SignedBlock::missing_field(stringify!(signature)))?
            .try_into()?;

        Ok(SignedBlock::new_unchecked(header, body, signature))
    }
}

// BLOCK INPUTS
// ================================================================================================

impl From<BlockInputs> for proto::store::BlockInputs {
    fn from(inputs: BlockInputs) -> Self {
        let (
            prev_block_header,
            partial_block_chain,
            account_witnesses,
            nullifier_witnesses,
            unauthenticated_note_proofs,
        ) = inputs.into_parts();

        proto::store::BlockInputs {
            latest_block_header: Some(prev_block_header.into()),
            account_witnesses: account_witnesses
                .into_iter()
                .map(|(id, witness)| AccountWitnessRecord { account_id: id, witness }.into())
                .collect(),
            nullifier_witnesses: nullifier_witnesses
                .into_iter()
                .map(|(nullifier, witness)| {
                    let proof = witness.into_proof();
                    NullifierWitnessRecord { nullifier, proof }.into()
                })
                .collect(),
            partial_block_chain: partial_block_chain.to_bytes(),
            unauthenticated_note_proofs: unauthenticated_note_proofs
                .iter()
                .map(proto::note::NoteInclusionInBlockProof::from)
                .collect(),
        }
    }
}

impl TryFrom<proto::store::BlockInputs> for BlockInputs {
    type Error = ConversionError;

    fn try_from(response: proto::store::BlockInputs) -> Result<Self, Self::Error> {
        let latest_block_header: BlockHeader = response
            .latest_block_header
            .ok_or(proto::blockchain::BlockHeader::missing_field("block_header"))?
            .try_into()?;

        let account_witnesses = response
            .account_witnesses
            .into_iter()
            .map(|entry| {
                let witness_record: AccountWitnessRecord = entry.try_into()?;
                Ok((witness_record.account_id, witness_record.witness))
            })
            .collect::<Result<BTreeMap<_, _>, ConversionError>>()?;

        let nullifier_witnesses = response
            .nullifier_witnesses
            .into_iter()
            .map(|entry| {
                let witness: NullifierWitnessRecord = entry.try_into()?;
                Ok((witness.nullifier, NullifierWitness::new(witness.proof)))
            })
            .collect::<Result<BTreeMap<_, _>, ConversionError>>()?;

        let unauthenticated_note_proofs = response
            .unauthenticated_note_proofs
            .iter()
            .map(<(NoteId, NoteInclusionProof)>::try_from)
            .collect::<Result<_, ConversionError>>()?;

        let partial_block_chain = PartialBlockchain::read_from_bytes(&response.partial_block_chain)
            .map_err(|source| {
                ConversionError::deserialization_error("PartialBlockchain", source)
            })?;

        Ok(BlockInputs::new(
            latest_block_header,
            partial_block_chain,
            account_witnesses,
            nullifier_witnesses,
            unauthenticated_note_proofs,
        ))
    }
}

// PUBLIC KEY
// ================================================================================================

impl TryFrom<proto::blockchain::ValidatorPublicKey> for PublicKey {
    type Error = ConversionError;
    fn try_from(public_key: proto::blockchain::ValidatorPublicKey) -> Result<Self, Self::Error> {
        PublicKey::read_from_bytes(&public_key.validator_key)
            .map_err(|source| ConversionError::deserialization_error("PublicKey", source))
    }
}

impl From<PublicKey> for proto::blockchain::ValidatorPublicKey {
    fn from(value: PublicKey) -> Self {
        Self::from(&value)
    }
}

impl From<&PublicKey> for proto::blockchain::ValidatorPublicKey {
    fn from(value: &PublicKey) -> Self {
        Self { validator_key: value.to_bytes() }
    }
}

// SIGNATURE
// ================================================================================================

impl TryFrom<proto::blockchain::BlockSignature> for Signature {
    type Error = ConversionError;
    fn try_from(signature: proto::blockchain::BlockSignature) -> Result<Self, Self::Error> {
        Signature::read_from_bytes(&signature.signature)
            .map_err(|source| ConversionError::deserialization_error("Signature", source))
    }
}

impl From<Signature> for proto::blockchain::BlockSignature {
    fn from(value: Signature) -> Self {
        Self::from(&value)
    }
}

impl From<&Signature> for proto::blockchain::BlockSignature {
    fn from(value: &Signature) -> Self {
        Self { signature: value.to_bytes() }
    }
}

// FEE PARAMETERS
// ================================================================================================

impl TryFrom<proto::blockchain::FeeParameters> for FeeParameters {
    type Error = ConversionError;
    fn try_from(fee_params: proto::blockchain::FeeParameters) -> Result<Self, Self::Error> {
        let native_asset_id = fee_params.native_asset_id.map(AccountId::try_from).ok_or(
            proto::blockchain::FeeParameters::missing_field(stringify!(native_asset_id)),
        )??;
        let fee_params = FeeParameters::new(native_asset_id, fee_params.verification_base_fee)?;
        Ok(fee_params)
    }
}

impl From<FeeParameters> for proto::blockchain::FeeParameters {
    fn from(value: FeeParameters) -> Self {
        Self::from(&value)
    }
}

impl From<&FeeParameters> for proto::blockchain::FeeParameters {
    fn from(value: &FeeParameters) -> Self {
        Self {
            native_asset_id: Some(value.native_asset_id().into()),
            verification_base_fee: value.verification_base_fee(),
        }
    }
}

// BLOCK RANGE
// ================================================================================================

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum InvalidBlockRange {
    #[error("start ({start}) greater than end ({end})")]
    StartGreaterThanEnd { start: BlockNumber, end: BlockNumber },
    #[error("empty range: start ({start})..end ({end})")]
    EmptyRange { start: BlockNumber, end: BlockNumber },
}

impl proto::rpc::BlockRange {
    /// Converts the block range into an inclusive range, using the fallback block number if the
    /// block to is not specified.
    pub fn into_inclusive_range<T: From<InvalidBlockRange>>(
        self,
        fallback: &BlockNumber,
    ) -> Result<RangeInclusive<BlockNumber>, T> {
        let block_range = RangeInclusive::new(
            self.block_from.into(),
            self.block_to.map_or(*fallback, BlockNumber::from),
        );

        if block_range.start() > block_range.end() {
            return Err(InvalidBlockRange::StartGreaterThanEnd {
                start: *block_range.start(),
                end: *block_range.end(),
            }
            .into());
        }

        if block_range.is_empty() {
            return Err(InvalidBlockRange::EmptyRange {
                start: *block_range.start(),
                end: *block_range.end(),
            }
            .into());
        }

        Ok(block_range)
    }
}

impl From<RangeInclusive<BlockNumber>> for proto::rpc::BlockRange {
    fn from(range: RangeInclusive<BlockNumber>) -> Self {
        Self {
            block_from: range.start().as_u32(),
            block_to: Some(range.end().as_u32()),
        }
    }
}
