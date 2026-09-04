use std::ops::RangeInclusive;

use miden_protocol::block::{
    BlockBody,
    BlockHeader,
    BlockNumber,
    BlockSignatures,
    FeeParameters,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::protocol_config::NextProtocolConfig;
use miden_protocol::utils::serde::Serializable;
use thiserror::Error;

use crate::decode::{ConversionResultExt, DecodeBytesExt, GrpcDecodeExt};
use crate::errors::ConversionError;
use crate::{decode, generated as proto};

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
            version: u32::from(header.version()),
            timestamp: header.timestamp(),
            block_num: header.block_num().as_u32(),
            prev_block_commitment: Some(header.prev_block_commitment().into()),
            chain_commitment: Some(header.chain_commitment().into()),
            account_root: Some(header.account_root().into()),
            nullifier_root: Some(header.nullifier_root().into()),
            note_root: Some(header.note_root().into()),
            tx_commitment: Some(header.tx_commitment().into()),
            validator_config: Some(header.validator_config().into()),
            fee_parameters: Some(header.fee_parameters().into()),
            protocol_config_commitment: Some(header.protocol_config_commitment().into()),
            next_protocol_config: header.next_protocol_config().map(Into::into),
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
        value.clone().try_into()
    }
}

impl TryFrom<proto::blockchain::BlockHeader> for BlockHeader {
    type Error = ConversionError;

    fn try_from(value: proto::blockchain::BlockHeader) -> Result<Self, Self::Error> {
        if value.version != 1 {
            return Err(ConversionError::message(format!(
                "unsupported block version {}",
                value.version
            )));
        }

        let decoder = value.decoder();
        let prev_block_commitment = decode!(decoder, value.prev_block_commitment)?;
        let chain_commitment = decode!(decoder, value.chain_commitment)?;
        let account_root = decode!(decoder, value.account_root)?;
        let nullifier_root = decode!(decoder, value.nullifier_root)?;
        let note_root = decode!(decoder, value.note_root)?;
        let tx_commitment = decode!(decoder, value.tx_commitment)?;
        let validator_config = decode!(decoder, value.validator_config)?;
        let fee_parameters = decode!(decoder, value.fee_parameters)?;
        let protocol_config_commitment = decode!(decoder, value.protocol_config_commitment)?;
        let next_protocol_config = value
            .next_protocol_config
            .map(NextProtocolConfig::try_from)
            .transpose()
            .context("next_protocol_config")?;

        Ok(BlockHeader::new(
            prev_block_commitment,
            value.block_num.into(),
            chain_commitment,
            account_root,
            nullifier_root,
            note_root,
            tx_commitment,
            validator_config,
            fee_parameters,
            protocol_config_commitment,
            next_protocol_config,
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
        BlockBody::decode_bytes(&value.block_body, "BlockBody")
    }
}

// SIGNED BLOCK
// ================================================================================================

impl From<&SignedBlock> for proto::blockchain::SignedBlock {
    fn from(block: &SignedBlock) -> Self {
        Self {
            header: Some(block.header().into()),
            body: Some(block.body().into()),
            signatures: block.signatures().as_signatures().iter().map(Into::into).collect(),
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
        let decoder = value.decoder();
        let header = decode!(decoder, value.header)?;
        let body = decode!(decoder, value.body)?;
        let signatures = value
            .signatures
            .into_iter()
            .map(Signature::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("signatures")?;
        let signatures = BlockSignatures::new(signatures)
            .map_err(ConversionError::new)
            .context("signatures")?;

        Ok(SignedBlock::new_unchecked(header, body, signatures))
    }
}

// PUBLIC KEY
// ================================================================================================

impl TryFrom<proto::blockchain::ValidatorPublicKey> for PublicKey {
    type Error = ConversionError;
    fn try_from(public_key: proto::blockchain::ValidatorPublicKey) -> Result<Self, Self::Error> {
        PublicKey::decode_bytes(&public_key.validator_key, "PublicKey")
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

// VALIDATOR CONFIGURATION
// ================================================================================================

impl TryFrom<proto::blockchain::ValidatorConfig> for ValidatorConfig {
    type Error = ConversionError;

    fn try_from(value: proto::blockchain::ValidatorConfig) -> Result<Self, Self::Error> {
        let keys = value
            .keys
            .into_iter()
            .map(PublicKey::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("keys")?;
        let quorum = u16::try_from(value.quorum).context("quorum")?;

        Self::new(keys, quorum).map_err(ConversionError::new)
    }
}

impl From<ValidatorConfig> for proto::blockchain::ValidatorConfig {
    fn from(value: ValidatorConfig) -> Self {
        Self::from(&value)
    }
}

impl From<&ValidatorConfig> for proto::blockchain::ValidatorConfig {
    fn from(value: &ValidatorConfig) -> Self {
        Self {
            keys: value.keys().iter().map(Into::into).collect(),
            quorum: u32::from(value.quorum()),
        }
    }
}

// NEXT PROTOCOL CONFIGURATION
// ================================================================================================

impl TryFrom<proto::blockchain::NextProtocolConfig> for NextProtocolConfig {
    type Error = ConversionError;

    fn try_from(value: proto::blockchain::NextProtocolConfig) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let protocol_config = decode!(decoder, value.protocol_config)?;

        Self::new(value.effective_from.into(), protocol_config).map_err(ConversionError::new)
    }
}

impl From<NextProtocolConfig> for proto::blockchain::NextProtocolConfig {
    fn from(value: NextProtocolConfig) -> Self {
        Self::from(&value)
    }
}

impl From<&NextProtocolConfig> for proto::blockchain::NextProtocolConfig {
    fn from(value: &NextProtocolConfig) -> Self {
        Self {
            effective_from: value.effective_from().as_u32(),
            protocol_config: Some(value.protocol_config().into()),
        }
    }
}

// SIGNATURE
// ================================================================================================

impl TryFrom<proto::blockchain::BlockSignature> for Signature {
    type Error = ConversionError;
    fn try_from(signature: proto::blockchain::BlockSignature) -> Result<Self, Self::Error> {
        Signature::decode_bytes(&signature.signature, "Signature")
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
        Ok(FeeParameters::new(fee_params.verification_base_fee))
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
    /// Converts the block range into an inclusive range.
    pub fn into_inclusive_range<T: From<InvalidBlockRange>>(
        self,
    ) -> Result<RangeInclusive<BlockNumber>, T> {
        let block_range = RangeInclusive::new(self.block_from.into(), self.block_to.into());

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
            block_to: range.end().as_u32(),
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::protocol_config::NextProtocolConfig;

    use super::*;

    fn header_with_scheduled_upgrade() -> BlockHeader {
        let header = BlockHeader::mock(7, None, None, &[]);
        let next_protocol_config =
            NextProtocolConfig::new(BlockNumber::from(42u32), Word::from([21u32, 22, 23, 24]))
                .unwrap();

        BlockHeader::new(
            header.prev_block_commitment(),
            header.block_num(),
            header.chain_commitment(),
            header.account_root(),
            header.nullifier_root(),
            header.note_root(),
            header.tx_commitment(),
            header.validator_config().clone(),
            header.fee_parameters().clone(),
            header.protocol_config_commitment(),
            Some(next_protocol_config),
            header.timestamp(),
        )
    }

    #[test]
    fn block_header_round_trip_preserves_protocol_configuration() {
        let header = header_with_scheduled_upgrade();

        let encoded: proto::blockchain::BlockHeader = (&header).into();
        let decoded = BlockHeader::try_from(encoded).unwrap();

        assert_eq!(decoded, header);
    }

    #[test]
    fn block_header_rejects_unknown_version() {
        let mut encoded: proto::blockchain::BlockHeader =
            BlockHeader::mock(7, None, None, &[]).into();
        encoded.version = 2;

        let error = BlockHeader::try_from(encoded).unwrap_err();

        assert!(error.to_string().contains("version"));
    }

    #[test]
    fn block_header_rejects_invalid_validator_quorum() {
        let mut encoded: proto::blockchain::BlockHeader =
            BlockHeader::mock(7, None, None, &[]).into();
        encoded.validator_config.as_mut().unwrap().quorum = 0;

        let error = BlockHeader::try_from(encoded).unwrap_err();

        assert!(error.to_string().contains("validator_config"));
    }

    #[test]
    fn block_header_requires_protocol_config_commitment() {
        let mut encoded: proto::blockchain::BlockHeader =
            BlockHeader::mock(7, None, None, &[]).into();
        encoded.protocol_config_commitment = None;

        let error = BlockHeader::try_from(encoded).unwrap_err();

        assert!(error.to_string().contains("protocol_config_commitment"));
    }
}
