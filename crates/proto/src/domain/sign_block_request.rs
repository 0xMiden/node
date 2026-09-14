//! Validator signing request conversions.

use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs};
use miden_protocol::protocol_config::ProtocolConfig;

use super::protocol_config::ensure_protocol_config_is_present_and_matches_header;
use crate::errors::ConversionError;
use crate::generated as proto;

/// The domain inputs needed to validate and sign a block.
#[derive(Debug)]
pub struct SignBlockRequest {
    pub tx_batches: OrderedBatches,
    pub block_header: BlockHeader,
    pub block_inputs: BlockInputs,
    pub protocol_config: Option<ProtocolConfig>,
}

impl TryFrom<proto::validator::SignBlockRequest> for SignBlockRequest {
    type Error = ConversionError;

    fn try_from(value: proto::validator::SignBlockRequest) -> Result<Self, Self::Error> {
        let block_inputs = value.block_inputs.ok_or_else(|| {
            ConversionError::missing_field::<proto::validator::SignBlockRequest>("block_inputs")
        })?;
        let next_validator_config = value.next_validator_config.ok_or_else(|| {
            ConversionError::missing_field::<proto::validator::SignBlockRequest>(
                "next_validator_config",
            )
        })?;
        let decoded = super::block_proposal::decode(
            block_inputs,
            value.batches,
            value.timestamp,
            next_validator_config,
            value.next_protocol_config,
        )?;
        let protocol_config = value
            .protocol_config
            .map(|config| {
                ensure_protocol_config_is_present_and_matches_header(
                    Some(config),
                    &decoded.block_header,
                )
            })
            .transpose()?;
        Ok(Self {
            tx_batches: decoded.tx_batches,
            block_header: decoded.block_header,
            block_inputs: decoded.block_inputs,
            protocol_config,
        })
    }
}

impl From<&SignBlockRequest> for proto::validator::SignBlockRequest {
    fn from(value: &SignBlockRequest) -> Self {
        Self {
            batches: value.tx_batches.as_slice().iter().map(Into::into).collect(),
            block_inputs: Some((&value.block_inputs).into()),
            timestamp: value.block_header.timestamp(),
            next_validator_config: Some(value.block_header.validator_config().into()),
            next_protocol_config: value.block_header.next_protocol_config().map(Into::into),
            protocol_config: value.protocol_config.as_ref().map(Into::into),
        }
    }
}

impl From<SignBlockRequest> for proto::validator::SignBlockRequest {
    fn from(value: SignBlockRequest) -> Self {
        Self::from(&value)
    }
}
