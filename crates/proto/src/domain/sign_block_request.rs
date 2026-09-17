//! Validator signing request conversions.

use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs};
use miden_protocol::protocol_config::ProtocolConfig;

use super::protocol_config::verify_protocol_config_commitment;
use crate::errors::{ConversionError, ConversionResultExt};
use crate::{BuildUnchecked, Verify, generated as proto};

/// The domain inputs needed to validate and sign a block.
#[derive(Debug)]
pub struct SignBlockRequest {
    pub tx_batches: OrderedBatches,
    pub block_header: BlockHeader,
    pub block_inputs: BlockInputs,
    pub protocol_config: Option<ProtocolConfig>,
}

impl BuildUnchecked for proto::validator::DecodedSignBlockRequest {
    type Output = SignBlockRequest;
    type Error = ConversionError;

    /// Build the proposal and check any supplied protocol configuration against its header. The
    /// caller must verify the parent and batch proofs and contents before signing.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        // SAFETY: The caller must authenticate the parent and validate batches before signing. The
        // shared proposal constructor checks block witnesses and batch consistency.
        let decoded = proto::block_proving::DecodedBlockProofRequest {
            block_inputs: self.block_inputs,
            batches: self.batches,
            timestamp: self.timestamp,
            next_validator_config: self.next_validator_config,
            next_protocol_config: self.next_protocol_config,
        }
        .build_unchecked()?;
        let protocol_config = self
            .protocol_config
            .map(|config| {
                verify_protocol_config_commitment(
                    config.verify().context("protocol_config")?,
                    &decoded.block_header,
                )
            })
            .transpose()?;
        Ok(SignBlockRequest {
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
