//! Validator signing request conversions.

use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockBody, BlockHeader, BlockInputs};
use miden_protocol::protocol_config::ProtocolConfig;

use super::protocol_config::verify_protocol_config_commitment;
use crate::errors::ConversionError;
use crate::{BlockProofRequest, BuildUnchecked, Verify, generated as proto};

/// The domain inputs needed to validate and sign a block.
#[derive(Debug)]
pub struct SignBlockRequest {
    pub tx_batches: OrderedBatches,
    pub block_header: BlockHeader,
    pub block_inputs: BlockInputs,
    pub protocol_config: Option<ProtocolConfig>,
}

impl BuildUnchecked for proto::miden::validator::v1::DecodedSignBlockRequest {
    type Output = SignBlockRequest;
    type Error = ConversionError;

    /// Build the proposal and check any supplied protocol configuration against its header. The
    /// caller must verify the parent and batch proofs and contents before signing.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let BlockSigningInputs { proving_inputs, protocol_config, .. } =
            self.build_with_body_unchecked()?;
        Ok(SignBlockRequest {
            tx_batches: proving_inputs.tx_batches,
            block_header: proving_inputs.block_header,
            block_inputs: proving_inputs.block_inputs,
            protocol_config,
        })
    }
}

/// A reconstructed candidate block and the inputs retained for proving.
#[derive(Debug)]
pub struct BlockSigningInputs {
    pub proving_inputs: BlockProofRequest,
    pub body: BlockBody,
    pub protocol_config: Option<ProtocolConfig>,
}

impl proto::miden::validator::v1::DecodedSignBlockRequest {
    /// Builds the header and body together and checks the supplied active configuration.
    ///
    /// The caller must authenticate the parent and validate the batch proofs and contents.
    pub fn build_with_body_unchecked(self) -> Result<BlockSigningInputs, ConversionError> {
        // SAFETY: The caller must authenticate the parent and validate batches before signing. The
        // shared proposal constructor checks block witnesses and batch consistency.
        let (proving_inputs, body) = proto::block_proving::DecodedBlockProofRequest {
            block_inputs: self.block_inputs,
            batches: self.batches,
            timestamp: self.timestamp,
            next_validator_config: self.next_validator_config,
            next_protocol_config: self.next_protocol_config,
        }
        .build_with_body_unchecked()?;
        let protocol_config = self.protocol_config.try_map(|config| {
            verify_protocol_config_commitment(
                config.verify().map_err(ConversionError::new)?,
                &proving_inputs.block_header,
            )
        })?;
        Ok(BlockSigningInputs { proving_inputs, body, protocol_config })
    }
}

impl From<&SignBlockRequest> for proto::miden::validator::v1::SignBlockRequest {
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

impl From<SignBlockRequest> for proto::miden::validator::v1::SignBlockRequest {
    fn from(value: SignBlockRequest) -> Self {
        Self::from(&value)
    }
}
