use std::time::Duration;

use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated as proto;
use miden_protocol::Word;
use miden_protocol::block::ProposedBlock;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::utils::serde::Serializable;
use thiserror::Error;
use tracing::{info, instrument};
use url::Url;

use crate::COMPONENT;

// VALIDATOR ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum ValidatorError {
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::Status),
    #[error("failed to convert block signature response: {0}")]
    Conversion(#[from] ConversionError),
}

// VALIDATOR CLIENT
// ================================================================================================

/// Interface to the validator's gRPC API.
///
/// Essentially just a thin wrapper around the generated gRPC client which improves type safety.
#[derive(Clone, Debug)]
pub struct BlockProducerValidatorClient {
    client: ValidatorClient,
}

impl BlockProducerValidatorClient {
    /// Creates a new validator client with a lazy connection.
    ///
    /// `timeout` bounds each request (notably `sign_block`) so that a silently dropped validator
    /// connection surfaces as a fast, retryable error instead of hanging on the OS-level TCP
    /// timeout and halting block production.
    pub fn new(validator_url: Url, timeout: Duration) -> anyhow::Result<Self> {
        info!(target: COMPONENT, validator_endpoint = %validator_url, "Initializing validator client");

        let validator = Builder::new(validator_url)
            .with_tls()?
            .with_timeout(timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>();

        Ok(Self { client: validator })
    }

    /// Signs the proposed block via the validator, returning the signature and the block commitment
    /// that the validator reports it signed (for cross-checking against the locally built block).
    #[instrument(target = COMPONENT, name = "validator.client.validate_block", skip_all, err)]
    pub async fn sign_block(
        &self,
        proposed_block: ProposedBlock,
    ) -> Result<(Signature, Word), ValidatorError> {
        // Send request and receive response.
        let message = proto::blockchain::ProposedBlock {
            proposed_block: proposed_block.to_bytes(),
        };
        let request = tonic::Request::new(message);
        let response = self.client.clone().sign_block(request).await?.into_inner();

        // Deserialize the signature and the signed block commitment.
        let signature: Signature = response
            .signature
            .ok_or_else(|| {
                ConversionError::missing_field::<proto::blockchain::SignBlockResponse>("signature")
            })?
            .try_into()?;
        let block_commitment = response
            .block_commitment
            .ok_or_else(|| {
                ConversionError::missing_field::<proto::blockchain::SignBlockResponse>(
                    "block_commitment",
                )
            })?
            .try_into()?;

        Ok((signature, block_commitment))
    }
}
