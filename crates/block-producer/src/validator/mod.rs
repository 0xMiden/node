use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::generated as proto;
use miden_protocol::block::ProposedBlock;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::utils::{Deserializable, DeserializationError, Serializable};
use thiserror::Error;
use miden_node_tracing::instrument_with_err_report;
use tracing::info;
use url::Url;

use crate::COMPONENT;

// VALIDATOR ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum ValidatorError {
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::Status),
    #[error("signature deserialization failed: {0}")]
    Deserialization(#[from] DeserializationError),
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
    pub fn new(validator_url: Url) -> Self {
        info!(target: COMPONENT, validator_endpoint = %validator_url, "Initializing validator client");

        let validator = Builder::new(validator_url)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<ValidatorClient>();

        Self { client: validator }
    }

    #[instrument_with_err_report(target = COMPONENT, name = "validator.client.validate_block", skip_all, err)]
    pub async fn sign_block(
        &self,
        proposed_block: ProposedBlock,
    ) -> Result<Signature, ValidatorError> {
        // Send request and receive response.
        let message = proto::blockchain::ProposedBlock {
            proposed_block: proposed_block.to_bytes(),
        };
        let request = tonic::Request::new(message);
        let response = self.client.clone().sign_block(request).await?;

        // Deserialize the signature.
        let signature = response.into_inner();
        Signature::read_from_bytes(&signature.signature).map_err(ValidatorError::Deserialization)
    }
}
