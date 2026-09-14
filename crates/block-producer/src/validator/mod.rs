use std::time::Duration;

use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::decode::GrpcDecodeExt;
use miden_node_proto::errors::ConversionError;
use miden_node_proto::{decode, generated as proto};
use miden_node_tracing::{info, miden_instrument};
use miden_protocol::Word;
use miden_protocol::block::{BlockInputs, ProposedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::protocol_config::ProtocolConfig;
use thiserror::Error;
use url::Url;

use crate::{COMPONENT, LOG_TARGET};

// VALIDATOR ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum ValidatorError {
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::Status),
    #[error("failed to convert block signature response: {0}")]
    Conversion(#[from] ConversionError),
}

// SIGN BLOCK RESPONSE
// ================================================================================================

/// A single validator's response to a `sign_block` request.
#[derive(Debug, Clone)]
pub struct SignBlockResponse {
    pub signature: Signature,
    pub block_commitment: Word,
    pub public_key: PublicKey,
}

// VALIDATOR CLIENT
// ================================================================================================

/// Interface to the block producer's fan-out over all configured validators' gRPC APIs.
///
/// Essentially just a thin wrapper around the generated gRPC clients which improves type safety.
#[derive(Clone, Debug)]
pub struct BlockProducerValidatorClient {
    clients: Vec<ValidatorClient>,
}

impl BlockProducerValidatorClient {
    /// Creates a new validator client with lazy connections to every configured validator.
    ///
    /// `timeout` bounds each request (notably `sign_block`) so that a silently dropped validator
    /// connection surfaces as a fast, retryable error instead of hanging on the OS-level TCP
    /// timeout and halting block production.
    pub fn new(validator_urls: Vec<Url>, timeout: Duration) -> anyhow::Result<Self> {
        let clients = validator_urls
            .into_iter()
            .map(|validator_url| {
                info!(
                    target: LOG_TARGET,
                    "Initializing validator client",
                    dependency.name = "validator",
                    dependency.endpoint = validator_url.to_string()
                );

                Ok(Builder::new(validator_url)
                    .with_tls()?
                    .with_timeout(timeout)
                    .without_metadata_version()
                    .without_metadata_genesis()
                    .with_otel_context_injection()
                    .connect_lazy::<ValidatorClient>())
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Self { clients })
    }

    /// Signs the proposed block via every validator concurrently, returning each validator's
    /// signature, the block commitment it reports having signed (for cross-checking against the
    /// locally built block), and its public key (so the caller can place the signature at the
    /// correct position in the block's signature set).
    ///
    /// Fails if any validator fails to respond, since every validator in the parent's set must
    /// sign for the block to reach quorum.
    #[miden_instrument(
        target = COMPONENT,
        name = "validator.client.validate_block",
        err,
    )]
    pub async fn sign_block(
        &self,
        proposed_block: &ProposedBlock,
        block_inputs: &BlockInputs,
        protocol_config: &ProtocolConfig,
    ) -> Result<Vec<SignBlockResponse>, ValidatorError> {
        let message = proto::block_proving::BlockProofRequest {
            protocol_config: Some(protocol_config.into()),
            batches: proposed_block.batches().as_slice().iter().map(Into::into).collect(),
            block_inputs: Some(block_inputs.into()),
            timestamp: proposed_block.timestamp(),
            next_validator_config: Some(proposed_block.next_validator_config().into()),
            next_protocol_config: proposed_block.next_protocol_config().map(Into::into),
        };

        let responses = futures::future::try_join_all(self.clients.iter().map(|client| {
            let mut client = client.clone();
            let message = message.clone();
            async move {
                let request = tonic::Request::new(message);
                let response = client.sign_block(request).await?.into_inner();
                Self::decode_response(response)
            }
        }))
        .await?;

        Ok(responses)
    }

    /// Decodes a single validator's `sign_block` response.
    fn decode_response(
        response: proto::validator::SignBlockResponse,
    ) -> Result<SignBlockResponse, ValidatorError> {
        let decoder = response.decoder();
        let signature: Signature = decode!(decoder, response.signature)?;
        let block_commitment = decode!(decoder, response.block_commitment)?;
        let public_key = decode!(decoder, response.public_key)?;

        Ok(SignBlockResponse { signature, block_commitment, public_key })
    }
}
