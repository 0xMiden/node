use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::remote_prover::proof::Proof as ProofVariant;
use miden_node_proto::generated::remote_prover::proof_request::Request;
use miden_node_proto::generated::remote_prover::{Proof, ProofRequest};
use miden_objects::conversion::decode_proven_batch;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_tx_batch::LocalBatchProver;
use url::Url;

/// Errors returned by [`RemoteBatchProver`].
#[derive(Debug, thiserror::Error)]
pub enum RemoteProverError {
    #[error("remote prover request failed")]
    Grpc(#[source] tonic::Status),
    #[error("remote prover returned an invalid batch proof response: {0}")]
    Protocol(String),
    #[error("failed to decode proven batch from remote prover")]
    Conversion(#[source] miden_objects::ConversionError),
}

// BATCH PROVER
// ================================================================================================

/// Represents a batch prover which can be either local or remote.
#[derive(Clone)]
pub(super) enum BatchProver {
    Local(LocalBatchProver),
    Remote(Box<RemoteBatchProver>),
}

impl BatchProver {
    pub(super) const fn kind(&self) -> &'static str {
        match self {
            BatchProver::Local(_) => "local",
            BatchProver::Remote(_) => "remote",
        }
    }

    pub(super) fn local() -> Self {
        Self::Local(LocalBatchProver::new())
    }

    pub(super) fn remote(url: Url) -> anyhow::Result<Self> {
        Ok(Self::Remote(Box::new(RemoteBatchProver::new(url)?)))
    }
}

// REMOTE BATCH PROVER
// ================================================================================================

/// Thin wrapper around the remote-prover gRPC service that proves transaction batches.
///
/// The connection is lazy: the underlying channel connects on first use and is shared (cheaply
/// cloned) across all subsequent calls.
#[derive(Clone)]
pub(super) struct RemoteBatchProver {
    client: RemoteProverClient,
}

impl RemoteBatchProver {
    /// Creates a new [`RemoteBatchProver`] with a lazy connection to the given gRPC endpoint.
    fn new(url: Url) -> anyhow::Result<Self> {
        let client = Builder::new(url)
            .with_tls()?
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect_lazy::<RemoteProverClient>();

        Ok(Self { client })
    }

    pub(super) async fn prove(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, RemoteProverError> {
        let request = tonic::Request::new(ProofRequest {
            request: Some(Request::Batch((&proposed_batch).into())),
        });

        let response = self.client.clone().prove(request).await.map_err(RemoteProverError::Grpc)?;
        let proof = extract_batch_proof(response.into_inner())?;

        decode_proven_batch(proof, &proposed_batch).map_err(RemoteProverError::Conversion)
    }
}

fn extract_batch_proof(
    response: Proof,
) -> Result<miden_objects::proto::transaction::ProvenBatch, RemoteProverError> {
    match response.proof {
        Some(ProofVariant::Batch(proof)) => Ok(proof),
        Some(_) => Err(RemoteProverError::Protocol(
            "response variant does not match batch request".to_string(),
        )),
        None => {
            Err(RemoteProverError::Protocol("response is missing the proof variant".to_string()))
        },
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn missing_batch_response_variant_is_a_protocol_error() {
        let error = extract_batch_proof(Proof { proof: None }).unwrap_err();

        assert!(matches!(error, RemoteProverError::Protocol(_)));
    }

    #[test]
    fn mismatched_batch_response_variant_is_a_protocol_error() {
        let response = Proof {
            proof: Some(ProofVariant::Transaction(
                miden_node_proto::generated::transaction::ProvenTransactionData::default(),
            )),
        };
        let error = extract_batch_proof(response).unwrap_err();

        assert!(matches!(error, RemoteProverError::Protocol(_)));
    }
}
