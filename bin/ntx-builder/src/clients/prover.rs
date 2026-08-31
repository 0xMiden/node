use std::time::Duration;

use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::remote_prover::proof::Proof as ProofVariant;
use miden_node_proto::generated::remote_prover::proof_request::Request;
use miden_node_proto::generated::remote_prover::{Proof, ProofRequest};
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_tx::TransactionProverError;
use url::Url;

/// Thin wrapper around the remote-prover gRPC service that proves transactions.
///
/// The connection is lazy: the underlying channel connects on first use and is shared (cheaply
/// cloned) across all subsequent calls.
#[derive(Clone)]
pub struct RemoteTransactionProver {
    client: RemoteProverClient,
}

impl RemoteTransactionProver {
    /// Creates a new [`RemoteTransactionProver`] with a lazy connection to the given gRPC endpoint.
    pub fn new(url: Url, timeout: Duration) -> anyhow::Result<Self> {
        let client = Builder::new(url)
            .with_tls()?
            .with_timeout(timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect_lazy::<RemoteProverClient>();

        Ok(Self { client })
    }

    pub async fn prove(
        &self,
        tx_inputs: &TransactionInputs,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        let request = tonic::Request::new(ProofRequest {
            request: Some(Request::Transaction(tx_inputs.into())),
        });

        let response = self.client.clone().prove(request).await.map_err(|err| {
            TransactionProverError::other_with_source("failed to prove transaction", err)
        })?;

        decode_transaction_proof(response.into_inner())
    }
}

fn decode_transaction_proof(response: Proof) -> Result<ProvenTransaction, TransactionProverError> {
    let proof = match response.proof {
        Some(ProofVariant::Transaction(proof)) => proof,
        Some(_) => {
            return Err(TransactionProverError::other(
                "remote prover response variant does not match transaction request",
            ));
        },
        None => {
            return Err(TransactionProverError::other(
                "remote prover response is missing proof variant",
            ));
        },
    };

    ProvenTransaction::try_from(proof).map_err(|_| {
        TransactionProverError::other(
            "failed to decode received response from remote transaction prover",
        )
    })
}

#[cfg(test)]
mod response_tests {
    use miden_node_proto::generated::remote_prover::Proof;
    use miden_node_proto::generated::remote_prover::proof::Proof as ProofVariant;

    use super::*;

    #[test]
    fn missing_transaction_response_variant_is_a_protocol_error() {
        let error = decode_transaction_proof(Proof { proof: None }).unwrap_err();

        assert!(error.to_string().contains("missing proof variant"));
    }

    #[test]
    fn mismatched_transaction_response_variant_is_a_protocol_error() {
        let response = Proof {
            proof: Some(ProofVariant::Block(
                miden_node_proto::generated::primitives::ExecutionProof::default(),
            )),
        };
        let error = decode_transaction_proof(response).unwrap_err();

        assert!(error.to_string().contains("does not match transaction request"));
    }
}
