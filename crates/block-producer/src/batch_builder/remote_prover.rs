use std::sync::Arc;

use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::remote_prover::{ProofRequest, ProofType};
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::transaction::{OutputNote, ProvenTransaction};
use miden_protocol::utils::serde::{Deserializable, DeserializationError, Serializable};
use miden_tx_batch::LocalBatchProver;
use url::Url;

/// Errors returned by [`RemoteBatchProver`].
#[derive(Debug, thiserror::Error)]
pub enum RemoteProverError {
    #[error("remote prover request failed")]
    Grpc(#[source] tonic::Status),
    #[error("failed to deserialize proven batch from remote prover")]
    Deserialize(#[source] DeserializationError),
    #[error("{0}")]
    Validation(String),
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
        Self::Local(LocalBatchProver::default())
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
        // Keep the set of transactions we passed in for later validation.
        let proposed_txs: Vec<_> = proposed_batch.transactions().iter().map(Arc::clone).collect();

        let request = tonic::Request::new(ProofRequest {
            proof_type: ProofType::Batch.into(),
            payload: proposed_batch.to_bytes(),
        });

        let response = self.client.clone().prove(request).await.map_err(RemoteProverError::Grpc)?;

        let proven_batch = ProvenBatch::read_from_bytes(&response.into_inner().payload)
            .map_err(RemoteProverError::Deserialize)?;

        Self::validate_tx_headers(&proven_batch, proposed_txs)?;

        Ok(proven_batch)
    }

    /// Validates that the proven batch's transaction headers are consistent with the transactions
    /// passed in the proposed batch.
    ///
    /// Note that we expect all input and output notes from a proposed transaction to be present
    /// in the corresponding header as well, because note erasure doesn't matter for the transaction
    /// itself and we want the original transaction data to be preserved.
    ///
    /// This expects that proposed transactions and batch transactions are in the same order, as
    /// define by `OrderedTransactionHeaders`.
    fn validate_tx_headers(
        proven_batch: &ProvenBatch,
        proposed_txs: Vec<Arc<ProvenTransaction>>,
    ) -> Result<(), RemoteProverError> {
        if proposed_txs.len() != proven_batch.transactions().as_slice().len() {
            return Err(RemoteProverError::Validation(format!(
                "remote prover returned {} transaction headers but {} transactions were passed as part of the proposed batch",
                proven_batch.transactions().as_slice().len(),
                proposed_txs.len()
            )));
        }

        // Because we checked the length matches we can zip the iterators up. We expect the
        // transactions to be in the same order.
        for (proposed_header, proven_header) in
            proposed_txs.into_iter().zip(proven_batch.transactions().as_slice())
        {
            if proven_header.account_id() != proposed_header.account_id() {
                return Err(RemoteProverError::Validation(format!(
                    "transaction header of {} has a different account ID than the proposed transaction",
                    proposed_header.id()
                )));
            }

            if proven_header.initial_state_commitment()
                != proposed_header.account_update().initial_state_commitment()
            {
                return Err(RemoteProverError::Validation(format!(
                    "transaction header of {} has a different initial state commitment than the proposed transaction",
                    proposed_header.id()
                )));
            }

            if proven_header.final_state_commitment()
                != proposed_header.account_update().final_state_commitment()
            {
                return Err(RemoteProverError::Validation(format!(
                    "transaction header of {} has a different final state commitment than the proposed transaction",
                    proposed_header.id()
                )));
            }

            // Check input notes
            let num_notes = proposed_header.input_notes().num_notes();
            if num_notes != proven_header.input_notes().num_notes() {
                return Err(RemoteProverError::Validation(format!(
                    "transaction header of {} has a different number of input notes than the proposed transaction",
                    proposed_header.id()
                )));
            }

            // Because we checked the length matches we can zip the iterators up. We expect the
            // nullifiers to be in the same order.
            for (proposed_nullifier, input_note_commitment) in
                proposed_header.nullifiers().zip(proven_header.input_notes().iter())
            {
                if proposed_nullifier != input_note_commitment.nullifier() {
                    return Err(RemoteProverError::Validation(format!(
                        "transaction header of {} has a different set of input notes than the proposed transaction",
                        proposed_header.id()
                    )));
                }
            }

            // Check output notes
            if proposed_header.output_notes().num_notes() != proven_header.output_notes().len() {
                return Err(RemoteProverError::Validation(format!(
                    "transaction header of {} has a different number of output notes than the proposed transaction",
                    proposed_header.id()
                )));
            }

            // Because we checked the length matches we can zip the iterators up. We expect the note
            // IDs to be in the same order.
            for (proposed_note_id, header_note) in proposed_header
                .output_notes()
                .iter()
                .map(OutputNote::id)
                .zip(proven_header.output_notes().iter())
            {
                if proposed_note_id != header_note.id() {
                    return Err(RemoteProverError::Validation(format!(
                        "transaction header of {} has a different set of input notes than the proposed transaction",
                        proposed_header.id()
                    )));
                }
            }
        }

        Ok(())
    }
}
