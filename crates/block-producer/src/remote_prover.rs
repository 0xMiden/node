use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::generated::remote_prover::api_client::ApiClient;
use miden_node_proto::generated::remote_prover::{self as proto};
use miden_protocol::batch::{OrderedBatches, ProposedBatch, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockInputs, BlockProof, ProposedBlock};
use miden_protocol::transaction::{OutputNote, ProvenTransaction};
use miden_protocol::utils::{Deserializable, Serializable};
use thiserror::Error;
use tokio::sync::Mutex;

// REMOTE PROVER ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum RemoteProverError {
    #[error("failed to connect to prover: {0}")]
    Connection(#[source] tonic::transport::Error),

    #[error("failed to prove: {0}")]
    Proving(#[source] tonic::Status),

    #[error("failed to create proposed block: {0}")]
    ProposedBlock(#[source] miden_protocol::errors::ProposedBlockError),

    #[error("failed to deserialize response: {0}")]
    Deserialization(#[source] miden_protocol::utils::DeserializationError),

    #[error("{0}")]
    Validation(String),
}

// REMOTE BATCH PROVER
// ================================================================================================

/// A batch prover that sends proposed batch data to a remote gRPC server and receives a proven
/// batch.
#[derive(Clone)]
pub struct RemoteBatchProver {
    client: Arc<Mutex<Option<ApiClient<tonic::transport::Channel>>>>,
    endpoint: String,
    timeout: Duration,
}

impl RemoteBatchProver {
    /// Creates a new [`RemoteBatchProver`] with the specified gRPC server endpoint.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: Arc::new(Mutex::new(None)),
            timeout: Duration::from_secs(10),
        }
    }

    /// Establishes a connection to the remote batch prover server.
    async fn connect(&self) -> Result<(), RemoteProverError> {
        let mut client = self.client.lock().await;
        if client.is_some() {
            return Ok(());
        }

        let endpoint = tonic::transport::Endpoint::try_from(self.endpoint.clone())
            .map_err(RemoteProverError::Connection)?
            .timeout(self.timeout);
        let channel = endpoint
            .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
            .map_err(RemoteProverError::Connection)?
            .connect()
            .await
            .map_err(RemoteProverError::Connection)?;

        *client = Some(ApiClient::new(channel));
        Ok(())
    }

    /// Proves a proposed batch using the remote prover.
    pub async fn prove(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, RemoteProverError> {
        self.connect().await?;

        let mut client = self
            .client
            .lock()
            .await
            .clone()
            .expect("client should be connected after connect()");

        // Keep track of the proposed transactions for validation.
        let proposed_txs: Vec<_> = proposed_batch.transactions().iter().map(Arc::clone).collect();

        let request = tonic::Request::new(proto::ProofRequest {
            proof_type: proto::ProofType::Batch.into(),
            payload: proposed_batch.to_bytes(),
        });

        let response = client.prove(request).await.map_err(RemoteProverError::Proving)?;

        let proven_batch = ProvenBatch::read_from_bytes(&response.into_inner().payload)
            .map_err(RemoteProverError::Deserialization)?;

        Self::validate_tx_headers(&proven_batch, proposed_txs)?;

        Ok(proven_batch)
    }

    /// Validates that the proven batch's transaction headers are consistent with the transactions
    /// passed in the proposed batch.
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

            for (proposed_note_id, header_note) in proposed_header
                .output_notes()
                .iter()
                .map(OutputNote::id)
                .zip(proven_header.output_notes().iter())
            {
                if proposed_note_id != header_note.id() {
                    return Err(RemoteProverError::Validation(format!(
                        "transaction header of {} has a different set of output notes than the proposed transaction",
                        proposed_header.id()
                    )));
                }
            }
        }

        Ok(())
    }
}

// REMOTE BLOCK PROVER
// ================================================================================================

/// A block prover that sends proposed block data to a remote gRPC server and receives a block
/// proof.
#[derive(Clone)]
pub struct RemoteBlockProver {
    client: Arc<Mutex<Option<ApiClient<tonic::transport::Channel>>>>,
    endpoint: String,
    timeout: Duration,
}

impl RemoteBlockProver {
    /// Creates a new [`RemoteBlockProver`] with the specified gRPC server endpoint.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: Arc::new(Mutex::new(None)),
            timeout: Duration::from_secs(10),
        }
    }

    /// Establishes a connection to the remote block prover server.
    async fn connect(&self) -> Result<(), RemoteProverError> {
        let mut client = self.client.lock().await;
        if client.is_some() {
            return Ok(());
        }

        let endpoint = tonic::transport::Endpoint::try_from(self.endpoint.clone())
            .map_err(RemoteProverError::Connection)?
            .timeout(self.timeout);
        let channel = endpoint
            .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
            .map_err(RemoteProverError::Connection)?
            .connect()
            .await
            .map_err(RemoteProverError::Connection)?;

        *client = Some(ApiClient::new(channel));
        Ok(())
    }

    /// Proves a block using the remote prover.
    pub async fn prove(
        &self,
        tx_batches: OrderedBatches,
        block_header: BlockHeader,
        block_inputs: BlockInputs,
    ) -> Result<BlockProof, RemoteProverError> {
        self.connect().await?;

        let mut client = self
            .client
            .lock()
            .await
            .clone()
            .expect("client should be connected after connect()");

        let proposed_block =
            ProposedBlock::new_at(block_inputs, tx_batches.into_vec(), block_header.timestamp())
                .map_err(RemoteProverError::ProposedBlock)?;

        let request = tonic::Request::new(proto::ProofRequest {
            proof_type: proto::ProofType::Block.into(),
            payload: proposed_block.to_bytes(),
        });

        let response = client.prove(request).await.map_err(RemoteProverError::Proving)?;

        let block_proof = BlockProof::read_from_bytes(&response.into_inner().payload)
            .map_err(RemoteProverError::Deserialization)?;

        Ok(block_proof)
    }
}
