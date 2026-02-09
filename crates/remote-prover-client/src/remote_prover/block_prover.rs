use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use miden_protocol::batch::{OrderedBatches, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockInputs, BlockProof, ProposedBlock, ProvenBlock};
use miden_protocol::transaction::{OrderedTransactionHeaders, TransactionHeader};
use miden_protocol::utils::{Deserializable, DeserializationError, Serializable};
use tokio::sync::Mutex;

use super::generated::api_client::ApiClient;
use crate::RemoteProverClientError;
use crate::remote_prover::generated as proto;

// REMOTE BLOCK PROVER
// ================================================================================================

/// A [`RemoteBlockProver`] is a block prover that sends a proposed block data to a remote
/// gRPC server and receives a proven block.
///
/// When compiled for the `wasm32-unknown-unknown` target, it uses the `tonic_web_wasm_client`
/// transport. Otherwise, it uses the built-in `tonic::transport` for native platforms.
///
/// The transport layer connection is established lazily when the first transaction is proven.
#[derive(Clone)]
pub struct RemoteBlockProver {
    #[cfg(target_arch = "wasm32")]
    client: Arc<Mutex<Option<ApiClient<tonic_web_wasm_client::Client>>>>,

    #[cfg(not(target_arch = "wasm32"))]
    client: Arc<Mutex<Option<ApiClient<tonic::transport::Channel>>>>,

    endpoint: String,
    timeout: Duration,
}

impl RemoteBlockProver {
    /// Creates a new [`RemoteBlockProver`] with the specified gRPC server endpoint. The
    /// endpoint should be in the format `{protocol}://{hostname}:{port}`.
    pub fn new(endpoint: impl Into<String>) -> Self {
        RemoteBlockProver {
            endpoint: endpoint.into(),
            client: Arc::new(Mutex::new(None)),
            timeout: Duration::from_secs(10),
        }
    }

    /// Configures the timeout for requests to the remote prover server.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout duration for requests.
    ///
    /// # Returns
    ///
    /// A new [`RemoteBlockProver`] instance with the configured timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Establishes a connection to the remote block prover server. The connection is
    /// maintained for the lifetime of the prover. If the connection is already established, this
    /// method does nothing.
    async fn connect(&self) -> Result<(), RemoteProverClientError> {
        let mut client = self.client.lock().await;
        if client.is_some() {
            return Ok(());
        }

        #[cfg(target_arch = "wasm32")]
        let new_client = {
            let fetch_options =
                tonic_web_wasm_client::options::FetchOptions::new().timeout(self.timeout);
            let web_client = tonic_web_wasm_client::Client::new_with_options(
                self.endpoint.clone(),
                fetch_options,
            );
            ApiClient::new(web_client)
        };

        #[cfg(not(target_arch = "wasm32"))]
        let new_client = {
            let endpoint = tonic::transport::Endpoint::try_from(self.endpoint.clone())
                .map_err(|err| RemoteProverClientError::ConnectionFailed(err.into()))?
                .timeout(self.timeout);
            let channel = endpoint
                .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
                .map_err(|err| RemoteProverClientError::ConnectionFailed(err.into()))?
                .connect()
                .await
                .map_err(|err| RemoteProverClientError::ConnectionFailed(err.into()))?;
            ApiClient::new(channel)
        };

        *client = Some(new_client);

        Ok(())
    }
}

impl RemoteBlockProver {
    pub async fn prove(
        &self,
        tx_batches: OrderedBatches,
        block_header: &BlockHeader,
        block_inputs: BlockInputs,
    ) -> Result<BlockProof, RemoteProverClientError> {
        use miden_protocol::utils::Serializable;
        self.connect().await?;

        let mut client = self
            .client
            .lock()
            .await
            .as_ref()
            .ok_or_else(|| {
                RemoteProverClientError::ConnectionFailed("client should be connected".into())
            })?
            .clone();

        let block_proof_request =
            ProposedBlock::new_at(block_inputs, tx_batches.into_vec(), block_header.timestamp())
                .map_err(|err| {
                    RemoteProverClientError::other_with_source(
                        "failed to create proposed block",
                        err,
                    )
                })?;

        let request = tonic::Request::new(block_proof_request.into());

        let response = client.prove(request).await.map_err(|err| {
            RemoteProverClientError::other_with_source("failed to prove block", err)
        })?;

        // Deserialize the response bytes back into a BlockProof.
        let block_proof = BlockProof::try_from(response.into_inner()).map_err(|err| {
            RemoteProverClientError::other_with_source(
                "failed to deserialize received response from remote block prover",
                err,
            )
        })?;

        Ok(block_proof)
    }
}

// CONVERSION
// ================================================================================================

impl TryFrom<proto::Proof> for BlockProof {
    type Error = DeserializationError;

    fn try_from(value: proto::Proof) -> Result<Self, Self::Error> {
        BlockProof::read_from_bytes(&value.payload)
    }
}

impl From<ProposedBlock> for proto::ProofRequest {
    fn from(proposed_block: ProposedBlock) -> Self {
        proto::ProofRequest {
            proof_type: proto::ProofType::Block.into(),
            payload: proposed_block.to_bytes(),
        }
    }
}
