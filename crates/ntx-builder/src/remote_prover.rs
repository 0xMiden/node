use std::sync::Arc;
use std::time::Duration;

use miden_node_proto::generated::remote_prover::api_client::ApiClient;
use miden_node_proto::generated::remote_prover::{self as proto};
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_protocol::utils::{Deserializable, Serializable};
use miden_protocol::vm::FutureMaybeSend;
use miden_tx::TransactionProverError;
use tokio::sync::Mutex;

// REMOTE TRANSACTION PROVER
// ================================================================================================

/// A transaction prover that sends witness data to a remote gRPC server and receives a proven
/// transaction.
#[derive(Clone)]
pub struct RemoteTransactionProver {
    client: Arc<Mutex<Option<ApiClient<tonic::transport::Channel>>>>,
    endpoint: String,
    timeout: Duration,
}

impl RemoteTransactionProver {
    /// Creates a new [`RemoteTransactionProver`] with the specified gRPC server endpoint.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: Arc::new(Mutex::new(None)),
            timeout: Duration::from_secs(10),
        }
    }

    /// Establishes a connection to the remote transaction prover server.
    async fn connect(&self) -> Result<(), TransactionProverError> {
        let mut client = self.client.lock().await;
        if client.is_some() {
            return Ok(());
        }

        let endpoint = tonic::transport::Endpoint::try_from(self.endpoint.clone())
            .map_err(|err| TransactionProverError::other_with_source("invalid endpoint", err))?
            .timeout(self.timeout);
        let channel = endpoint
            .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
            .map_err(|err| {
                TransactionProverError::other_with_source("failed to configure TLS", err)
            })?
            .connect()
            .await
            .map_err(|err| {
                TransactionProverError::other_with_source("failed to connect to remote prover", err)
            })?;

        *client = Some(ApiClient::new(channel));
        Ok(())
    }

    /// Proves a transaction using the remote prover.
    pub fn prove(
        &self,
        tx_inputs: &TransactionInputs,
    ) -> impl FutureMaybeSend<Result<ProvenTransaction, TransactionProverError>> {
        let tx_inputs_bytes = tx_inputs.to_bytes();
        let this = self.clone();

        async move {
            this.connect().await?;

            let mut client = this
                .client
                .lock()
                .await
                .clone()
                .ok_or_else(|| TransactionProverError::other("client should be connected"))?;

            let request = tonic::Request::new(proto::ProofRequest {
                proof_type: proto::ProofType::Transaction.into(),
                payload: tx_inputs_bytes,
            });

            let response = client.prove(request).await.map_err(|err| {
                TransactionProverError::other_with_source("failed to prove transaction", err)
            })?;

            let proven_transaction = ProvenTransaction::read_from_bytes(
                &response.into_inner().payload,
            )
            .map_err(|_| {
                TransactionProverError::other(
                    "failed to deserialize response from remote transaction prover",
                )
            })?;

            Ok(proven_transaction)
        }
    }
}
