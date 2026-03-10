use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::time::Duration;

use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_protocol::utils::serde::{Deserializable, DeserializationError, Serializable};
use miden_protocol::vm::FutureMaybeSend;
use miden_tx::TransactionProverError;
use tokio::sync::Mutex;

use super::generated::api_client::ApiClient;
use crate::RemoteProverClientError;
use crate::remote_prover::generated as proto;

// REMOTE TRANSACTION PROVER
// ================================================================================================

/// A [`RemoteTransactionProver`] is a transaction prover that sends witness data to a remote
/// gRPC server and receives a proven transaction.
///
/// When compiled for the `wasm32-unknown-unknown` target, it uses the `tonic_web_wasm_client`
/// transport. Otherwise, it uses the built-in `tonic::transport` for native platforms.
///
/// The transport layer connection is established lazily when the first transaction is proven.
#[derive(Clone)]
pub struct RemoteTransactionProver {
    #[cfg(target_arch = "wasm32")]
    client: Arc<Mutex<Option<ApiClient<tonic_web_wasm_client::Client>>>>,

    #[cfg(not(target_arch = "wasm32"))]
    client: Arc<Mutex<Option<ApiClient<tonic::transport::Channel>>>>,

    endpoint: String,
    timeout: Duration,
}

impl RemoteTransactionProver {
    /// Creates a new [`RemoteTransactionProver`] with the specified gRPC server endpoint. The
    /// endpoint should be in the format `{protocol}://{hostname}:{port}`.
    pub fn new(endpoint: impl Into<String>) -> Self {
        RemoteTransactionProver {
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
    /// A new [`RemoteTransactionProver`] instance with the configured timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Establishes a connection to the remote transaction prover server. The connection is
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

impl RemoteTransactionProver {
    pub fn prove(
        &self,
        tx_inputs: &TransactionInputs,
    ) -> impl FutureMaybeSend<Result<ProvenTransaction, TransactionProverError>> {
        async move {
            use miden_protocol::utils::serde::Serializable;
            self.connect().await.map_err(|err| {
                TransactionProverError::other_with_source(
                    "failed to connect to the remote prover",
                    err,
                )
            })?;

            let mut client = self
                .client
                .lock()
                .await
                .as_ref()
                .ok_or_else(|| TransactionProverError::other("client should be connected"))?
                .clone();

            let request = tonic::Request::new(tx_inputs.into());

            let response = client.prove(request).await.map_err(|err| {
                TransactionProverError::other_with_source("failed to prove transaction", err)
            })?;

            // Deserialize the response bytes back into a ProvenTransaction.
            let proven_transaction =
                ProvenTransaction::try_from(response.into_inner()).map_err(|_| {
                    TransactionProverError::other(
                        "failed to deserialize received response from remote transaction prover",
                    )
                })?;

            Ok(proven_transaction)
        }
    }
}

// CONVERSIONS
// ================================================================================================

impl TryFrom<proto::Proof> for ProvenTransaction {
    type Error = DeserializationError;

    fn try_from(response: proto::Proof) -> Result<Self, Self::Error> {
        ProvenTransaction::read_from_bytes(&response.payload)
    }
}

impl From<&TransactionInputs> for proto::ProofRequest {
    fn from(tx_inputs: &TransactionInputs) -> Self {
        proto::ProofRequest {
            proof_type: proto::ProofType::Transaction.into(),
            payload: tx_inputs.to_bytes(),
        }
    }
}
