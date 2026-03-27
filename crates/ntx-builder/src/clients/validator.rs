use std::time::Duration;

use miden_node_proto::clients::{Builder, ValidatorClient as InnerValidatorClient};
use miden_node_proto::generated::{self as proto};
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_protocol::utils::serde::Serializable;
use tonic::Status;
use tracing::{info, instrument};
use url::Url;

use crate::COMPONENT;

// CLIENT
// ================================================================================================

/// Interface to the validator's gRPC API.
///
/// Thin wrapper around the generated gRPC client which encapsulates the connection
/// configuration and improves type safety. Cloning this client shares the underlying
/// gRPC channel.
#[derive(Clone, Debug)]
pub struct ValidatorClient {
    client: InnerValidatorClient,
}

impl ValidatorClient {
    /// Creates a new validator client with a lazy connection and a 10-second timeout.
    pub fn new(validator_url: Url) -> Self {
        info!(target: COMPONENT, validator_endpoint = %validator_url, "Initializing validator client with lazy connection");

        let validator = Builder::new(validator_url)
            .without_tls()
            .with_timeout(Duration::from_secs(10))
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<InnerValidatorClient>();

        Self { client: validator }
    }

    /// Submits a proven transaction with its inputs to the validator for re-execution.
    #[instrument(target = COMPONENT, name = "ntx.validator.client.submit_proven_transaction", skip_all, err)]
    pub async fn submit_proven_transaction(
        &self,
        proven_tx: &ProvenTransaction,
        tx_inputs: &TransactionInputs,
    ) -> Result<(), Status> {
        let request = proto::transaction::ProvenTransaction {
            transaction: proven_tx.to_bytes(),
            transaction_inputs: Some(tx_inputs.to_bytes()),
        };
        self.client.clone().submit_proven_transaction(request).await?;
        Ok(())
    }
}
