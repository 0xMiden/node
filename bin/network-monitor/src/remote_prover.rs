//! Remote transaction prover test functionality.
//!
//! This module contains the logic for periodically testing remote transaction prover functionality
//! by sending mock transactions and checking for successful transaction proof generation.

use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::{Builder as ClientBuilder, RemoteProverClient};
use miden_node_proto::generated as proto;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::TransactionInputs;
use miden_testing::{Auth, MockChainBuilder};
use miden_tx::utils::Serializable;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tonic::Request;
use tracing::{info, instrument};
use url::Url;

use crate::status::{ServiceDetails, ServiceStatus, Status};
use crate::{COMPONENT, current_unix_timestamp_secs};

// PROOF TYPE
// ================================================================================================

/// Remote prover types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofType {
    Transaction,
    Block,
    Batch,
}

impl From<ProofType> for proto::remote_prover::ProofType {
    fn from(value: ProofType) -> Self {
        match value {
            ProofType::Transaction => proto::remote_prover::ProofType::Transaction,
            ProofType::Block => proto::remote_prover::ProofType::Block,
            ProofType::Batch => proto::remote_prover::ProofType::Batch,
        }
    }
}

impl From<proto::remote_prover::ProofType> for ProofType {
    fn from(value: proto::remote_prover::ProofType) -> Self {
        match value {
            proto::remote_prover::ProofType::Transaction => ProofType::Transaction,
            proto::remote_prover::ProofType::Batch => ProofType::Batch,
            proto::remote_prover::ProofType::Block => ProofType::Block,
        }
    }
}

// REMOTE PROVER TEST TYPES
// ================================================================================================

/// Details of a remote transaction prover test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverTestDetails {
    pub test_duration_ms: u64,
    pub proof_size_bytes: usize,
    pub success_count: u64,
    pub failure_count: u64,
    pub proof_type: ProofType,
}

// REMOTE TRANSACTION PROVER TEST TASK
// ================================================================================================

/// Runs a task that continuously tests remote prover functionality and updates a watch channel.
///
/// This function spawns a task that periodically sends mock request payloads to a remote prover
/// and measures the success/failure rate and performance metrics for proof generation.
///
/// # Arguments
///
/// * `prover_url` - The URL of the remote prover service to test.
/// * `name` - The name of the remote prover.
/// * `proof_type` - The type of proof to test.
/// * `serialized_request_payload` - The serialized request payload to send to the remote prover.
/// * `status_sender` - The sender for the watch channel.
///
/// # Returns
///
/// `Ok(())` if the task completes successfully, or an error if the task fails.
pub async fn run_remote_prover_test_task(
    prover_url: Url,
    name: &str,
    proof_type: ProofType,
    serialized_request_payload: proto::remote_prover::ProofRequest,
    status_sender: watch::Sender<ServiceStatus>,
    request_timeout: Duration,
    test_interval: Duration,
) {
    let mut client = ClientBuilder::new(prover_url)
        .with_tls()
        .expect("TLS is enabled")
        .with_timeout(request_timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<RemoteProverClient>();

    let mut interval = tokio::time::interval(test_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut success_count = 0u64;
    let mut failure_count = 0u64;

    loop {
        interval.tick().await;

        let current_time = current_unix_timestamp_secs();

        let status = test_remote_prover(
            &mut client,
            name,
            &proof_type,
            &serialized_request_payload,
            current_time,
            &mut success_count,
            &mut failure_count,
        )
        .await;

        // Send the status update; exit if no receivers (shutdown signal)
        if status_sender.send(status).is_err() {
            info!("No receivers for remote prover status updates, shutting down");
            return;
        }
    }
}

/// Tests the remote prover by sending a mock request payload.
///
/// This function sends a mock request payload to the remote prover and measures the response time
/// and success/failure rate for proof generation.
///
/// # Arguments
///
/// * `client` - The remote prover gRPC client.
/// * `name` - The name of the remote prover.
/// * `proof_type` - The type of proof to test.
/// * `serialized_request_payload` - The serialized request payload to send to the remote prover.
/// * `current_time` - The current time in seconds since UNIX epoch.
/// * `success_count` - Mutable reference to the success counter.
/// * `failure_count` - Mutable reference to the failure counter.
///
/// # Returns
///
/// A `ServiceStatus` containing the results of the proof test.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.remote_prover.test_remote_prover",
    skip_all,
    level = "info",
    ret(level = "debug")
)]
async fn test_remote_prover(
    client: &mut miden_node_proto::clients::RemoteProverClient,
    name: &str,
    proof_type: &ProofType,
    serialized_request_payload: &proto::remote_prover::ProofRequest,
    current_time: u64,
    success_count: &mut u64,
    failure_count: &mut u64,
) -> ServiceStatus {
    let start_time = std::time::Instant::now();

    // Create the proof request
    let request = Request::new(serialized_request_payload.clone());

    // Send the request and measure the time
    match client.prove(request).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            let response_inner = response.into_inner();

            *success_count += 1;

            ServiceStatus {
                name: name.to_string(),
                status: Status::Healthy,
                last_checked: current_time,
                error: None,
                details: ServiceDetails::RemoteProverTest(ProverTestDetails {
                    test_duration_ms: duration.as_millis() as u64,
                    proof_size_bytes: response_inner.payload.len(),
                    success_count: *success_count,
                    failure_count: *failure_count,
                    proof_type: proof_type.clone(),
                }),
            }
        },
        Err(e) => {
            *failure_count += 1;

            ServiceStatus {
                name: name.to_string(),
                status: Status::Unhealthy,
                last_checked: current_time,
                error: Some(tonic_status_to_json(&e)),
                details: ServiceDetails::RemoteProverTest(ProverTestDetails {
                    test_duration_ms: 0,
                    proof_size_bytes: 0,
                    success_count: *success_count,
                    failure_count: *failure_count,
                    proof_type: proof_type.clone(),
                }),
            }
        },
    }
}

/// Converts a `tonic::Status` error to a JSON string with structured error information.
///
/// This function extracts the code, message, details, and metadata from a `tonic::Status`
/// error and serializes them into a JSON string for structured error reporting.
///
/// # Arguments
///
/// * `status` - The `tonic::Status` error to convert.
///
/// # Returns
///
/// A JSON string containing the structured error information.
fn tonic_status_to_json(status: &tonic::Status) -> String {
    let error_json = serde_json::json!({
        "code": format!("{:?}", status.code()),
        "message": status.message(),
        "details": if status.details().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(format!("details present ({} bytes)", status.details().len()))
        },
        "metadata": {
            "headers": status.metadata().iter().map(|kv| {
                match kv {
                    tonic::metadata::KeyAndValueRef::Ascii(key, value) => {
                        (key.as_str(), value.to_str().unwrap_or("<invalid ascii>"))
                    },
                    tonic::metadata::KeyAndValueRef::Binary(key, _value) => {
                        (key.as_str(), "<binary data>")
                    }
                }
            }).collect::<std::collections::HashMap<_, _>>()
        }
    });

    error_json.to_string()
}

// TRANSACTION WITNESS GENERATOR
// ================================================================================================

/// Generates a mock transaction for testing remote prover functionality.
///
/// This function creates a mock transaction using `MockChainBuilder` similar to what's done
/// in the remote prover tests. The transaction is generated once and can be reused for
/// multiple proof test calls.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.remote_prover.generate_mock_transaction",
    skip_all,
    level = "info",
    ret(level = "debug"),
    err
)]
pub async fn generate_mock_transaction() -> anyhow::Result<TransactionInputs> {
    let mut mock_chain_builder = MockChainBuilder::new();

    // Create an account with basic authentication
    let account = mock_chain_builder
        .add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak })
        .context("Failed to add wallet to mock chain")?;

    // Create a fungible asset
    let fungible_asset: Asset = FungibleAsset::new(
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET
            .try_into()
            .context("Failed to convert account ID")?,
        100,
    )
    .context("Failed to create fungible asset")?
    .into();

    // Create a P2ID note
    let note = mock_chain_builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().context("Failed to convert sender account ID")?,
            account.id(),
            &[fungible_asset],
            NoteType::Private,
        )
        .context("Failed to add P2ID note")?;

    // Build the mock chain
    let mock_chain = mock_chain_builder.build().context("Failed to build mock chain")?;

    // Build transaction context
    let tx_context = mock_chain
        .build_tx_context(account.id(), &[note.id()], &[])
        .context("Failed to build transaction context")?
        .build()
        .context("Failed to build transaction")?;

    // Execute the transaction
    let executed_transaction =
        tx_context.execute().await.context("Failed to execute transaction")?;
    Ok(executed_transaction.into())
}

// GENERATE TEST REQUEST PAYLOAD
// ================================================================================================

#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.remote_prover.generate_prover_test_payload",
    skip_all,
    level = "info",
    ret(level = "debug")
)]
pub(crate) async fn generate_prover_test_payload() -> proto::remote_prover::ProofRequest {
    proto::remote_prover::ProofRequest {
        proof_type: proto::remote_prover::ProofType::Transaction.into(),
        payload: generate_mock_transaction().await.unwrap().to_bytes(),
    }
}
