//! Remote prover monitoring: status polling and proof-test probing.
//!
//! A prover is monitored by up to two tasks:
//! - [`ProverStatusService`] (impl [`Service`]): polls the proxy status endpoint on the status
//!   cadence and publishes the public [`ServiceStatus`] by merging in the latest probe outcome.
//! - [`run_prover_test`] (spawned lazily by the status service): runs proof-test probes on the
//!   longer test cadence and publishes a private [`ProbeSnapshot`]. Only spawned the first time the
//!   status service observes the prover reporting [`ProofType::Transaction`].

use std::time::{Duration, Instant};

use anyhow::Context;
use miden_node_proto::clients::{RemoteProverClient, RemoteProverProxyStatusClient};
use miden_node_proto::generated as proto;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::TransactionInputs;
use miden_protocol::utils::serde::Serializable;
use miden_testing::{Auth, MockChainBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tonic::Request;
use tracing::{debug, instrument};
use url::Url;

use crate::COMPONENT;
use crate::service::{Service, build_tls_client};
use crate::service_status::{
    ProverTestOutcome,
    RemoteProverDetails,
    RemoteProverStatusDetails,
    ServiceDetails,
    ServiceStatus,
    Status,
};

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

// PROBE SNAPSHOT
// ================================================================================================

/// Private snapshot of the most recent probe result. Shared from the probe task to the status
/// service via a `watch` channel.
#[derive(Debug, Clone, Default)]
pub struct ProbeSnapshot {
    pub latest: Option<ProverTestOutcome>,
    pub success_count: u64,
    pub failure_count: u64,
}

// PROVER STATUS SERVICE
// ================================================================================================

/// Parameters captured at construction time for spawning the probe task lazily, the first time the
/// status service observes the prover reporting [`ProofType::Transaction`].
struct ProbeSpawner {
    client: RemoteProverClient,
    payload: proto::remote_prover::ProofRequest,
    interval: Duration,
    probe_tx: watch::Sender<ProbeSnapshot>,
    name: String,
}

/// Polls the remote prover's proxy status endpoint and publishes the combined [`ServiceStatus`]
/// (status + latest probe outcome). Spawns the probe task the first time the prover reports
/// Transaction type.
pub struct ProverStatusService {
    name: String,
    url: String,
    client: RemoteProverProxyStatusClient,
    interval: Duration,
    last_status: Option<RemoteProverStatusDetails>,
    last_status_err: Option<String>,
    probe_rx: watch::Receiver<ProbeSnapshot>,
    probe_spawner: Option<ProbeSpawner>,
}

impl ProverStatusService {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        prover_url: Url,
        interval: Duration,
        request_timeout: Duration,
        probe_interval: Duration,
        probe_tx: watch::Sender<ProbeSnapshot>,
        probe_rx: watch::Receiver<ProbeSnapshot>,
        test_client: RemoteProverClient,
        payload: proto::remote_prover::ProofRequest,
    ) -> Self {
        let url = prover_url.to_string();
        let client = build_tls_client::<RemoteProverProxyStatusClient>(prover_url, request_timeout);
        let probe_spawner = Some(ProbeSpawner {
            client: test_client,
            payload,
            interval: probe_interval,
            probe_tx,
            name: name.clone(),
        });
        Self {
            name,
            url,
            client,
            interval,
            last_status: None,
            last_status_err: None,
            probe_rx,
            probe_spawner,
        }
    }

    /// Spawns the probe task if the prover has just been observed to support Transaction proofs and
    /// we haven't spawned it yet. No-op in all other cases.
    fn maybe_spawn_probe(&mut self) {
        let Some(status) = &self.last_status else { return };
        if !matches!(status.supported_proof_type, ProofType::Transaction) {
            return;
        }
        let Some(spawner) = self.probe_spawner.take() else {
            return;
        };
        debug!(target: COMPONENT, prover = %self.name, "spawning probe task");
        tokio::spawn(run_prover_test(
            spawner.client,
            spawner.payload,
            spawner.interval,
            spawner.probe_tx,
            spawner.name,
        ));
    }

    /// Classifies the current status + probe state into a [`ServiceStatus`].
    fn build_status(&self, probe: &ProbeSnapshot) -> ServiceStatus {
        let Some(status_details) = self.last_status.clone() else {
            let msg = self.last_status_err.clone().unwrap_or_else(|| "discovering".to_string());
            let mut status = ServiceStatus::unknown(&self.name, ServiceDetails::Error);
            status.error = Some(msg);
            return status;
        };

        let details = ServiceDetails::RemoteProverStatus(RemoteProverDetails {
            status: status_details.clone(),
            test: probe.latest.clone(),
        });

        // Most recent status poll failed — report unhealthy but keep last known status details.
        if let Some(err) = &self.last_status_err {
            return ServiceStatus::unhealthy(&self.name, err.clone(), details);
        }

        if let Some(outcome) = &probe.latest {
            if outcome.status == Status::Unhealthy {
                let msg = outcome.error.clone().unwrap_or_else(|| "prover test failed".to_string());
                return ServiceStatus::unhealthy(&self.name, msg, details);
            }
        }

        let unhealthy_workers: Vec<_> = status_details
            .workers
            .iter()
            .filter(|w| w.status != Status::Healthy)
            .map(|w| w.name.clone())
            .collect();

        if status_details.workers.is_empty() {
            ServiceStatus::unknown(&self.name, details)
        } else if !unhealthy_workers.is_empty() {
            ServiceStatus::unhealthy(
                &self.name,
                format!("unhealthy workers: {}", unhealthy_workers.join(", ")),
                details,
            )
        } else {
            ServiceStatus::healthy(&self.name, details)
        }
    }
}

impl Service for ProverStatusService {
    fn name(&self) -> &str {
        &self.name
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        self.build_status(&ProbeSnapshot::default())
    }

    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.prover.status_check",
        skip_all,
        level = "info",
        ret(level = "debug"),
        fields(prover = %self.name)
    )]
    async fn check(&mut self) -> ServiceStatus {
        match self.client.status(()).await {
            Ok(response) => {
                self.last_status = Some(RemoteProverStatusDetails::from_proxy_status(
                    response.into_inner(),
                    self.url.clone(),
                ));
                self.last_status_err = None;
            },
            Err(e) => {
                debug!(target: COMPONENT, prover = %self.name, error = %e, "Remote prover status check failed");
                self.last_status_err = Some(e.to_string());
            },
        }
        self.maybe_spawn_probe();
        let probe = self.probe_rx.borrow().clone();
        self.build_status(&probe)
    }
}

// PROBE TASK
// ================================================================================================

/// Runs proof-test probes on the configured interval. The task is spawned by
/// [`ProverStatusService::maybe_spawn_probe`] only after the prover has been observed to support
/// Transaction proofs.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.prover.run_test",
    skip_all,
    level = "info",
    fields(prover = %name),
)]
async fn run_prover_test(
    mut client: RemoteProverClient,
    payload: proto::remote_prover::ProofRequest,
    interval: Duration,
    probe_tx: watch::Sender<ProbeSnapshot>,
    name: String,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut state = ProbeSnapshot::default();

    loop {
        timer.tick().await;

        let start = Instant::now();
        let request = Request::new(payload.clone());
        match client.prove(request).await {
            Ok(response) => {
                state.success_count += 1;
                state.latest = Some(ProverTestOutcome {
                    details: ProverTestDetails {
                        test_duration_ms: start.elapsed().as_millis() as u64,
                        proof_size_bytes: response.into_inner().payload.len(),
                        success_count: state.success_count,
                        failure_count: state.failure_count,
                        proof_type: ProofType::Transaction,
                    },
                    status: Status::Healthy,
                    error: None,
                });
            },
            Err(e) => {
                state.failure_count += 1;
                state.latest = Some(ProverTestOutcome {
                    details: ProverTestDetails {
                        test_duration_ms: 0,
                        proof_size_bytes: 0,
                        success_count: state.success_count,
                        failure_count: state.failure_count,
                        proof_type: ProofType::Transaction,
                    },
                    status: Status::Unhealthy,
                    error: Some(tonic_status_to_json(&e)),
                });
            },
        }

        if probe_tx.send(state.clone()).is_err() {
            debug!(target: COMPONENT, prover = %name, "probe channel closed, exiting probe task");
            return;
        }
    }
}

// TONIC STATUS TO JSON
// ================================================================================================

/// Converts a `tonic::Status` error to a JSON string with structured error information.
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
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.remote_prover.generate_mock_transaction",
    skip_all,
    level = "info",
    ret(level = "debug"),
    err
)]
async fn generate_mock_transaction() -> anyhow::Result<TransactionInputs> {
    let mut mock_chain_builder = MockChainBuilder::new();

    let account = mock_chain_builder
        .add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })
        .context("Failed to add wallet to mock chain")?;

    let fungible_asset: Asset = FungibleAsset::new(
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET
            .try_into()
            .context("Failed to convert account ID")?,
        100,
    )
    .context("Failed to create fungible asset")?
    .into();

    let note = mock_chain_builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().context("Failed to convert sender account ID")?,
            account.id(),
            &[fungible_asset],
            NoteType::Private,
        )
        .context("Failed to add P2ID note")?;

    let mock_chain = mock_chain_builder.build().context("Failed to build mock chain")?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[note.id()], &[])
        .context("Failed to build transaction context")?
        .build()
        .context("Failed to build transaction")?;

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
