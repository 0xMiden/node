//! Remote prover monitoring: status polling and proof-test probing.
//!
//! A prover is monitored by up to two tasks:
//! - [`ProverStatusService`] (impl [`Service`]): polls the proxy status endpoint on the status
//!   cadence and publishes the public [`ServiceStatus`] by merging in the latest probe outcome.
//! - [`run_prover_test`] (spawned by the status service): acquires the proof-test payload from the
//!   RPC, retrying until it succeeds, then runs proof-test probes on the longer test cadence and
//!   publishes a private [`ProbeSnapshot`]. First spawned when the status service observes the
//!   prover reporting [`ProofType::Transaction`]; respawned if it ever terminates, and its
//!   snapshot is reported as stale once it stops updating.

use std::time::{Duration, Instant};

use miden_node_proto::clients::{RemoteProverClient, RemoteProverProxyStatusClient};
use miden_node_proto::generated as proto;
use miden_protocol::utils::serde::Serializable;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tonic::Request;
use tracing::{debug, instrument, warn};
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
    /// The prover reported a proof type this monitor version does not know about.
    Unknown,
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

/// Parameters captured at construction time for spawning (and respawning) the probe task once the
/// status service observes the prover reporting [`ProofType::Transaction`].
struct ProbeSpawner {
    client: RemoteProverClient,
    rpc_url: Url,
    interval: Duration,
    probe_tx: watch::Sender<ProbeSnapshot>,
    name: String,
}

impl ProbeSpawner {
    /// Spawns a probe task and returns its handle.
    fn spawn(&self) -> JoinHandle<()> {
        tokio::spawn(run_prover_test(
            self.client.clone(),
            self.rpc_url.clone(),
            self.interval,
            self.probe_tx.clone(),
            self.name.clone(),
        ))
    }
}

/// Polls the remote prover's proxy status endpoint and publishes the combined [`ServiceStatus`]
/// (status + latest probe outcome). Spawns the probe task once the prover reports Transaction type
/// and keeps it alive from then on.
pub struct ProverStatusService {
    name: String,
    url: String,
    client: RemoteProverProxyStatusClient,
    interval: Duration,
    request_timeout: Duration,
    last_status: Option<RemoteProverStatusDetails>,
    last_status_err: Option<String>,
    probe_rx: watch::Receiver<ProbeSnapshot>,
    probe_spawner: ProbeSpawner,
    probe_handle: Option<JoinHandle<()>>,
    /// When the most recent [`ProbeSnapshot`] change was observed; used to flag stale probe data.
    last_probe_change: Option<Instant>,
}

impl ProverStatusService {
    pub fn new(
        name: String,
        prover_url: Url,
        rpc_url: Url,
        interval: Duration,
        request_timeout: Duration,
        probe_interval: Duration,
        test_client: RemoteProverClient,
    ) -> Self {
        let url = prover_url.to_string();
        let client = build_tls_client::<RemoteProverProxyStatusClient>(prover_url, request_timeout);
        let (probe_tx, probe_rx) = watch::channel(ProbeSnapshot::default());
        let probe_spawner = ProbeSpawner {
            client: test_client,
            rpc_url,
            interval: probe_interval,
            probe_tx,
            name: name.clone(),
        };
        Self {
            name,
            url,
            client,
            interval,
            request_timeout,
            last_status: None,
            last_status_err: None,
            probe_rx,
            probe_spawner,
            probe_handle: None,
            last_probe_change: None,
        }
    }

    /// Keeps the probe task alive once the prover has been observed to support Transaction proofs.
    ///
    /// Spawns the task on the first Transaction-type observation and respawns it if it ever
    /// terminates. The task only ends by panicking (its snapshot channel outlives it), so a
    /// finished handle is surfaced as an unhealthy outcome before respawning.
    fn ensure_probe_running(&mut self) {
        let Some(status) = &self.last_status else {
            return;
        };
        if !matches!(status.supported_proof_type, ProofType::Transaction) {
            return;
        }
        match &self.probe_handle {
            None => {
                debug!(target: COMPONENT, prover = %self.name, "spawning probe task");
                self.probe_handle = Some(self.probe_spawner.spawn());
            },
            Some(handle) if handle.is_finished() => {
                warn!(
                    target: COMPONENT,
                    prover = %self.name,
                    "probe task terminated unexpectedly; respawning"
                );
                self.probe_spawner.probe_tx.send_modify(|snapshot| {
                    snapshot.failure_count += 1;
                    snapshot.latest = Some(ProverTestOutcome {
                        details: ProverTestDetails {
                            test_duration_ms: 0,
                            proof_size_bytes: 0,
                            success_count: snapshot.success_count,
                            failure_count: snapshot.failure_count,
                            proof_type: ProofType::Transaction,
                        },
                        status: Status::Unhealthy,
                        error: Some("probe task terminated unexpectedly; respawning".to_string()),
                    });
                });
                self.probe_handle = Some(self.probe_spawner.spawn());
            },
            Some(_) => {},
        }
    }

    /// Classifies the current status + probe state into a [`ServiceStatus`].
    fn build_status(&self, probe: &ProbeSnapshot) -> ServiceStatus {
        let Some(status_details) = self.last_status.clone() else {
            let msg = self.last_status_err.clone().unwrap_or_else(|| "discovering".to_string());
            let mut status = ServiceStatus::unknown(&self.name, ServiceDetails::Error);
            status.error = Some(msg);
            return status;
        };

        let test_outcome = classify_probe_outcome(
            probe.latest.clone(),
            self.last_probe_change.map(|changed| changed.elapsed()),
            probe_staleness_window(self.probe_spawner.interval, self.request_timeout),
        );

        let details = ServiceDetails::RemoteProverStatus(RemoteProverDetails {
            status: status_details.clone(),
            test: test_outcome.clone(),
        });

        // Most recent status poll failed; report unhealthy but keep last known status details.
        if let Some(err) = &self.last_status_err {
            return ServiceStatus::unhealthy(&self.name, err.clone(), details);
        }

        if let Some(outcome) = &test_outcome {
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
        self.ensure_probe_running();
        if self.probe_rx.has_changed().unwrap_or(false) {
            self.last_probe_change = Some(Instant::now());
        }
        let probe = self.probe_rx.borrow_and_update().clone();
        self.build_status(&probe)
    }
}

// PROBE OUTCOME CLASSIFICATION
// ================================================================================================

/// Window after which a probe outcome with no fresh updates is considered stale.
///
/// Two full probe intervals plus the request timeout: a healthy probe task publishes at least
/// once per interval, and a single in-flight `prove()` call cannot outlive the request timeout.
fn probe_staleness_window(probe_interval: Duration, request_timeout: Duration) -> Duration {
    probe_interval * 2 + request_timeout
}

/// Re-classifies a probe outcome as stale when no snapshot update has been observed within the
/// staleness window.
///
/// Staleness is an observability gap, not a prover failure, so the outcome is degraded to
/// [`Status::Unknown`] (which does not flip the prover card to unhealthy) instead of
/// [`Status::Unhealthy`].
fn classify_probe_outcome(
    outcome: Option<ProverTestOutcome>,
    elapsed_since_change: Option<Duration>,
    staleness_window: Duration,
) -> Option<ProverTestOutcome> {
    let outcome = outcome?;
    match elapsed_since_change {
        Some(elapsed) if elapsed > staleness_window => Some(ProverTestOutcome {
            status: Status::Unknown,
            error: Some(format!("stale: no probe update for {}s", elapsed.as_secs())),
            details: outcome.details,
        }),
        _ => Some(outcome),
    }
}

// PROBE TASK
// ================================================================================================

/// Delay between payload-acquisition attempts. Each attempt is already bounded internally by the
/// genesis-discovery backoff, so this only paces consecutive failed attempts.
const PAYLOAD_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Runs proof-test probes on the configured interval. The task is spawned (and respawned) by
/// [`ProverStatusService::ensure_probe_running`] only after the prover has been observed to
/// support Transaction proofs.
///
/// The probe payload is acquired from the RPC first, retrying until it succeeds, so an RPC that
/// is unreachable at spawn time delays probing instead of permanently disarming it. Acquisition
/// failures are published as [`Status::Unknown`] outcomes: they are an RPC problem, not a prover
/// failure.
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
    rpc_url: Url,
    interval: Duration,
    probe_tx: watch::Sender<ProbeSnapshot>,
    name: String,
) {
    let payload = loop {
        if probe_tx.is_closed() {
            debug!(target: COMPONENT, prover = %name, "probe channel closed, exiting probe task");
            return;
        }
        match generate_prover_test_payload(&rpc_url).await {
            Ok(payload) => break payload,
            Err(e) => {
                warn!(
                    target: COMPONENT,
                    prover = %name,
                    error = ?e,
                    "failed to build remote-prover probe payload; retrying"
                );
                probe_tx.send_modify(|snapshot| {
                    snapshot.latest = Some(ProverTestOutcome {
                        details: ProverTestDetails {
                            test_duration_ms: 0,
                            proof_size_bytes: 0,
                            success_count: snapshot.success_count,
                            failure_count: snapshot.failure_count,
                            proof_type: ProofType::Transaction,
                        },
                        status: Status::Unknown,
                        error: Some(format!("building probe payload failed: {e:#}")),
                    });
                });
                tokio::time::sleep(PAYLOAD_RETRY_DELAY).await;
            },
        }
    };

    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Start from the last published snapshot so a respawned task keeps the running counters.
    let mut state = probe_tx.borrow().clone();

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

// GENERATE TEST REQUEST PAYLOAD
// ================================================================================================

/// Builds the proof request used to probe a remote transaction prover.
///
/// The payload is a real, self-consistent counter genesis transaction built in-memory (see
/// [`crate::deploy::build_probe_transaction_inputs`]); the remote prover re-executes and proves it.
/// This requires a single RPC read for the genesis block header and is independent of the network
/// transaction service.
#[instrument(
    parent = None,
    target = COMPONENT,
    name = "network_monitor.remote_prover.generate_prover_test_payload",
    skip_all,
    level = "info",
    ret(level = "debug"),
    err
)]
async fn generate_prover_test_payload(
    rpc_url: &Url,
) -> anyhow::Result<proto::remote_prover::ProofRequest> {
    let tx_inputs = crate::deploy::build_probe_transaction_inputs(rpc_url).await?;
    Ok(proto::remote_prover::ProofRequest {
        proof_type: proto::remote_prover::ProofType::Transaction.into(),
        payload: tx_inputs.to_bytes(),
    })
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(status: Status, error: Option<&str>) -> ProverTestOutcome {
        ProverTestOutcome {
            details: ProverTestDetails {
                test_duration_ms: 50,
                proof_size_bytes: 1024,
                success_count: 3,
                failure_count: 1,
                proof_type: ProofType::Transaction,
            },
            status,
            error: error.map(str::to_string),
        }
    }

    const WINDOW: Duration = Duration::from_secs(100);

    #[test]
    fn fresh_outcome_passes_through() {
        let classified = classify_probe_outcome(
            Some(outcome(Status::Healthy, None)),
            Some(Duration::from_secs(10)),
            WINDOW,
        )
        .unwrap();
        assert_eq!(classified.status, Status::Healthy);
        assert!(classified.error.is_none());
    }

    #[test]
    fn stale_outcome_degrades_to_unknown() {
        let classified = classify_probe_outcome(
            Some(outcome(Status::Healthy, None)),
            Some(Duration::from_secs(101)),
            WINDOW,
        )
        .unwrap();
        assert_eq!(classified.status, Status::Unknown);
        let err = classified.error.expect("stale outcome should carry an error note");
        assert!(err.contains("stale"), "got: {err}");
        // Numeric details from the last real probe are preserved.
        assert_eq!(classified.details.success_count, 3);
    }

    #[test]
    fn stale_unhealthy_outcome_degrades_to_unknown() {
        // A stale failure must not keep the card unhealthy forever; staleness wins.
        let classified = classify_probe_outcome(
            Some(outcome(Status::Unhealthy, Some("prove failed"))),
            Some(Duration::from_secs(500)),
            WINDOW,
        )
        .unwrap();
        assert_eq!(classified.status, Status::Unknown);
    }

    #[test]
    fn missing_outcome_stays_missing() {
        assert!(classify_probe_outcome(None, Some(Duration::from_secs(500)), WINDOW).is_none());
    }

    #[test]
    fn outcome_without_observed_change_passes_through() {
        let classified =
            classify_probe_outcome(Some(outcome(Status::Healthy, None)), None, WINDOW).unwrap();
        assert_eq!(classified.status, Status::Healthy);
    }

    #[test]
    fn staleness_window_scales_with_interval_and_timeout() {
        let window = probe_staleness_window(Duration::from_secs(120), Duration::from_secs(10));
        assert_eq!(window, Duration::from_secs(250));
    }
}
