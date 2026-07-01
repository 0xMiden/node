//! Task management for the network monitor.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use backon::{ExponentialBuilder, Retryable};
use miden_node_proto::clients::RemoteProverClient;
use miden_node_utils::tasks::Tasks as SupervisedTasks;
use tokio::sync::watch::Receiver;
use tokio::sync::{Mutex, watch};
use tracing::{debug, warn};

use crate::COMPONENT;
use crate::config::MonitorConfig;
use crate::counter::{CounterTrackingService, IncrementService, LatencyState, TrackedAccounts};
use crate::deploy::create_and_deploy_accounts;
use crate::explorer::ExplorerService;
use crate::faucet::FaucetService;
use crate::frontend::{ServerState, serve};
use crate::note_transport::NoteTransportService;
use crate::remote_prover::ProverStatusService;
use crate::service::{Service, build_tls_client};
use crate::status::{
    CounterTrackingDetails,
    IncrementDetails,
    RpcService,
    ServiceDetails,
    ServiceStatus,
};
use crate::validator::ValidatorService;

/// Task management structure that supervises named component tasks.
#[derive(Default)]
pub struct Tasks {
    handles: SupervisedTasks,
}

impl Tasks {
    /// Create a new Tasks instance.
    pub fn new() -> Self {
        Self { handles: SupervisedTasks::new() }
    }

    /// Spawn the RPC status checker task.
    pub fn spawn_rpc_checker(&mut self, config: &MonitorConfig) -> Receiver<ServiceStatus> {
        let svc = RpcService::new(
            config.rpc_url.clone(),
            config.status_check_interval,
            config.request_timeout,
            config.stale_chain_tip_threshold,
        );
        self.spawn_service(svc)
    }

    /// Spawn the explorer status checker task.
    pub fn spawn_explorer_checker(&mut self, config: &MonitorConfig) -> Receiver<ServiceStatus> {
        let explorer_url = config.explorer_url.clone().expect("Explorer URL exists");
        let svc = ExplorerService::new(
            explorer_url,
            config.status_check_interval,
            config.request_timeout,
        );
        self.spawn_service(svc)
    }

    /// Spawn the note transport status checker task.
    pub fn spawn_note_transport_checker(
        &mut self,
        config: &MonitorConfig,
    ) -> Receiver<ServiceStatus> {
        let note_transport_url =
            config.note_transport_url.clone().expect("Note transport URL exists");
        let svc = NoteTransportService::new(
            note_transport_url,
            config.status_check_interval,
            config.request_timeout,
        );
        self.spawn_service(svc)
    }

    /// Spawn the validator status checker task.
    pub fn spawn_validator_checker(&mut self, config: &MonitorConfig) -> Receiver<ServiceStatus> {
        let validator_url = config.validator_url.clone().expect("Validator URL exists");
        let svc = ValidatorService::new(
            validator_url,
            config.status_check_interval,
            config.request_timeout,
        );
        self.spawn_service(svc)
    }

    /// Spawn prover status tasks for all configured provers.
    ///
    /// Each prover is monitored by a [`ProverStatusService`] that polls on the status cadence.
    /// Once it observes the prover reporting `ProofType::Transaction`, the status service spawns
    /// (and keeps alive) a probe task that acquires its test payload from the RPC and runs
    /// proof-test probes on the test cadence.
    pub fn spawn_prover_tasks(&mut self, config: &MonitorConfig) -> Vec<Receiver<ServiceStatus>> {
        let mut prover_rxs = Vec::new();
        for (i, prover_url) in config.remote_prover_urls.iter().enumerate() {
            let name = format!("Remote Prover ({})", i + 1);
            let test_client =
                build_tls_client::<RemoteProverClient>(prover_url.clone(), config.request_timeout);

            let status_svc = ProverStatusService::new(
                name,
                prover_url.clone(),
                config.rpc_url.clone(),
                config.status_check_interval,
                config.request_timeout,
                config.remote_prover_test_interval,
                test_client,
            );
            prover_rxs.push(self.spawn_service(status_svc));
        }
        prover_rxs
    }

    /// Spawn the faucet testing task.
    pub fn spawn_faucet(&mut self, config: &MonitorConfig) -> Receiver<ServiceStatus> {
        let faucet_url = config.faucet_url.clone().expect("faucet URL exists");
        let svc =
            FaucetService::new(faucet_url, config.faucet_test_interval, config.request_timeout);
        self.spawn_service(svc)
    }

    /// Spawn the network transaction service checker task.
    ///
    /// Returns the two status receivers immediately, seeded with an unknown "deploying monitor
    /// accounts" status, and bootstraps the services in a supervised background task so that a
    /// slow or unreachable RPC neither delays the dashboard nor aborts the monitor (see
    /// [`run_ntx`]).
    pub fn spawn_ntx_service(
        &mut self,
        config: &MonitorConfig,
    ) -> (Receiver<ServiceStatus>, Receiver<ServiceStatus>) {
        let (increment_tx, increment_rx) = watch::channel(ntx_seed_status(
            IncrementService::NAME,
            ServiceDetails::NtxIncrement(IncrementDetails::default()),
        ));
        let (tracking_tx, tracking_rx) = watch::channel(ntx_seed_status(
            CounterTrackingService::NAME,
            ServiceDetails::NtxTracking(CounterTrackingDetails::default()),
        ));

        let config = config.clone();
        self.handles.spawn_infallible("ntx", run_ntx(config, increment_tx, tracking_tx));
        debug!(target: COMPONENT, service = "ntx", "spawned service");

        (increment_rx, tracking_rx)
    }

    /// Spawns a [`Service`] and returns its `ServiceStatus` receiver.
    ///
    /// Seeds the `watch::channel` from [`Service::initial_status`] and hands the sender to
    /// [`Service::run`] in a new task. The returned receiver is what [`ServerState`] consumes.
    pub fn spawn_service<S: Service>(&mut self, svc: S) -> Receiver<ServiceStatus> {
        let (tx, rx) = watch::channel(svc.initial_status());
        let service_name = svc.name().to_string();
        self.handles
            .spawn_infallible(service_name.clone(), async move { svc.run(tx).await });
        debug!(target: COMPONENT, service = %service_name, "spawned service");
        rx
    }

    /// Spawn the HTTP frontend server.
    pub fn spawn_http_server(&mut self, server_state: ServerState, config: &MonitorConfig) {
        let config = config.clone();
        self.handles
            .spawn_infallible("frontend", async move { serve(server_state, config).await });
    }

    /// Handles the failure of a task.
    ///
    /// Waits for any task to complete or fail and returns an error. Since components are
    /// expected to run indefinitely, any task completion is treated as fatal.
    pub async fn handle_failure(mut self) -> Result<()> {
        self.handles.join_next_as_error().await
    }
}

// NTX BOOTSTRAP
// ================================================================================================

/// Seed status published on the NTX channels until the accounts are deployed.
fn ntx_seed_status(name: &str, details: ServiceDetails) -> ServiceStatus {
    let mut status = ServiceStatus::unknown(name, details);
    status.error = Some("deploying monitor accounts".to_string());
    status
}

/// Bootstraps the network transaction services and runs them.
///
/// Deployment is retried forever with exponential backoff, publishing an unhealthy status on both
/// channels after each failed attempt, so a network that is down at startup degrades the cards
/// instead of aborting the monitor. Once bootstrapped, both services run on separate tasks; if
/// either exits or panics, this supervised task ends and [`Tasks::handle_failure`] treats it as
/// fatal, the same semantics they had when spawned directly.
async fn run_ntx(
    config: MonitorConfig,
    increment_tx: watch::Sender<ServiceStatus>,
    tracking_tx: watch::Sender<ServiceStatus>,
) {
    let backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(30))
        .with_factor(2.0)
        .with_jitter()
        .without_max_times();

    let (increment_svc, tracking_svc) = (|| async { bootstrap_ntx(&config).await })
        .retry(backoff)
        .notify(|err: &anyhow::Error, sleep: Duration| {
            warn!(
                target: COMPONENT,
                err = ?err,
                sleep_ms = sleep.as_millis() as u64,
                "NTX bootstrap failed; retrying after backoff",
            );
            let msg = format!("deploying monitor accounts failed: {err:#}");
            increment_tx.send_replace(ServiceStatus::unhealthy(
                IncrementService::NAME,
                &msg,
                ServiceDetails::NtxIncrement(IncrementDetails::default()),
            ));
            tracking_tx.send_replace(ServiceStatus::unhealthy(
                CounterTrackingService::NAME,
                &msg,
                ServiceDetails::NtxTracking(CounterTrackingDetails::default()),
            ));
        })
        .await
        .expect("unbounded retry only resolves on success");

    // Run the services on their own tasks (a shared task would serialize the increment service's
    // local proving with the tracking polls). The first one to finish ends this supervised task;
    // the JoinSet aborts the other on drop.
    let mut services = tokio::task::JoinSet::new();
    services.spawn(increment_svc.run(increment_tx));
    services.spawn(tracking_svc.run(tracking_tx));
    services.join_next().await;
}

/// One bootstrap attempt: create and deploy fresh accounts, then build both services.
///
/// Creates a fresh wallet/counter pair in memory, deploys the counter to the network, and hands
/// the same counter account to both services via a [`watch::channel`]. The increment service
/// publishes new counters on the channel when it regenerates accounts after persistent failures;
/// the tracking service observes the channel to switch over.
async fn bootstrap_ntx(
    config: &MonitorConfig,
) -> Result<(IncrementService, CounterTrackingService)> {
    let (wallet_account, secret_key, counter_account) =
        create_and_deploy_accounts(&config.rpc_url).await?;

    let (accounts_tx, accounts_rx) = watch::channel(TrackedAccounts {
        wallet: wallet_account.clone(),
        counter: counter_account.clone(),
    });

    let latency_state = Arc::new(Mutex::new(LatencyState::default()));

    let increment_svc = IncrementService::new(
        config.clone(),
        wallet_account,
        secret_key,
        counter_account,
        accounts_tx,
        latency_state.clone(),
    )
    .await?;
    let tracking_svc =
        CounterTrackingService::new(config.clone(), accounts_rx, latency_state).await?;

    Ok((increment_svc, tracking_svc))
}
