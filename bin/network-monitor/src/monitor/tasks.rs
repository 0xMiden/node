//! Task management for the network monitor.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::Result;
use miden_node_proto::clients::RemoteProverClient;
use miden_node_utils::tasks::Tasks as SupervisedTasks;
use tokio::sync::watch::Receiver;
use tokio::sync::{Mutex, watch};
use tracing::debug;

use crate::COMPONENT;
use crate::config::MonitorConfig;
use crate::counter::{CounterTrackingService, IncrementService, LatencyState};
use crate::deploy::create_and_deploy_accounts;
use crate::explorer::ExplorerService;
use crate::faucet::FaucetService;
use crate::frontend::{ServerState, serve};
use crate::note_transport::NoteTransportService;
use crate::remote_prover::{ProbeSnapshot, ProverStatusService, generate_prover_test_payload};
use crate::service::{Service, build_tls_client};
use crate::status::{RpcService, ServiceStatus};
use crate::validator::ValidatorService;

/// Task management structure that supervises named component tasks.
#[derive(Default)]
pub struct Tasks {
    handles: SupervisedTasks<()>,
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
    /// The first time it observes the prover reporting `ProofType::Transaction`, the status
    /// service spawns a detached probe task that runs proof-test probes on the test cadence.
    pub async fn spawn_prover_tasks(
        &mut self,
        config: &MonitorConfig,
    ) -> Vec<watch::Receiver<ServiceStatus>> {
        let mut prover_rxs = Vec::new();
        for (i, prover_url) in config.remote_prover_urls.iter().enumerate() {
            let name = format!("Remote Prover ({})", i + 1);
            let (probe_tx, probe_rx) = watch::channel(ProbeSnapshot::default());
            let test_client =
                build_tls_client::<RemoteProverClient>(prover_url.clone(), config.request_timeout);
            let payload = generate_prover_test_payload().await;

            let status_svc = ProverStatusService::new(
                name,
                prover_url.clone(),
                config.status_check_interval,
                config.request_timeout,
                config.remote_prover_test_interval,
                probe_tx,
                probe_rx,
                test_client,
                payload,
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
    /// Creates a fresh wallet/counter pair in memory, deploys the counter to the network, and
    /// hands the same counter account to both services via a [`watch::channel`]. The increment
    /// service publishes new counters on the channel when it regenerates accounts after
    /// persistent failures; the tracking service observes the channel to switch over.
    pub async fn spawn_ntx_service(
        &mut self,
        config: &MonitorConfig,
    ) -> Result<(Receiver<ServiceStatus>, Receiver<ServiceStatus>)> {
        let (wallet_account, secret_key, counter_account) =
            create_and_deploy_accounts(&config.rpc_url).await?;

        let (counter_tx, counter_rx) = watch::channel(counter_account.clone());

        let expected_counter_value = Arc::new(AtomicU64::new(0));
        let latency_state = Arc::new(Mutex::new(LatencyState::default()));

        let increment_svc = IncrementService::new(
            config.clone(),
            wallet_account,
            secret_key,
            counter_account,
            counter_tx,
            Arc::clone(&expected_counter_value),
            latency_state.clone(),
        )
        .await?;
        let tracking_svc = CounterTrackingService::new(
            config.clone(),
            counter_rx,
            Arc::clone(&expected_counter_value),
            latency_state,
        )
        .await?;

        let increment_rx = self.spawn_service(increment_svc);
        let tracking_rx = self.spawn_service(tracking_svc);

        Ok((increment_rx, tracking_rx))
    }

    /// Spawns a [`Service`] and returns its `ServiceStatus` receiver.
    ///
    /// Seeds the `watch::channel` from [`Service::initial_status`] and hands the sender to
    /// [`Service::run`] in a new task. The returned receiver is what [`ServerState`] consumes.
    pub fn spawn_service<S: Service>(&mut self, svc: S) -> Receiver<ServiceStatus> {
        let (tx, rx) = watch::channel(svc.initial_status());
        let service_name = svc.name().to_string();
        self.handles.spawn(service_name.clone(), async move { svc.run(tx).await });
        debug!(target: COMPONENT, service = %service_name, "spawned service");
        rx
    }

    /// Spawn the HTTP frontend server.
    pub fn spawn_http_server(&mut self, server_state: ServerState, config: &MonitorConfig) {
        let config = config.clone();
        self.handles.spawn("frontend", async move { serve(server_state, config).await });
    }

    /// Handles the failure of a task.
    ///
    /// Waits for any task to complete or fail and returns an error. Since components are
    /// expected to run indefinitely, any task completion is treated as fatal.
    pub async fn handle_failure(&mut self) -> Result<()> {
        let component_result = self.handles.join_next().await.expect("join set is not empty");
        self.handles.abort_all();

        let component_name = component_result.name;
        let err = match component_result.result {
            Ok(()) => anyhow::anyhow!("component completed unexpectedly"),
            Err(join_err) => anyhow::Error::from(join_err),
        };

        Err(err.context(format!("component {component_name} failed")))
    }
}
