//! Task management for the network monitor.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use miden_node_proto::clients::{
    Builder as ClientBuilder,
    RemoteProverProxyStatusClient,
    RpcClient,
};
use tokio::sync::watch::Receiver;
use tokio::sync::{Mutex, watch};
use tokio::task::{Id, JoinSet};
use tracing::{debug, instrument};

use crate::COMPONENT;
use crate::config::MonitorConfig;
use crate::counter::{LatencyState, run_counter_tracking_task, run_increment_task};
use crate::deploy::ensure_accounts_exist;
use crate::explorer::{initial_explorer_status, run_explorer_status_task};
use crate::faucet::run_faucet_test_task;
use crate::frontend::{ServerState, serve};
use crate::note_transport::{initial_note_transport_status, run_note_transport_status_task};
use crate::remote_prover::{ProofType, generate_prover_test_payload, run_remote_prover_test_task};
use crate::status::{
    ServiceStatus,
    StaleChainTracker,
    check_remote_prover_status,
    check_rpc_status,
    run_remote_prover_status_task,
    run_rpc_status_task,
};

/// Task management structure that encapsulates `JoinSet` and component names.
#[derive(Default)]
pub struct Tasks {
    handles: JoinSet<()>,
    names: HashMap<Id, String>,
}

impl Tasks {
    /// Create a new Tasks instance.
    pub fn new() -> Self {
        Self {
            handles: JoinSet::new(),
            names: HashMap::new(),
        }
    }

    /// Spawn the RPC status checker task.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.tasks.spawn_rpc_checker",
        skip_all,
        level = "info",
        ret(level = "debug"),
        err
    )]
    pub async fn spawn_rpc_checker(
        &mut self,
        config: &MonitorConfig,
    ) -> Result<Receiver<ServiceStatus>> {
        debug!(target: COMPONENT, rpc_url = %config.rpc_url, "Spawning RPC status checker task");

        // Create initial status for RPC service
        let mut rpc = ClientBuilder::new(config.rpc_url.clone())
            .with_tls()
            .expect("TLS is enabled")
            .with_timeout(config.request_timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection()
            .connect_lazy::<RpcClient>();

        let current_time = current_unix_timestamp_secs();
        let mut stale_tracker = StaleChainTracker::new(config.stale_chain_tip_threshold);
        let initial_rpc_status = check_rpc_status(
            &mut rpc,
            config.rpc_url.to_string(),
            current_time,
            &mut stale_tracker,
        )
        .await;

        // Spawn the RPC checker
        let (rpc_tx, rpc_rx) = watch::channel(initial_rpc_status);
        let rpc_url = config.rpc_url.clone();
        let status_check_interval = config.status_check_interval;
        let request_timeout = config.request_timeout;
        let stale_chain_tip_threshold = config.stale_chain_tip_threshold;
        let id = self
            .handles
            .spawn(async move {
                run_rpc_status_task(
                    rpc_url,
                    rpc_tx,
                    status_check_interval,
                    request_timeout,
                    stale_chain_tip_threshold,
                )
                .await;
            })
            .id();
        self.names.insert(id, "rpc-checker".to_string());

        debug!(target: COMPONENT, "RPC status checker task spawned successfully");
        Ok(rpc_rx)
    }

    /// Spawn the explorer status checker task.
    #[instrument(target = COMPONENT, name = "tasks.spawn-explorer-checker", skip_all)]
    pub async fn spawn_explorer_checker(
        &mut self,
        config: &MonitorConfig,
    ) -> Result<Receiver<ServiceStatus>> {
        let explorer_url = config.explorer_url.clone().expect("Explorer URL exists");
        let name = "Explorer".to_string();
        let status_check_interval = config.status_check_interval;
        let request_timeout = config.request_timeout;
        let (explorer_status_tx, explorer_status_rx) = watch::channel(initial_explorer_status());

        let id = self
            .handles
            .spawn(async move {
                run_explorer_status_task(
                    explorer_url,
                    name,
                    explorer_status_tx,
                    status_check_interval,
                    request_timeout,
                )
                .await;
            })
            .id();
        self.names.insert(id, "explorer-checker".to_string());

        println!("Spawned explorer status checker task");

        Ok(explorer_status_rx)
    }

    /// Spawn the note transport status checker task.
    #[instrument(target = COMPONENT, name = "tasks.spawn-note-transport-checker", skip_all)]
    pub async fn spawn_note_transport_checker(
        &mut self,
        config: &MonitorConfig,
    ) -> Result<Receiver<ServiceStatus>> {
        let note_transport_url =
            config.note_transport_url.clone().expect("Note transport URL exists");
        let name = "Note Transport".to_string();
        let status_check_interval = config.status_check_interval;
        let request_timeout = config.request_timeout;
        let (tx, rx) = watch::channel(initial_note_transport_status());

        let id = self
            .handles
            .spawn(async move {
                run_note_transport_status_task(
                    note_transport_url,
                    name,
                    tx,
                    status_check_interval,
                    request_timeout,
                )
                .await;
            })
            .id();
        self.names.insert(id, "note-transport-checker".to_string());

        println!("Spawned note transport status checker task");

        Ok(rx)
    }

    /// Spawn prover status and test tasks for all configured provers.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.tasks.spawn_prover_tasks",
        skip_all,
        level = "info",
        ret(level = "debug"),
        err
    )]
    pub async fn spawn_prover_tasks(
        &mut self,
        config: &MonitorConfig,
    ) -> Result<Vec<(watch::Receiver<ServiceStatus>, watch::Receiver<ServiceStatus>)>> {
        debug!(target: COMPONENT, prover_count = config.remote_prover_urls.len(), "Spawning prover tasks");
        let mut prover_rxs = Vec::new();

        for (i, prover_url) in config.remote_prover_urls.iter().enumerate() {
            let name = format!("Remote Prover ({})", i + 1);

            let mut remote_prover = ClientBuilder::new(prover_url.clone())
                .with_tls()
                .expect("TLS is enabled")
                .with_timeout(config.request_timeout)
                .without_metadata_version()
                .without_metadata_genesis()
                .without_otel_context_injection()
                .connect_lazy::<RemoteProverProxyStatusClient>();

            let current_time = current_unix_timestamp_secs();

            let initial_prover_status = check_remote_prover_status(
                &mut remote_prover,
                name.clone(),
                prover_url.to_string(),
                current_time,
            )
            .await;

            let (prover_status_tx, prover_status_rx) =
                watch::channel(initial_prover_status.clone());

            // Spawn the remote prover status check task
            let component_name = format!("prover-checker-{}", i + 1);
            let prover_url_clone = prover_url.clone();
            let name_clone = name.clone();
            let status_check_interval = config.status_check_interval;
            let request_timeout = config.request_timeout;
            let id = self
                .handles
                .spawn(async move {
                    run_remote_prover_status_task(
                        prover_url_clone,
                        name_clone,
                        prover_status_tx,
                        status_check_interval,
                        request_timeout,
                    )
                    .await;
                })
                .id();
            self.names.insert(id, component_name);

            // Extract proof_type directly from the service status
            // If the prover is not available during startup, skip spawning test tasks
            let proof_type = if let crate::status::ServiceDetails::RemoteProverStatus(details) =
                &initial_prover_status.details
            {
                Some(details.supported_proof_type.clone())
            } else {
                // Prover is not available during startup, but we'll still monitor its status
                tracing::warn!(
                    "Prover {} is not available during startup, skipping test task initialization",
                    name
                );
                None
            };

            // Only spawn test tasks for transaction provers if proof_type is available
            let prover_test_rx = if matches!(proof_type, Some(ProofType::Transaction)) {
                debug!("Starting transaction proof tests for prover: {}", name);
                let payload = generate_prover_test_payload().await;
                let (prover_test_tx, prover_test_rx) =
                    watch::channel(initial_prover_status.clone());

                let prover_url_clone = prover_url.clone();
                let name_clone = name.clone();
                let proof_type = proof_type.expect("proof type is Some");
                let remote_prover_interval = config.remote_prover_test_interval;

                let id = self
                    .handles
                    .spawn(async move {
                        run_remote_prover_test_task(
                            prover_url_clone,
                            &name_clone,
                            proof_type,
                            payload,
                            prover_test_tx,
                            request_timeout,
                            remote_prover_interval,
                        )
                        .await;
                    })
                    .id();
                let component_name = format!("prover-test-{}", i + 1);
                self.names.insert(id, component_name);

                prover_test_rx
            } else {
                debug!(
                    "Skipping prover tests for {} (supports {:?} proofs, only testing Transaction proofs)",
                    name, proof_type
                );
                // For non-transaction provers, create a dummy receiver with no test task
                let (_tx, rx) = watch::channel(initial_prover_status.clone());
                rx
            };

            prover_rxs.push((prover_status_rx, prover_test_rx));
        }

        debug!(target: COMPONENT, spawned_provers = prover_rxs.len(), "All prover tasks spawned successfully");
        Ok(prover_rxs)
    }

    /// Spawn the faucet testing task.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.tasks.spawn_faucet",
        skip_all,
        level = "info",
        ret(level = "debug")
    )]
    pub fn spawn_faucet(&mut self, config: &MonitorConfig) -> Receiver<ServiceStatus> {
        let current_time = current_unix_timestamp_secs();

        // Create initial faucet test status
        let initial_faucet_status = ServiceStatus {
            name: "Faucet".to_string(),
            status: crate::status::Status::Unknown,
            last_checked: current_time,
            error: None,
            details: crate::status::ServiceDetails::FaucetTest(crate::faucet::FaucetTestDetails {
                url: config.faucet_url.as_ref().expect("faucet URL exists").to_string(),
                test_duration_ms: 0,
                success_count: 0,
                failure_count: 0,
                last_tx_id: None,
                faucet_metadata: None,
            }),
        };

        // Spawn the faucet testing task
        let (faucet_tx, faucet_rx) = watch::channel(initial_faucet_status);
        // SAFETY: config.faucet_url is Some
        let faucet_url = config.faucet_url.clone().unwrap();
        let faucet_test_interval = config.faucet_test_interval;
        let request_timeout = config.request_timeout;
        let id = self
            .handles
            .spawn(async move {
                run_faucet_test_task(faucet_url, faucet_tx, faucet_test_interval, request_timeout)
                    .await;
            })
            .id();
        self.names.insert(id, "faucet-test".to_string());

        faucet_rx
    }

    /// Spawn the network transaction service checker task.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.tasks.spawn_ntx_service",
        skip_all,
        level = "info",
        ret(level = "debug"),
        err
    )]
    pub async fn spawn_ntx_service(
        &mut self,
        config: &MonitorConfig,
    ) -> Result<(Receiver<ServiceStatus>, Receiver<ServiceStatus>)> {
        // Ensure accounts exist before starting monitoring tasks
        ensure_accounts_exist(&config.wallet_filepath, &config.counter_filepath, &config.rpc_url)
            .await?;

        let current_time = current_unix_timestamp_secs();

        // Create shared atomic counter for tracking expected counter value
        let expected_counter_value = Arc::new(AtomicU64::new(0));
        let latency_state = Arc::new(Mutex::new(LatencyState::default()));
        let latency_state_for_increment = latency_state.clone();
        let latency_state_for_tracking = latency_state.clone();

        // Create initial increment status
        let initial_increment_status = ServiceStatus {
            name: "Local Transactions".to_string(),
            status: crate::status::Status::Unknown,
            last_checked: current_time,
            error: None,
            details: crate::status::ServiceDetails::NtxIncrement(crate::status::IncrementDetails {
                success_count: 0,
                failure_count: 0,
                last_tx_id: None,
                last_latency_blocks: None,
            }),
        };

        // Create initial tracking status
        let initial_tracking_status = ServiceStatus {
            name: "Network Transactions".to_string(),
            status: crate::status::Status::Unknown,
            last_checked: current_time,
            error: None,
            details: crate::status::ServiceDetails::NtxTracking(
                crate::status::CounterTrackingDetails {
                    current_value: None,
                    expected_value: None,
                    last_updated: None,
                    pending_increments: None,
                },
            ),
        };

        // Spawn the increment task
        let (increment_tx, increment_rx) = watch::channel(initial_increment_status);
        let config_clone = config.clone();
        let counter_clone = Arc::clone(&expected_counter_value);
        let increment_id = self
            .handles
            .spawn(async move {
                Box::pin(run_increment_task(
                    config_clone,
                    increment_tx,
                    counter_clone,
                    latency_state_for_increment,
                ))
                .await
                .expect("Counter increment task runs indefinitely");
            })
            .id();
        self.names.insert(increment_id, "counter-increment".to_string());

        // Spawn the tracking task
        let (tracking_tx, tracking_rx) = watch::channel(initial_tracking_status);
        let config_clone = config.clone();
        let counter_clone = Arc::clone(&expected_counter_value);
        let tracking_id = self
            .handles
            .spawn(async move {
                Box::pin(run_counter_tracking_task(
                    config_clone,
                    tracking_tx,
                    counter_clone,
                    latency_state_for_tracking,
                ))
                .await
                .expect("Counter tracking task runs indefinitely");
            })
            .id();
        self.names.insert(tracking_id, "counter-tracking".to_string());

        Ok((increment_rx, tracking_rx))
    }

    /// Spawn the HTTP frontend server.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.tasks.spawn_http_server",
        skip_all,
        level = "info",
        ret(level = "debug")
    )]
    pub fn spawn_http_server(&mut self, server_state: ServerState, config: &MonitorConfig) {
        let config = config.clone();
        let id = self.handles.spawn(async move { serve(server_state, config).await }).id();
        self.names.insert(id, "frontend".to_string());
    }

    /// Wait for any task to complete or fail and return the result.
    async fn join_next_with_id(&mut self) -> Option<Result<(Id, ()), tokio::task::JoinError>> {
        self.handles.join_next_with_id().await
    }

    /// Get the component name for a given task ID.
    fn get_component_name(&self, id: Id) -> Option<&String> {
        self.names.get(&id)
    }

    /// Handles the failure of a task.
    ///
    /// This method waits for any task to complete or fail and returns an error.
    /// Since we expect components to run indefinitely, any task completion is treated as fatal.
    ///
    /// # Returns
    ///
    /// An error if any task fails or completes unexpectedly.
    pub async fn handle_failure(&mut self) -> Result<()> {
        // Wait for any task to complete or fail
        let component_result = self.join_next_with_id().await.expect("join set is not empty");

        // We expect components to run indefinitely, so we treat any return as fatal.
        let (id, err) = match component_result {
            Ok((id, ())) => (id, anyhow::anyhow!("component completed unexpectedly")),
            Err(join_err) => (join_err.id(), anyhow::Error::from(join_err)),
        };
        let component_name = self.get_component_name(id).map_or("unknown", String::as_str);

        // Exit with error context
        Err(err.context(format!("component {component_name} failed")))
    }
}

/// Gets the current Unix timestamp in seconds.
///
/// This function is infallible - if the system time is somehow before Unix epoch
/// (extremely unlikely), it returns 0.
pub fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))  // Fallback to 0 if before Unix epoch
        .as_secs()
}
