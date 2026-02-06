// EXPLORER STATUS CHECKER
// ================================================================================================

use std::fmt::{self, Display};
use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{info, instrument};
use url::Url;

use crate::status::{
    ExplorerStatusDetails,
    ServiceDetails,
    ServiceStatus,
    StaleChainTracker,
    Status,
};
use crate::{COMPONENT, current_unix_timestamp_secs};

const LATEST_BLOCK_QUERY: &str = "
query LatestBlock {
    blocks(input: { sort_by: timestamp, order_by: desc }, first: 1) {
        edges {
            node {
                block_number
                timestamp
                number_of_transactions
                number_of_nullifiers
                number_of_notes
                block_commitment
                chain_commitment
                proof_commitment
                number_of_account_updates
            }
        }
    }
}
";

#[derive(Serialize, Copy, Clone)]
struct EmptyVariables;

#[derive(Serialize, Copy, Clone)]
struct GraphqlRequest<V> {
    query: &'static str,
    variables: V,
}

const LATEST_BLOCK_REQUEST: GraphqlRequest<EmptyVariables> = GraphqlRequest {
    query: LATEST_BLOCK_QUERY,
    variables: EmptyVariables,
};

/// Runs a task that continuously checks explorer status and updates a watch channel.
///
/// This function spawns a task that periodically checks the explorer service status
/// and sends updates through a watch channel.
///
/// # Arguments
///
/// * `explorer_url` - The URL of the explorer service.
/// * `name` - The name of the explorer.
/// * `status_sender` - The sender for the watch channel.
/// * `status_check_interval` - The interval at which to check the status of the services.
///
/// # Returns
///
/// `Ok(())` if the monitoring task runs and completes successfully, or an error if there are
/// connection issues or failures while checking the explorer status.
pub async fn run_explorer_status_task(
    explorer_url: Url,
    name: String,
    status_sender: watch::Sender<ServiceStatus>,
    status_check_interval: Duration,
    request_timeout: Duration,
    stale_chain_tip_threshold: Duration,
) {
    let explorer_client = reqwest::Client::new();
    let mut stale_tracker = StaleChainTracker::new(stale_chain_tip_threshold);

    let mut interval = tokio::time::interval(status_check_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let current_time = current_unix_timestamp_secs();

        let status = check_explorer_status(
            &explorer_client,
            explorer_url.clone(),
            name.clone(),
            current_time,
            request_timeout,
            &mut stale_tracker,
        )
        .await;

        // Send the status update; exit if no receivers (shutdown signal)
        if status_sender.send(status).is_err() {
            info!("No receivers for explorer status updates, shutting down");
            return;
        }
    }
}

/// Checks the status of the explorer service.
///
/// This function checks the status of the explorer service.
///
/// # GraphQL Query
///
/// See [`LATEST_BLOCK_QUERY`] for the exact query string used.
///
/// # Arguments
///
/// * `explorer` - The explorer client.
/// * `name` - The name of the explorer.
/// * `url` - The URL of the explorer.
/// * `current_time` - The current time.
///
/// # Returns
///
/// A `ServiceStatus` containing the status of the explorer service.
#[instrument(target = COMPONENT, name = "check-status.explorer", skip_all, ret(level = "info"))]
pub(crate) async fn check_explorer_status(
    explorer_client: &Client,
    explorer_url: Url,
    name: String,
    current_time: u64,
    request_timeout: Duration,
    stale_tracker: &mut StaleChainTracker,
) -> ServiceStatus {
    let resp = explorer_client
        .post(explorer_url.clone())
        .json(&LATEST_BLOCK_REQUEST)
        .timeout(request_timeout)
        .send()
        .await;

    let value = match resp {
        Ok(resp) => resp.json::<serde_json::Value>().await,
        Err(e) => return unhealthy(&name, current_time, &e),
    };

    let details = match value {
        Ok(value) => ExplorerStatusDetails::try_from(value),
        Err(e) => return unhealthy(&name, current_time, &e),
    };

    match details {
        Ok(details) => {
            // Check for stale block data
            if let Some(stale_duration) =
                stale_tracker.update(details.block_number as u32, current_time)
            {
                return ServiceStatus {
                    name: name.clone(),
                    status: Status::Unhealthy,
                    last_checked: current_time,
                    error: Some(format!(
                        "Block {} has not changed for {} seconds",
                        details.block_number, stale_duration
                    )),
                    details: ServiceDetails::ExplorerStatus(details),
                };
            }

            ServiceStatus {
                name: name.clone(),
                status: Status::Healthy,
                last_checked: current_time,
                error: None,
                details: ServiceDetails::ExplorerStatus(details),
            }
        },
        Err(e) => unhealthy(&name, current_time, &e),
    }
}

/// Returns an unhealthy service status.
fn unhealthy(name: &str, current_time: u64, err: &impl ToString) -> ServiceStatus {
    ServiceStatus {
        name: name.to_owned(),
        status: Status::Unhealthy,
        last_checked: current_time,
        error: Some(err.to_string()),
        details: ServiceDetails::Error,
    }
}

#[derive(Debug)]
pub enum ExplorerStatusError {
    MissingField(String),
}

impl Display for ExplorerStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExplorerStatusError::MissingField(field) => write!(f, "missing field: {field}"),
        }
    }
}

impl TryFrom<serde_json::Value> for ExplorerStatusDetails {
    type Error = ExplorerStatusError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        let node = value.pointer("/data/blocks/edges/0/node").ok_or_else(|| {
            ExplorerStatusError::MissingField("data.blocks.edges[0].node".to_string())
        })?;

        let block_number = node
            .get("block_number")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ExplorerStatusError::MissingField("block_number".to_string()))?;
        let timestamp = node
            .get("timestamp")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ExplorerStatusError::MissingField("timestamp".to_string()))?;

        let number_of_transactions = node
            .get("number_of_transactions")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ExplorerStatusError::MissingField("number_of_transactions".to_string())
            })?;
        let number_of_nullifiers = node
            .get("number_of_nullifiers")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ExplorerStatusError::MissingField("number_of_nullifiers".to_string()))?;
        let number_of_notes = node
            .get("number_of_notes")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ExplorerStatusError::MissingField("number_of_notes".to_string()))?;
        let number_of_account_updates = node
            .get("number_of_account_updates")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ExplorerStatusError::MissingField("number_of_account_updates".to_string())
            })?;

        let block_commitment = node
            .get("block_commitment")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ExplorerStatusError::MissingField("block_commitment".to_string()))?
            .to_string();
        let chain_commitment = node
            .get("chain_commitment")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ExplorerStatusError::MissingField("chain_commitment".to_string()))?
            .to_string();
        let proof_commitment = node
            .get("proof_commitment")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ExplorerStatusError::MissingField("proof_commitment".to_string()))?
            .to_string();

        Ok(Self {
            block_number,
            timestamp,
            number_of_transactions,
            number_of_nullifiers,
            number_of_notes,
            number_of_account_updates,
            block_commitment,
            chain_commitment,
            proof_commitment,
        })
    }
}

pub(crate) fn initial_explorer_status() -> ServiceStatus {
    ServiceStatus {
        name: "Explorer".to_string(),
        status: Status::Unknown,
        last_checked: current_unix_timestamp_secs(),
        error: None,
        details: ServiceDetails::ExplorerStatus(ExplorerStatusDetails::default()),
    }
}
