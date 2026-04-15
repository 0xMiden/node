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

use crate::status::{ExplorerStatusDetails, ServiceDetails, ServiceStatus, Status};
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
) {
    let mut explorer_client = reqwest::Client::new();

    let mut interval = tokio::time::interval(status_check_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let current_time = current_unix_timestamp_secs();

        let status = check_explorer_status(
            &mut explorer_client,
            explorer_url.clone(),
            name.clone(),
            current_time,
            request_timeout,
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
    explorer_client: &mut Client,
    explorer_url: Url,
    name: String,
    current_time: u64,
    request_timeout: Duration,
) -> ServiceStatus {
    let resp = explorer_client
        .post(explorer_url.clone())
        .json(&LATEST_BLOCK_REQUEST)
        .timeout(request_timeout)
        .send()
        .await;

    let body = match resp {
        Ok(resp) => match resp.text().await {
            Ok(body) => body,
            Err(e) => return unhealthy(&name, current_time, &e),
        },
        Err(e) => return unhealthy(&name, current_time, &e),
    };

    let value: serde_json::Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(e) => {
            let msg = format!("{e}: {body}");
            return unhealthy(&name, current_time, &msg);
        },
    };

    let details = ExplorerStatusDetails::try_from(value);

    match details {
        Ok(details) => ServiceStatus {
            name: name.clone(),
            status: Status::Healthy,
            last_checked: current_time,
            error: None,
            details: ServiceDetails::ExplorerStatus(details),
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
    /// A required field was not present in the response.
    NotPresent(String),
    /// A field was present but had an unexpected type.
    TypeMismatch {
        field: String,
        expected: &'static str,
        got: String,
    },
}

impl Display for ExplorerStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExplorerStatusError::NotPresent(field) => {
                write!(f, "field '{field}': not present in response")
            },
            ExplorerStatusError::TypeMismatch { field, expected, got } => {
                write!(f, "field '{field}': expected {expected}, got {got}")
            },
        }
    }
}

/// Extracts a u64 from a named field.
///
/// Accepts both numeric values and string-encoded numbers (as returned by the Explorer's
/// GraphQL API).
fn require_u64(node: &serde_json::Value, field: &str) -> Result<u64, ExplorerStatusError> {
    let value = node.get(field).ok_or_else(|| ExplorerStatusError::NotPresent(field.into()))?;

    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| ExplorerStatusError::TypeMismatch {
            field: field.into(),
            expected: "u64-compatible value",
            got: truncate_json(value),
        })
}

/// Extracts a string from a named field.
fn require_str(node: &serde_json::Value, field: &str) -> Result<String, ExplorerStatusError> {
    let value = node.get(field).ok_or_else(|| ExplorerStatusError::NotPresent(field.into()))?;

    value
        .as_str()
        .map(String::from)
        .ok_or_else(|| ExplorerStatusError::TypeMismatch {
            field: field.into(),
            expected: "string",
            got: truncate_json(value),
        })
}

/// Returns a short string representation of a JSON value for error messages.
///
/// Truncates the JSON string to at most 60 characters, appending "..." if truncated.
/// Truncation is done at a character boundary to avoid panicking on multi-byte characters.
fn truncate_json(value: &serde_json::Value) -> String {
    let s = value.to_string();
    match s.char_indices().nth(60) {
        Some((idx, _)) => format!("{}...", &s[..idx]),
        None => s,
    }
}

impl TryFrom<serde_json::Value> for ExplorerStatusDetails {
    type Error = ExplorerStatusError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        let node = value.pointer("/data/blocks/edges/0/node").ok_or_else(|| {
            ExplorerStatusError::NotPresent("data.blocks.edges[0].node".to_string())
        })?;

        Ok(Self {
            block_number: require_u64(node, "block_number")?,
            timestamp: require_u64(node, "timestamp")?,
            number_of_transactions: require_u64(node, "number_of_transactions")?,
            number_of_nullifiers: require_u64(node, "number_of_nullifiers")?,
            number_of_notes: require_u64(node, "number_of_notes")?,
            number_of_account_updates: require_u64(node, "number_of_account_updates")?,
            block_commitment: require_str(node, "block_commitment")?,
            chain_commitment: require_str(node, "chain_commitment")?,
            proof_commitment: require_str(node, "proof_commitment")?,
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
