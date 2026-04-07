// VALIDATOR STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use miden_node_proto::clients::{Builder as ClientBuilder, ValidatorClient};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{info, instrument};
use url::Url;

use crate::status::{ServiceDetails, ServiceStatus, Status, ValidatorStatusDetails};
use crate::{COMPONENT, current_unix_timestamp_secs};

/// Runs a task that continuously checks validator status and updates a watch channel.
pub async fn run_validator_status_task(
    url: Url,
    name: String,
    status_sender: watch::Sender<ServiceStatus>,
    status_check_interval: Duration,
    request_timeout: Duration,
) {
    let mut validator = ClientBuilder::new(url.clone())
        .with_tls()
        .expect("TLS is enabled")
        .with_timeout(request_timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<ValidatorClient>();

    let mut interval = tokio::time::interval(status_check_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let current_time = current_unix_timestamp_secs();

        let status =
            check_validator_status(&mut validator, url.to_string(), name.clone(), current_time)
                .await;

        if status_sender.send(status).is_err() {
            info!("No receivers for validator status updates, shutting down");
            return;
        }
    }
}

/// Checks the status of the validator service via its gRPC Status endpoint.
#[instrument(
    target = COMPONENT,
    name = "check-status.validator",
    skip_all,
    ret(level = "info")
)]
pub(crate) async fn check_validator_status(
    validator: &mut ValidatorClient,
    url: String,
    name: String,
    current_time: u64,
) -> ServiceStatus {
    match validator.status(()).await {
        Ok(response) => {
            let status = response.into_inner();

            ServiceStatus {
                name,
                status: Status::Healthy,
                last_checked: current_time,
                error: None,
                details: ServiceDetails::ValidatorStatus(ValidatorStatusDetails {
                    url,
                    version: status.version,
                    chain_tip: status.chain_tip,
                    validated_transactions_count: status.validated_transactions_count,
                    signed_blocks_count: status.signed_blocks_count,
                }),
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

pub(crate) fn initial_validator_status() -> ServiceStatus {
    ServiceStatus {
        name: "Validator".to_string(),
        status: Status::Unknown,
        last_checked: current_unix_timestamp_secs(),
        error: None,
        details: ServiceDetails::ValidatorStatus(ValidatorStatusDetails::default()),
    }
}
