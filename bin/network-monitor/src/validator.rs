// VALIDATOR STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use miden_node_proto::clients::{Builder as ClientBuilder, ValidatorClient};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{info, instrument};
use url::Url;

use crate::COMPONENT;
use crate::status::{ServiceDetails, ServiceStatus, ValidatorStatusDetails};

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

        let status = check_validator_status(&mut validator, &url, name.clone()).await;

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
    url: &Url,
    name: String,
) -> ServiceStatus {
    match validator.status(()).await {
        Ok(response) => {
            let status = response.into_inner();

            ServiceStatus::healthy(
                name,
                ServiceDetails::ValidatorStatus(ValidatorStatusDetails {
                    url: url.to_string(),
                    version: status.version,
                    chain_tip: status.chain_tip,
                    validated_transactions_count: status.validated_transactions_count,
                    signed_blocks_count: status.signed_blocks_count,
                }),
            )
        },
        Err(e) => ServiceStatus::error(name, e),
    }
}

pub(crate) fn initial_validator_status() -> ServiceStatus {
    ServiceStatus::unknown(
        "Validator",
        ServiceDetails::ValidatorStatus(ValidatorStatusDetails::default()),
    )
}
