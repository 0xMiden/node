// NOTE TRANSPORT STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tonic::transport::{Channel, ClientTlsConfig};
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::{HealthCheckRequest, health_check_response};
use tracing::{info, instrument};
use url::Url;

use crate::status::{NoteTransportStatusDetails, ServiceDetails, ServiceStatus, Status};
use crate::{COMPONENT, current_unix_timestamp_secs};

/// Creates a `tonic` channel for the given URL, enabling TLS for `https` schemes.
fn create_channel(url: &Url, timeout: Duration) -> Result<Channel, tonic::transport::Error> {
    let mut endpoint = Channel::from_shared(url.to_string()).expect("valid URL").timeout(timeout);

    if url.scheme() == "https" {
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?;
    }

    Ok(endpoint.connect_lazy())
}

/// Runs a task that continuously checks note transport health and updates a watch channel.
pub async fn run_note_transport_status_task(
    url: Url,
    name: String,
    status_sender: watch::Sender<ServiceStatus>,
    status_check_interval: Duration,
    request_timeout: Duration,
) {
    let channel = create_channel(&url, request_timeout).expect("failed to create channel");
    let mut health_client = HealthClient::new(channel);

    let mut interval = tokio::time::interval(status_check_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let current_time = current_unix_timestamp_secs();

        let status = check_note_transport_status(
            &mut health_client,
            url.to_string(),
            name.clone(),
            current_time,
        )
        .await;

        if status_sender.send(status).is_err() {
            info!("No receivers for note transport status updates, shutting down");
            return;
        }
    }
}

/// Checks the health of the note transport service via the standard gRPC Health Checking Protocol.
#[instrument(
    target = COMPONENT,
    name = "check-status.note-transport",
    skip_all,
    ret(level = "info")
)]
pub(crate) async fn check_note_transport_status(
    health_client: &mut HealthClient<Channel>,
    url: String,
    name: String,
    current_time: u64,
) -> ServiceStatus {
    let request = HealthCheckRequest { service: String::new() };

    match health_client.check(request).await {
        Ok(response) => {
            let serving_status = response.into_inner().status();
            let is_serving = serving_status == health_check_response::ServingStatus::Serving;

            let status = if is_serving { Status::Healthy } else { Status::Unhealthy };
            let serving_status_str = format!("{serving_status:?}");

            ServiceStatus {
                name,
                status,
                last_checked: current_time,
                error: None,
                details: ServiceDetails::NoteTransportStatus(NoteTransportStatusDetails {
                    url,
                    serving_status: serving_status_str,
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

pub(crate) fn initial_note_transport_status() -> ServiceStatus {
    ServiceStatus {
        name: "Note Transport".to_string(),
        status: Status::Unknown,
        last_checked: current_unix_timestamp_secs(),
        error: None,
        details: ServiceDetails::NoteTransportStatus(NoteTransportStatusDetails::default()),
    }
}
