// NOTE TRANSPORT STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use miden_node_tracing::miden_instrument;
use tonic::transport::{Channel, ClientTlsConfig};
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::{HealthCheckRequest, HealthCheckResponse};
use url::Url;

use crate::COMPONENT;
use crate::service::Service;
use crate::status::{NoteTransportStatusDetails, ServiceDetails, ServiceStatus};

pub struct NoteTransportService {
    url: Url,
    client: HealthClient<Channel>,
    interval: Duration,
}

impl NoteTransportService {
    pub fn new(url: Url, interval: Duration, timeout: Duration) -> Self {
        let channel = create_channel(&url, timeout).expect("failed to create channel");
        let client = HealthClient::new(channel);
        Self { url, client, interval }
    }
}

impl Service for NoteTransportService {
    fn name(&self) -> &'static str {
        "Note Transport"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::NoteTransportStatus(NoteTransportStatusDetails {
                url: self.url.to_string(),
            }),
        )
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "check-status.note-transport",
        ret(level = "info"),
    )]
    async fn check(&mut self) -> ServiceStatus {
        let details = NoteTransportStatusDetails { url: self.url.to_string() };
        let health = self
            .client
            .check(HealthCheckRequest {
                service: miden_node_proto::server::note_transport_api::service_name().to_string(),
            })
            .await
            .map(tonic::Response::into_inner);
        status_from_health(self.name(), details, health)
    }
}

/// Builds the service status from the health response.
fn status_from_health(
    service_name: &str,
    details: NoteTransportStatusDetails,
    health: Result<HealthCheckResponse, tonic::Status>,
) -> ServiceStatus {
    let error = match health {
        Ok(response) if response.status == ServingStatus::Serving as i32 => {
            return ServiceStatus::healthy(
                service_name,
                ServiceDetails::NoteTransportStatus(details),
            );
        },
        Ok(response) => format!("service is not serving: {}", response.status),
        Err(error) => format!("health check failed: {error}"),
    };
    ServiceStatus::unhealthy(service_name, error, ServiceDetails::NoteTransportStatus(details))
}

/// Creates a `tonic` channel for the given URL, enabling TLS for `https` schemes.
fn create_channel(url: &Url, timeout: Duration) -> Result<Channel, tonic::transport::Error> {
    let mut endpoint = Channel::from_shared(url.to_string()).expect("valid URL").timeout(timeout);

    if url.scheme() == "https" {
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?;
    }

    Ok(endpoint.connect_lazy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::Status;

    #[tokio::test]
    async fn checks_note_transport_api_health() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (reporter, service) = tonic_health::server::health_reporter();
        reporter
            .set_service_status("note_transport.Api", tonic_health::ServingStatus::Serving)
            .await;
        let incoming = futures::stream::unfold(listener, |listener| async {
            Some((listener.accept().await.map(|(stream, _)| stream), listener))
        });
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        let url = Url::parse(&format!("http://{address}")).unwrap();
        let mut monitor =
            NoteTransportService::new(url.clone(), Duration::from_secs(1), Duration::from_secs(5));
        assert_eq!(monitor.check().await.status, Status::Healthy);
        reporter
            .set_service_status("note_transport.Api", tonic_health::ServingStatus::NotServing)
            .await;
        let status = monitor.check().await;
        assert_eq!(status.status, Status::Unhealthy);
        let ServiceDetails::NoteTransportStatus(details) = status.details else {
            panic!("expected note transport details");
        };
        assert_eq!(details.url, url.to_string());
        server.abort();
    }

    #[test]
    fn only_serving_health_response_is_healthy() {
        for (response, expected) in [
            (ServingStatus::Serving as i32, Status::Healthy),
            (ServingStatus::NotServing as i32, Status::Unhealthy),
            (ServingStatus::Unknown as i32, Status::Unhealthy),
            (ServingStatus::ServiceUnknown as i32, Status::Unhealthy),
            (99, Status::Unhealthy),
        ] {
            let status = status_from_health(
                "Note Transport",
                NoteTransportStatusDetails { url: "https://nt.example".to_string() },
                Ok(HealthCheckResponse { status: response }),
            );
            assert_eq!(status.status, expected);
            assert_eq!(status.error.is_none(), expected == Status::Healthy);
            let ServiceDetails::NoteTransportStatus(details) = status.details else {
                panic!("expected note transport details");
            };
            assert_eq!(details.url, "https://nt.example");
        }
    }

    #[test]
    fn failed_health_response_is_unhealthy_and_preserves_url() {
        let status = status_from_health(
            "Note Transport",
            NoteTransportStatusDetails { url: "https://nt.example".to_string() },
            Err(tonic::Status::unavailable("service unavailable")),
        );
        assert_eq!(status.status, Status::Unhealthy);
        assert!(status.error.as_deref().is_some_and(|error| {
            error.contains("health check failed") && error.contains("service unavailable")
        }));
        let ServiceDetails::NoteTransportStatus(details) = status.details else {
            panic!("expected note transport details");
        };
        assert_eq!(details.url, "https://nt.example");
    }
}
