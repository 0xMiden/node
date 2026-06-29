// NOTE TRANSPORT STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use tonic::transport::{Channel, ClientTlsConfig};
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::{HealthCheckRequest, health_check_response};
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
            ServiceDetails::NoteTransportStatus(NoteTransportStatusDetails::default()),
        )
    }

    #[miden_node_utils::tracing::miden_instrument(
        target = COMPONENT,
        name = "check-status.note-transport",
        skip_all,
        ret(level = "info")
    )]
    async fn check(&mut self) -> ServiceStatus {
        let request = HealthCheckRequest { service: String::new() };
        let url = self.url.to_string();

        match self.client.check(request).await {
            Ok(response) => {
                let serving_status = response.into_inner().status();
                let is_serving = serving_status == health_check_response::ServingStatus::Serving;
                let serving_status_str = format!("{serving_status:?}");
                let details = ServiceDetails::NoteTransportStatus(NoteTransportStatusDetails {
                    url,
                    serving_status: serving_status_str.clone(),
                });

                if is_serving {
                    ServiceStatus::healthy(self.name(), details)
                } else {
                    ServiceStatus::unhealthy(
                        self.name(),
                        format!("serving status: {serving_status_str}"),
                        details,
                    )
                }
            },
            Err(e) => ServiceStatus::error(self.name(), e),
        }
    }
}

/// Creates a `tonic` channel for the given URL, enabling TLS for `https` schemes.
fn create_channel(url: &Url, timeout: Duration) -> Result<Channel, tonic::transport::Error> {
    let mut endpoint = Channel::from_shared(url.to_string()).expect("valid URL").timeout(timeout);

    if url.scheme() == "https" {
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?;
    }

    Ok(endpoint.connect_lazy())
}
