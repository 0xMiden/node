// NOTE TRANSPORT STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use miden_node_tracing::miden_instrument;
use miden_note_transport_proto::miden_note_transport::StatsResponse;
use miden_note_transport_proto::miden_note_transport::miden_note_transport_client::MidenNoteTransportClient;
use tonic::transport::{Channel, ClientTlsConfig};
use url::Url;

use crate::COMPONENT;
use crate::service::Service;
use crate::status::{NoteTransportStatusDetails, ServiceDetails, ServiceStatus};

pub struct NoteTransportService {
    url: Url,
    client: MidenNoteTransportClient<Channel>,
    interval: Duration,
}

impl NoteTransportService {
    pub fn new(url: Url, interval: Duration, timeout: Duration) -> Self {
        let channel = create_channel(&url, timeout).expect("failed to create channel");
        let client = MidenNoteTransportClient::new(channel);
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

    #[miden_instrument(
        target = COMPONENT,
        name = "check-status.note-transport",
    )]
    async fn check(&mut self) -> ServiceStatus {
        let details = NoteTransportStatusDetails {
            url: self.url.to_string(),
            ..NoteTransportStatusDetails::default()
        };

        let stats = self.client.stats(()).await.map(tonic::Response::into_inner);
        status_from_stats(self.name(), details, stats)
    }
}

/// Builds the service status from the note transport's stats response.
fn status_from_stats(
    service_name: &str,
    mut details: NoteTransportStatusDetails,
    stats: Result<StatsResponse, tonic::Status>,
) -> ServiceStatus {
    match stats {
        Ok(stats) => {
            apply_stats(&mut details, &stats);
            ServiceStatus::healthy(service_name, ServiceDetails::NoteTransportStatus(details))
        },
        Err(e) => ServiceStatus::unhealthy(
            service_name,
            format!("stats call failed: {e}"),
            ServiceDetails::NoteTransportStatus(details),
        ),
    }
}

/// Copies the stats response into the card details.
///
/// The version is a plain string on the wire, so a server that predates the field reports an
/// empty string; that degrades to `None` rather than rendering an empty value.
fn apply_stats(details: &mut NoteTransportStatusDetails, stats: &StatsResponse) {
    details.version = (!stats.version.is_empty()).then(|| stats.version.clone());
    details.total_notes = Some(stats.total_notes);
    details.total_tags = Some(stats.total_tags);
    // An empty per-tag list leaves `last_activity` unset. The card then renders `-`.
    details.last_activity = stats
        .notes_per_tag
        .iter()
        .filter_map(|tag| tag.last_activity.as_ref())
        .filter_map(|ts| u64::try_from(ts.seconds).ok())
        .max();
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

    #[test]
    fn successful_stats_response_is_healthy() {
        let details = NoteTransportStatusDetails {
            url: "https://nt.example".to_string(),
            ..NoteTransportStatusDetails::default()
        };
        let response = StatsResponse {
            version: "0.5.0".to_string(),
            total_notes: 42,
            total_tags: 7,
            notes_per_tag: Vec::new(),
        };

        let service_status = status_from_stats("Note Transport", details, Ok(response));

        assert_eq!(service_status.status, Status::Healthy);
        assert_eq!(service_status.error, None);
        let ServiceDetails::NoteTransportStatus(details) = service_status.details else {
            panic!("expected note transport details");
        };
        assert_eq!(details.version.as_deref(), Some("0.5.0"));
        assert_eq!(details.total_notes, Some(42));
        assert_eq!(details.total_tags, Some(7));
    }

    #[test]
    fn failed_stats_response_is_unhealthy_and_preserves_url() {
        let details = NoteTransportStatusDetails {
            url: "https://nt.example".to_string(),
            ..NoteTransportStatusDetails::default()
        };

        let status = status_from_stats(
            "Note Transport",
            details,
            Err(tonic::Status::unavailable("stats unavailable")),
        );

        assert_eq!(status.status, Status::Unhealthy);
        assert!(status.error.as_deref().is_some_and(|error| {
            error.contains("stats call failed") && error.contains("stats unavailable")
        }));
        let ServiceDetails::NoteTransportStatus(details) = status.details else {
            panic!("expected note transport details");
        };
        assert_eq!(details.url, "https://nt.example");
        assert_eq!(details.version, None);
        assert_eq!(details.total_notes, None);
        assert_eq!(details.total_tags, None);
    }
}
