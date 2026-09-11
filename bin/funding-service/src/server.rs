//! The HTTP server.

use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use miden_node_tracing::info;
use miden_node_utils::shutdown::CancellationToken;
use tokio::net::TcpListener;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::LOG_TARGET;
use crate::status::StatusSnapshot;

mod status;

// FUNDING SERVICE HTTP SERVER
// ================================================================================================

/// Path of the status endpoint.
const STATUS_PATH: &str = "/status";

/// The HTTP service of the funding service.
pub struct FundingServer {
    status: StatusSnapshot,
    request_timeout: Duration,
}

impl FundingServer {
    pub(crate) fn new(status: StatusSnapshot, request_timeout: Duration) -> Self {
        Self { status, request_timeout }
    }

    /// Starts the HTTP server on the given listener.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let endpoint = listener
            .local_addr()
            .context("failed to read the funding service listen address")?;
        info!(
            target: LOG_TARGET,
            "Funding service HTTP API listening",
            service.name = "miden-funding-service",
            service.version = env!("CARGO_PKG_VERSION"),
            funding_service.listen = endpoint.to_string()
        );

        axum::serve(listener, self.router())
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .context("failed to serve the funding service HTTP API")
    }

    /// Builds the router of the API.
    fn router(self) -> Router {
        Router::new()
            .route(STATUS_PATH, get(status::status))
            .layer(TraceLayer::new_for_http())
            // The server cancels a handler which runs longer than the timeout. The client then
            // receives the status code 408.
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                self.request_timeout,
            ))
            .with_state(self.status)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use miden_protocol::asset::FungibleAsset;
    use tower::ServiceExt;

    use super::*;

    /// Builds a status snapshot for the handler tests.
    pub(crate) fn test_status(max_amount: u64) -> StatusSnapshot {
        StatusSnapshot::new(FungibleAsset::mock_issuer(), max_amount)
    }

    fn test_router(status: StatusSnapshot) -> Router {
        FundingServer::new(status, Duration::from_secs(1)).router()
    }

    #[tokio::test]
    async fn status_is_served_as_json_on_its_route() {
        let response = test_router(test_status(500))
            .oneshot(Request::get(STATUS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
    }
}
