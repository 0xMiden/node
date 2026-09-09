//! The HTTP server.

use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use miden_node_tracing::info;
use miden_node_utils::shutdown::CancellationToken;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::LOG_TARGET;
use crate::status::StatusSnapshot;
use crate::worker::FundingRequest;

mod request_funds;
mod status;

// FUNDING SERVICE HTTP SERVER
// ================================================================================================

/// Path of the status endpoint.
const STATUS_PATH: &str = "/status";

/// Path of the funding endpoint.
const REQUEST_FUNDS_PATH: &str = "/request-funds";

/// The state the handlers share.
#[derive(Clone)]
pub(crate) struct FundingState {
    pub(crate) requests: mpsc::Sender<FundingRequest>,
    pub(crate) status: StatusSnapshot,
}

/// The HTTP service of the funding service.
pub struct FundingServer {
    state: FundingState,
    request_timeout: Duration,
}

impl FundingServer {
    pub(crate) fn new(
        requests: mpsc::Sender<FundingRequest>,
        status: StatusSnapshot,
        request_timeout: Duration,
    ) -> Self {
        Self {
            state: FundingState { requests, status },
            request_timeout,
        }
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
            .route(REQUEST_FUNDS_PATH, post(request_funds::request_funds))
            .layer(TraceLayer::new_for_http())
            // The server cancels a handler which runs longer than the timeout. The client then
            // receives the status code 408.
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                self.request_timeout,
            ))
            .with_state(self.state)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use miden_protocol::asset::FungibleAsset;
    use tower::ServiceExt;

    use super::*;

    /// Builds a server whose worker channel is held by the caller, so a test can assert on what the
    /// handlers queued without running a worker.
    pub(crate) fn test_state(max_amount: u64) -> (FundingState, mpsc::Receiver<FundingRequest>) {
        let (requests, rx) = mpsc::channel(4);
        let status = StatusSnapshot::new(FungibleAsset::mock_issuer(), max_amount);

        (FundingState { requests, status }, rx)
    }

    fn test_router(state: FundingState) -> Router {
        FundingServer {
            state,
            request_timeout: Duration::from_secs(1),
        }
        .router()
    }

    #[tokio::test]
    async fn status_is_served_as_json_on_its_route() {
        let (state, _rx) = test_state(500);

        let response = test_router(state)
            .oneshot(Request::get(STATUS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
    }

    /// A malformed account ID must be rejected before the request reaches the worker.
    #[tokio::test]
    async fn a_malformed_account_id_is_rejected() {
        let (state, mut rx) = test_state(500);

        let response = test_router(state)
            .oneshot(
                Request::post(REQUEST_FUNDS_PATH)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"account_id":"not hex","amount":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(rx.try_recv().is_err(), "no request should reach the worker");
    }
}
