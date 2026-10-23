//! The HTTP server.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use miden_node_tracing::info;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::asset::AssetId;
use tokio::net::TcpListener;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::LOG_TARGET;
use crate::db::FundingDatabase;
use crate::status::StatusSnapshot;

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
    /// Durable storage for accepted funding notes.
    pub(crate) database: Arc<FundingDatabase>,
    pub(crate) status: StatusSnapshot,
    /// The native asset the notes hold.
    pub(crate) fee_asset_id: AssetId,
}

/// The HTTP service of the funding service.
pub struct FundingServer {
    state: FundingState,
    request_timeout: Duration,
}

impl FundingServer {
    pub(crate) fn new(
        database: Arc<FundingDatabase>,
        status: StatusSnapshot,
        fee_asset_id: AssetId,
        request_timeout: Duration,
    ) -> Self {
        Self {
            state: FundingState { database, status, fee_asset_id },
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
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;
    use tower::ServiceExt;

    use super::*;

    /// Builds handler state backed by a temporary database.
    pub(crate) async fn test_state(max_amount: u64) -> (tempfile::TempDir, FundingState) {
        let fee_faucet_id = FungibleAsset::mock_issuer();
        let status =
            StatusSnapshot::new(fee_faucet_id, crate::test_utils::test_native_asset(), max_amount);
        let directory = tempfile::tempdir().unwrap();
        let database = FundingDatabase::bootstrap(
            &directory.path().join(crate::lifecycle::DATABASE_FILENAME),
            crate::db::DatabaseIdentity {
                genesis_commitment: Word::from([1u32; 4]),
                funding_account_id: status.account_id(),
                fee_asset_id: AssetId::new_fungible(fee_faucet_id),
            },
        )
        .await
        .unwrap();

        (
            directory,
            FundingState {
                database: Arc::new(database),
                status,
                fee_asset_id: AssetId::new_fungible(fee_faucet_id),
            },
        )
    }

    pub(crate) fn test_router(state: FundingState) -> Router {
        FundingServer {
            state,
            request_timeout: Duration::from_secs(1),
        }
        .router()
    }

    #[tokio::test]
    async fn status_is_served_as_json_on_its_route() {
        let (_directory, state) = test_state(500).await;

        let response = test_router(state)
            .oneshot(Request::get(STATUS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
    }

    /// A malformed account ID must be rejected before persistence.
    #[tokio::test]
    async fn a_malformed_account_id_is_rejected() {
        let (_directory, state) = test_state(500).await;
        let database = Arc::clone(&state.database);

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
        assert!(database.pending_requests(1.try_into().unwrap()).await.unwrap().is_empty());
    }
}
