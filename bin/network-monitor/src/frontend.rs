//! HTTP frontend for the network monitor.
//!
//! Routes:
//! - `GET /` — full dashboard rendered with [`maud`].
//! - `GET /fragments/status` — card grid only, swapped into `#status-container` by htmx every 10s.
//! - `GET /status` — JSON snapshot, kept for external consumers.
//! - Static assets (CSS, htmx bundle, probes.js, favicon) embedded at compile time via
//!   `include_str!` / `include_bytes!`.

use axum::Router;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use maud::Markup;
use miden_node_utils::tracing::miden_instrument;
use tokio::sync::watch;
use tracing::info;

use crate::config::MonitorConfig;
use crate::status::{NetworkStatus, ServiceStatus};
use crate::{COMPONENT, view};

// SERVER STATE
// ================================================================================================

/// State for the web server containing watch receivers for all services.
///
/// Each entry in `services` is a `ServiceStatus` channel. The frontend simply snapshots every
/// entry on each `/status` request. Adding a new service is just pushing another receiver into
/// this Vec at startup; no changes to this struct or `get_status` are required.
#[derive(Clone)]
pub struct ServerState {
    pub services: Vec<watch::Receiver<ServiceStatus>>,
    pub monitor_version: String,
    pub network_name: String,
}

/// Runs the frontend server.
pub async fn serve(server_state: ServerState, config: MonitorConfig) {
    let app = Router::new()
        .route("/assets/index.css", get(serve_css))
        .route("/assets/htmx.min.js", get(serve_htmx))
        .route("/assets/probes.js", get(serve_probes_js))
        .route("/assets/favicon.ico", get(serve_favicon))
        .route("/", get(get_dashboard))
        .route("/fragments/status", get(get_status_fragment))
        .route("/status", get(get_status))
        .with_state(server_state);

    let bind_address = format!("0.0.0.0:{}", config.port);
    info!("Starting web server on {bind_address}");
    info!("Dashboard available at: http://localhost:{}/", config.port);
    let listener = tokio::net::TcpListener::bind(&bind_address)
        .await
        .expect("Failed to bind to address");
    axum::serve(listener, app).await.expect("Failed to start web server");
}

// HTML ROUTES
// ================================================================================================

#[miden_instrument(
    target = COMPONENT,
    name = "frontend.get-dashboard",
    skip_all,
)]
async fn get_dashboard(
    axum::extract::State(server_state): axum::extract::State<ServerState>,
) -> Markup {
    view::page(&server_state)
}

#[miden_instrument(
    target = COMPONENT,
    name = "frontend.get-status-fragment",
    skip_all,
)]
async fn get_status_fragment(
    axum::extract::State(server_state): axum::extract::State<ServerState>,
) -> Markup {
    view::status_fragment(&view::snapshot(&server_state))
}

// JSON ROUTE
// ================================================================================================

#[miden_instrument(
    target = COMPONENT,
    name = "frontend.get-status",
    skip_all,
)]
async fn get_status(
    axum::extract::State(server_state): axum::extract::State<ServerState>,
) -> axum::response::Json<NetworkStatus> {
    axum::response::Json(view::snapshot(&server_state))
}

// STATIC ASSETS
// ================================================================================================

async fn serve_css() -> Response {
    (
        [(header::CONTENT_TYPE, header::HeaderValue::from_static("text/css"))],
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.css")),
    )
        .into_response()
}

async fn serve_htmx() -> Response {
    (
        [(header::CONTENT_TYPE, header::HeaderValue::from_static("text/javascript"))],
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/htmx.min.js")),
    )
        .into_response()
}

async fn serve_probes_js() -> Response {
    (
        [(header::CONTENT_TYPE, header::HeaderValue::from_static("text/javascript"))],
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/probes.js")),
    )
        .into_response()
}

async fn serve_favicon() -> Response {
    (
        [(header::CONTENT_TYPE, header::HeaderValue::from_static("image/x-icon"))],
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/favicon.ico")),
    )
        .into_response()
}
