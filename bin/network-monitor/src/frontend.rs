//! This file explicitly embeds each of the frontend files into the binary using `include_str!` and
//! `include_bytes!`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use tokio::sync::watch;
use tracing::{info, instrument};

use crate::COMPONENT;
use crate::config::MonitorConfig;
use crate::status::{NetworkStatus, ServiceStatus};

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
///
/// This function runs the frontend server that serves the dashboard and the status data.
///
/// # Arguments
///
/// * `server_state` - The server state containing watch receivers for all services.
/// * `config` - The configuration of the network.
pub async fn serve(server_state: ServerState, config: MonitorConfig) {
    // build our application with routes
    let app = Router::new()
        // Serve embedded assets
        .route("/assets/index.css", get(serve_css))
        .route("/assets/index.js", get(serve_js))
        .route("/assets/favicon.ico", get(serve_favicon))
        // Main dashboard route
        .route("/", get(get_dashboard))
        // API route for status data
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

#[instrument(target = COMPONENT, name = "frontend.get-dashboard", skip_all)]
async fn get_dashboard() -> Html<&'static str> {
    Html(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.html")))
}

#[instrument(target = COMPONENT, name = "frontend.get-status", skip_all)]
async fn get_status(
    axum::extract::State(server_state): axum::extract::State<ServerState>,
) -> axum::response::Json<NetworkStatus> {
    let services: Vec<ServiceStatus> =
        server_state.services.iter().map(|rx| rx.borrow().clone()).collect();

    let last_updated = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();

    axum::response::Json(NetworkStatus {
        services,
        last_updated,
        monitor_version: server_state.monitor_version.clone(),
        network_name: server_state.network_name.clone(),
    })
}

async fn serve_css() -> Response {
    (
        [(header::CONTENT_TYPE, header::HeaderValue::from_static("text/css"))],
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.css")),
    )
        .into_response()
}

async fn serve_js() -> Response {
    (
        [(header::CONTENT_TYPE, header::HeaderValue::from_static("text/javascript"))],
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.js")),
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
