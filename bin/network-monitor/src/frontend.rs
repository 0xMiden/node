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
use crate::status::{NetworkStatus, RemoteProverDetails, ServiceDetails, ServiceStatus, Status};

// SERVER STATE
// ================================================================================================

/// State for the web server containing watch receivers for all services.
#[derive(Clone)]
pub struct ServerState {
    pub rpc: watch::Receiver<ServiceStatus>,
    pub provers: Vec<(watch::Receiver<ServiceStatus>, watch::Receiver<ServiceStatus>)>,
    pub faucet: Option<watch::Receiver<ServiceStatus>>,
    pub ntx_increment: Option<watch::Receiver<ServiceStatus>>,
    pub ntx_tracking: Option<watch::Receiver<ServiceStatus>>,
    pub explorer: Option<watch::Receiver<ServiceStatus>>,
    pub note_transport: Option<watch::Receiver<ServiceStatus>>,
    pub validator: Option<watch::Receiver<ServiceStatus>>,
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
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();

    let mut services = Vec::new();

    // Collect RPC status
    services.push(server_state.rpc.borrow().clone());

    // Collect faucet status if available
    if let Some(faucet_rx) = &server_state.faucet {
        services.push(faucet_rx.borrow().clone());
    }

    // Collect all remote prover statuses, merging status + test into a single entry per prover.
    for (prover_status_rx, prover_test_rx) in &server_state.provers {
        services.push(merge_prover(&prover_status_rx.borrow(), &prover_test_rx.borrow()));
    }

    // Collect explorer status if available
    if let Some(explorer_rx) = &server_state.explorer {
        services.push(explorer_rx.borrow().clone());
    }

    // Collect counter increment status if enabled
    if let Some(ntx_increment_rx) = &server_state.ntx_increment {
        services.push(ntx_increment_rx.borrow().clone());
    }

    // Collect counter tracking status if enabled
    if let Some(ntx_tracking_rx) = &server_state.ntx_tracking {
        services.push(ntx_tracking_rx.borrow().clone());
    }

    // Collect note transport status if available
    if let Some(note_transport_rx) = &server_state.note_transport {
        services.push(note_transport_rx.borrow().clone());
    }

    // Collect validator status if available
    if let Some(validator_rx) = &server_state.validator {
        services.push(validator_rx.borrow().clone());
    }

    let network_status = NetworkStatus {
        services,
        last_updated: current_time,
        monitor_version: server_state.monitor_version.clone(),
        network_name: server_state.network_name.clone(),
    };

    axum::response::Json(network_status)
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

/// Merges the status and test receivers for a single remote prover into one `ServiceStatus`.
///
/// The combined status is `Unhealthy` if either the status check or the test failed, `Unknown`
/// if the status checker has not yet seen the prover, and `Healthy` otherwise. The test result
/// is only attached when the test task has produced an actual `RemoteProverTest` result (before
/// the first test completes, the test channel holds the initial prover status and should not be
/// surfaced as a test).
fn merge_prover(status: &ServiceStatus, test: &ServiceStatus) -> ServiceStatus {
    // Extract prover status details, or pass through the raw status if the prover is down
    // (details will be `ServiceDetails::Error` in that case).
    let status_details = match &status.details {
        ServiceDetails::ProverStatusCheck(d) => d.clone(),
        _ => return status.clone(),
    };

    // Only attach test details once the test task has produced a real result.
    let (test_details, test_status, test_error) = match &test.details {
        ServiceDetails::ProverTestResult(d) => {
            (Some(d.clone()), Some(test.status.clone()), test.error.clone())
        },
        _ => (None, None, None),
    };

    let details = ServiceDetails::RemoteProverStatus(RemoteProverDetails {
        status: status_details,
        test: test_details,
        test_status: test_status.clone(),
        test_error: test_error.clone(),
    });

    let name = &status.name;
    let base = match (&status.status, &test_status) {
        (Status::Unhealthy, _) | (_, Some(Status::Unhealthy)) => {
            let error = status
                .error
                .clone()
                .or(test_error)
                .unwrap_or_else(|| "prover is unhealthy".to_string());
            ServiceStatus::unhealthy(name, error, details)
        },
        (Status::Unknown, _) => ServiceStatus::unknown(name, details),
        _ => ServiceStatus::healthy(name, details),
    };

    base.with_last_checked(status.last_checked)
}
