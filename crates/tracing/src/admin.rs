//! HTTP endpoints for controlling process tracing on a private administration listener.

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, put};
use axum::{Json, Router, middleware};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use crate::logging::{FILTER_CONTROLS, FilterControls};

/// Returns tracing routes for a private, externally authenticated administration listener.
///
/// Call after [`crate::setup_tracing`] to enable filter updates. Changes replace the selected
/// output's filter until process restart. An OpenTelemetry exporter must be enabled at startup
/// before its filter can be updated. Target listing is available without tracing initialization.
pub fn router() -> Router {
    router_with_controls(FILTER_CONTROLS.get().cloned())
}

fn router_with_controls(controls: Option<FilterControls>) -> Router {
    Router::new()
        .route("/admin/tracing/stdout-filter", put(set_stdout_filter))
        .route("/admin/tracing/otel-filter", put(set_otel_filter))
        .route("/admin/tracing/targets", get(targets))
        .layer(middleware::map_response(no_store))
        .with_state(controls)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilterRequest {
    filter: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type ApiError = (StatusCode, Json<ErrorResponse>);

fn error(status: StatusCode, message: impl Into<String>) -> ApiError {
    (status, Json(ErrorResponse { error: message.into() }))
}

fn controls_unavailable() -> ApiError {
    error(StatusCode::SERVICE_UNAVAILABLE, "tracing filter controls are not initialized")
}

async fn set_stdout_filter(
    State(controls): State<Option<FilterControls>>,
    Json(request): Json<FilterRequest>,
) -> Result<StatusCode, ApiError> {
    let controls = controls.ok_or_else(controls_unavailable)?;
    let filter = parse_filter(&request.filter)?;
    (controls.stdout)(filter).map_err(|_| reload_failed())?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_otel_filter(
    State(controls): State<Option<FilterControls>>,
    Json(request): Json<FilterRequest>,
) -> Result<StatusCode, ApiError> {
    let controls = controls.ok_or_else(controls_unavailable)?;
    let reload = controls.otel.ok_or_else(|| {
        error(StatusCode::CONFLICT, "OpenTelemetry exporting was disabled at startup")
    })?;
    let filter = parse_filter(&request.filter)?;
    reload(filter).map_err(|_| reload_failed())?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_filter(expression: &str) -> Result<EnvFilter, ApiError> {
    EnvFilter::try_new(expression)
        .map_err(|err| error(StatusCode::BAD_REQUEST, format!("invalid tracing filter: {err}")))
}

fn reload_failed() -> ApiError {
    error(StatusCode::INTERNAL_SERVER_ERROR, "failed to update tracing filter")
}

#[derive(Serialize)]
struct TargetsResponse {
    targets: Vec<&'static str>,
}

async fn targets() -> Json<TargetsResponse> {
    Json(TargetsResponse { targets: crate::declared_targets() })
}

async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests;
