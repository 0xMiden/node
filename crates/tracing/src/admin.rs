//! HTTP endpoints for controlling process tracing on a private administration listener.

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router, middleware};
use serde::{Deserialize, Serialize};

use crate::filter_control::{FILTER_CONTROLS, FilterControl, FilterControls, SetFilterError};

/// Returns tracing routes for a private, externally authenticated administration listener.
///
/// Call after [`crate::setup_tracing`] to enable filter reads and updates. Changes replace the selected
/// output's filter until process restart. An OpenTelemetry exporter must be enabled at startup
/// before its filter can be read or updated. Target listing is available without tracing initialization.
pub fn router() -> Router {
    router_with_controls(FILTER_CONTROLS.get().cloned())
}

fn router_with_controls(controls: Option<FilterControls>) -> Router {
    Router::new()
        .route("/admin/tracing/stdout-filter", get(get_stdout_filter).put(set_stdout_filter))
        .route("/admin/tracing/otel-filter", get(get_otel_filter).put(set_otel_filter))
        .route("/admin/tracing/targets", get(list_targets))
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

#[derive(Serialize)]
struct FilterResponse {
    filter: String,
}

async fn get_stdout_filter(
    State(controls): State<Option<FilterControls>>,
) -> Result<Json<FilterResponse>, ApiError> {
    let controls = controls.ok_or_else(controls_unavailable)?;
    read_filter(controls.stdout.as_ref())
}

async fn get_otel_filter(
    State(controls): State<Option<FilterControls>>,
) -> Result<Json<FilterResponse>, ApiError> {
    let controls = controls.ok_or_else(controls_unavailable)?;
    let control = controls.otel.ok_or_else(otel_disabled)?;
    read_filter(control.as_ref())
}

fn read_filter(control: &dyn FilterControl) -> Result<Json<FilterResponse>, ApiError> {
    let filter = control
        .current_expression()
        .map_err(|cause| internal_error("failed to read tracing filter", &cause))?;
    Ok(Json(FilterResponse { filter }))
}

fn otel_disabled() -> ApiError {
    error(StatusCode::CONFLICT, "OpenTelemetry exporting was disabled at startup")
}

async fn set_stdout_filter(
    State(controls): State<Option<FilterControls>>,
    Json(request): Json<FilterRequest>,
) -> Result<StatusCode, ApiError> {
    let controls = controls.ok_or_else(controls_unavailable)?;
    set_filter(controls.stdout.as_ref(), request.filter)
}

async fn set_otel_filter(
    State(controls): State<Option<FilterControls>>,
    Json(request): Json<FilterRequest>,
) -> Result<StatusCode, ApiError> {
    let controls = controls.ok_or_else(controls_unavailable)?;
    let control = controls.otel.ok_or_else(otel_disabled)?;
    set_filter(control.as_ref(), request.filter)
}

fn set_filter(control: &dyn FilterControl, expression: String) -> Result<StatusCode, ApiError> {
    control.set_expression(expression).map_err(|cause| match cause {
        SetFilterError::InvalidExpression(cause) => {
            error(StatusCode::BAD_REQUEST, format!("invalid tracing filter: {cause}"))
        },
        SetFilterError::Internal(cause) => {
            internal_error("failed to update tracing filter", &cause)
        },
    })?;
    Ok(StatusCode::NO_CONTENT)
}

fn internal_error(message: &'static str, cause: &anyhow::Error) -> ApiError {
    crate::error_v2!(cause, "tracing admin API internal error");
    error(StatusCode::INTERNAL_SERVER_ERROR, message)
}

#[derive(Serialize)]
struct TargetsResponse {
    targets: Vec<&'static str>,
}

async fn list_targets() -> Json<TargetsResponse> {
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
