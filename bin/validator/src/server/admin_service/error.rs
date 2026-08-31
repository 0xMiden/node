//! Error responses shared by every administration endpoint.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use miden_node_tracing::{ErrorReport, error};
use serde::Serialize;

use crate::LOG_TARGET;

#[derive(Debug)]
pub(super) struct ApiError {
    pub(super) status: StatusCode,
    pub(super) message: String,
}

impl ApiError {
    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub(super) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    /// A failure the caller cannot act on, reported to them as `message` alone.
    ///
    /// `cause` is logged rather than returned — the event macro records its display value and
    /// source chain as `exception.message` — because it describes the validator's internals rather
    /// than anything about the request. Logging is the only record of it: these are plain axum
    /// handlers, so they are not covered by the `miden_instrument(err)` fault reporting the gRPC
    /// services get.
    pub(super) fn internal(message: &'static str, cause: &impl ErrorReport) -> Self {
        error!(
            cause,
            target: LOG_TARGET,
            "validator admin API internal error",
            response.message = message #[nonstandard]
        );
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.to_owned(),
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorResponse { error: self.message })).into_response()
    }
}
