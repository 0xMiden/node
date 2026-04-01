use std::any::Any;

use http::{Response, StatusCode, header};
use http_body_util::Full;
pub use tower_http::catch_panic::CatchPanicLayer;

use crate::tracing::OpenTelemetrySpanExt;

/// Custom callback that is used by Tower to fulfill the
/// [`tower_http::catch_panic::ResponseForPanic`] trait.
///
/// This should be added to tonic server builder as a layer via [`CatchPanicLayer::custom()`].
#[track_caller]
pub fn catch_panic_layer_fn(err: Box<dyn Any + Send + 'static>) -> Response<Full<bytes::Bytes>> {
    // Log the panic error details.
    let err = stringify_panic_error(err);
    tracing::error!(panic = true, error = %err, "panic");

    // Mark the current span as failed for OpenTelemetry.
    let wrapped = anyhow::Error::msg(err.clone());
    tracing::Span::current().set_error(wrapped.as_ref());

    // Return generic error response.
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/grpc")
        .body(Full::from(""))
        .unwrap()
}

/// Converts a dynamic panic-related error into a string.
fn stringify_panic_error(err: Box<dyn Any + Send + 'static>) -> String {
    if let Some(&msg) = err.downcast_ref::<&str>() {
        msg.to_string()
    } else if let Ok(msg) = err.downcast::<String>() {
        *msg
    } else {
        "unknown".to_string()
    }
}
