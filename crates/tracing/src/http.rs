//! HTTP server request spans.

use std::time::Duration;

use axum::extract::MatchedPath;
use http::{Request, Response};
use opentelemetry::trace::Status;
use tower_http::trace::{
    DefaultOnRequest,
    DefaultOnResponse,
    HttpMakeClassifier,
    MakeSpan,
    OnResponse,
    TraceLayer,
};
use tracing::{Span, field};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

/// Creates one server span per request, including responses produced by middleware.
pub fn http_trace_layer()
-> TraceLayer<HttpMakeClassifier, HttpMakeSpan, DefaultOnRequest, HttpOnResponse> {
    TraceLayer::new_for_http()
        .make_span_with(HttpMakeSpan)
        .on_response(HttpOnResponse::default())
}

/// Names server spans by method and matched route so path parameters and query strings stay
/// private.
#[derive(Clone, Copy)]
pub struct HttpMakeSpan;

impl<B> MakeSpan<B> for HttpMakeSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let route = request.extensions().get::<MatchedPath>().map(MatchedPath::as_str);
        // OpenTelemetry uses `_OTHER` for the method attribute and `HTTP` in the span name for
        // unknown methods. This keeps arbitrary client-supplied methods from creating unbounded
        // numbers of distinct attribute values and span names.
        let method = match request.method().as_str() {
            known @ ("GET" | "POST" | "DELETE" | "PUT" | "PATCH" | "HEAD" | "OPTIONS" | "TRACE"
            | "CONNECT") => known,
            _ => "_OTHER",
        };
        let name = if method == "_OTHER" { "HTTP" } else { method };
        let span = crate::info_span!(
            "request",
            otel.kind = "server",
            otel.name = name,
            http.request.method = method,
            http.route = route,
            http.response.status_code = field::Empty,
        );
        if let Some(route) = route {
            span.record("otel.name", format_args!("{name} {route}"));
        }
        span
    }
}

/// Records the HTTP status and marks server errors on the request span.
#[derive(Clone, Default)]
pub struct HttpOnResponse(DefaultOnResponse);

impl<B> OnResponse<B> for HttpOnResponse {
    fn on_response(self, response: &Response<B>, latency: Duration, span: &Span) {
        let status = response.status();
        span.record("http.response.status_code", i64::from(status.as_u16()));
        if status.is_server_error() {
            span.set_status(Status::error(""));
        }
        self.0.on_response(response, latency, span);
    }
}
