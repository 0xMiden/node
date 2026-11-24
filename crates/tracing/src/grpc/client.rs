//! Traces outgoing gRPC requests through the end of their response bodies.

use std::time::Duration;

use tower_http::classify::GrpcFailureClass;
use tower_http::trace::{GrpcMakeClassifier, MakeSpan, OnFailure, Trace};
use tracing::Span;

/// A gRPC transport that creates a client span for each request.
pub type GrpcClientTrace<S> =
    Trace<S, GrpcMakeClassifier, ClientMakeSpan, (), (), (), (), ClientOnFailure>;

/// Wraps the client transport, including any interceptor that injects the current trace context.
pub fn trace_grpc_client<S>(service: S) -> GrpcClientTrace<S> {
    Trace::new_for_grpc(service)
        .make_span_with(ClientMakeSpan)
        .on_request(())
        .on_response(())
        .on_body_chunk(())
        .on_eos(())
        .on_failure(ClientOnFailure)
}

/// Names each client span after the fully qualified gRPC method.
#[derive(Clone, Copy, Debug)]
pub struct ClientMakeSpan;

impl<B> MakeSpan<B> for ClientMakeSpan {
    fn make_span(&mut self, request: &http::Request<B>) -> Span {
        let name = request.uri().path().trim_start_matches('/');
        let (service, method) = name.rsplit_once('/').unwrap_or(("", name));
        crate::info_span!(
            "rpc",
            otel.kind = "client",
            otel.name = name,
            rpc.system = "grpc",
            rpc.service = service,
            rpc.method = method,
        )
    }
}

/// Marks failed calls on their client span, including errors delivered in trailers.
#[derive(Clone, Copy, Debug)]
pub struct ClientOnFailure;

impl OnFailure<GrpcFailureClass> for ClientOnFailure {
    fn on_failure(&mut self, failure: GrpcFailureClass, _: Duration, span: &Span) {
        tracing_opentelemetry::OpenTelemetrySpanExt::set_status(
            span,
            opentelemetry::trace::Status::error(failure.to_string()),
        );
    }
}
