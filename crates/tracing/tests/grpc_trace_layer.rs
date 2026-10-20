use std::convert::Infallible;

use http_body_util::Empty;
use miden_node_tracing::grpc::{GrpcTraceLayer, grpc_trace_layer, public_grpc_trace_layer};
use opentelemetry::trace::{Status, TracerProvider as _};
use opentelemetry::{KeyValue, Value};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tower::{Layer as _, ServiceExt as _, service_fn};
use tracing_subscriber::layer::SubscriberExt as _;

/// Sends one request through `layer` to a server that responds with the gRPC status `code` in the
/// headers, and returns the exported request span.
fn request_span(layer: &GrpcTraceLayer, code: tonic::Code) -> SpanData {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::OpenTelemetryLayer::new(provider.tracer("test")));
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    tracing::subscriber::with_default(subscriber, || {
        let service =
            layer.layer(service_fn(move |_request: http::Request<Empty<bytes::Bytes>>| {
                let response = http::Response::builder()
                    .header("grpc-status", (code as i32).to_string())
                    .body(Empty::<bytes::Bytes>::new())
                    .unwrap();
                async move { Ok::<_, Infallible>(response) }
            }));
        let request = http::Request::post("http://localhost/rpc.Api/SubmitProvenTx")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(Empty::new())
            .unwrap();
        runtime.block_on(service.oneshot(request)).unwrap();
    });
    provider.force_flush().unwrap();
    let mut spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1, "{spans:?}");
    spans.remove(0)
}

fn attribute<'a>(span: &'a SpanData, name: &str) -> Option<&'a Value> {
    span.attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == name)
        .map(|attribute: &KeyValue| &attribute.value)
}

fn assert_failure(span: &SpanData, code: tonic::Code, class: &str, kind: &str) {
    assert_eq!(attribute(span, "rpc.grpc.status_code"), Some(&Value::I64(code as i64)));
    assert_eq!(attribute(span, "failure.class"), Some(&Value::from(class.to_owned())));
    assert_eq!(attribute(span, "failure.kind"), Some(&Value::from(kind.to_owned())));
}

#[test]
fn successful_requests_record_the_ok_status_code() {
    let span = request_span(&grpc_trace_layer(), tonic::Code::Ok);
    assert_eq!(attribute(&span, "rpc.grpc.status_code"), Some(&Value::I64(0)));
    assert_eq!(attribute(&span, "failure.class"), None);
    assert_eq!(span.status, Status::Unset);
}

#[test]
fn rejected_requests_do_not_fail_the_span() {
    for (code, kind) in [
        (tonic::Code::InvalidArgument, "invalid_argument"),
        (tonic::Code::FailedPrecondition, "failed_precondition"),
        (tonic::Code::ResourceExhausted, "resource_exhausted"),
    ] {
        let span = request_span(&grpc_trace_layer(), code);
        assert_failure(&span, code, "rejected", kind);
        assert_eq!(span.status, Status::Unset, "{code:?}");
    }
}

#[test]
fn node_failures_fail_the_span() {
    for (code, class, kind) in [
        (tonic::Code::Unavailable, "transient", "unavailable"),
        (tonic::Code::Internal, "fault", "internal"),
        (tonic::Code::Unknown, "fault", "unknown"),
        (tonic::Code::Unimplemented, "fault", "unimplemented"),
    ] {
        let span = request_span(&grpc_trace_layer(), code);
        assert_failure(&span, code, class, kind);
        assert_eq!(span.status, Status::error(""), "{code:?}");
    }
}

#[test]
fn public_servers_reject_unknown_and_unimplemented_requests() {
    for (code, kind) in
        [(tonic::Code::Unknown, "unknown"), (tonic::Code::Unimplemented, "unimplemented")]
    {
        let span = request_span(&public_grpc_trace_layer(), code);
        assert_failure(&span, code, "rejected", kind);
        assert_eq!(span.status, Status::Unset, "{code:?}");
    }
    let span = request_span(&public_grpc_trace_layer(), tonic::Code::Internal);
    assert_eq!(span.status, Status::error(""));
}
