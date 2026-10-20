use std::convert::Infallible;

use http::HeaderMap;
use http_body_util::{BodyExt as _, Empty};
use miden_node_tracing::grpc::{GrpcTraceLayer, grpc_trace_layer};
use opentelemetry::trace::{Event, Status, TracerProvider as _};
use opentelemetry::{KeyValue, Value};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tower::{Layer as _, ServiceExt as _, service_fn};
use tracing_subscriber::layer::SubscriberExt as _;

/// Where the server puts the response's gRPC status.
#[derive(Clone, Copy, Debug)]
enum StatusIn {
    /// A trailers-only response, as tonic returns a handler's error.
    Headers,
    /// The trailers after the response body, as tonic returns a successful or streamed response.
    Trailers,
}

/// Sends one request through `layer` to a server that responds with `status`, reads the response
/// body, and returns the exported request span.
fn request_span(layer: &GrpcTraceLayer, status: &tonic::Status, status_in: StatusIn) -> SpanData {
    let mut status_headers = HeaderMap::new();
    status.add_header(&mut status_headers).unwrap();

    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::OpenTelemetryLayer::new(provider.tracer("test")));
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    tracing::subscriber::with_default(subscriber, || {
        let service =
            layer.layer(service_fn(move |_request: http::Request<Empty<bytes::Bytes>>| {
                let (headers, trailers) = match status_in {
                    StatusIn::Headers => (status_headers.clone(), None),
                    StatusIn::Trailers => (HeaderMap::new(), Some(Ok(status_headers.clone()))),
                };
                let mut response = http::Response::new(
                    Empty::<bytes::Bytes>::new().with_trailers(std::future::ready(trailers)),
                );
                *response.headers_mut() = headers;
                async move { Ok::<_, Infallible>(response) }
            }));
        let request = http::Request::post("http://localhost/rpc.Api/GetAccount")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(Empty::new())
            .unwrap();
        runtime.block_on(async {
            let response = service.oneshot(request).await.unwrap();
            response.into_body().collect().await.unwrap();
        });
    });
    provider.force_flush().unwrap();
    let mut spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1, "{spans:?}");
    spans.remove(0)
}

fn attribute<'a>(attributes: &'a [KeyValue], name: &str) -> Option<&'a Value> {
    attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == name)
        .map(|attribute| &attribute.value)
}

/// Returns the span's `rpc.grpc.status_code`, which must be recorded at most once.
fn status_code(span: &SpanData) -> Option<&Value> {
    let mut codes = span
        .attributes
        .iter()
        .filter(|attribute| attribute.key.as_str() == "rpc.grpc.status_code");
    let code = codes.next().map(|attribute| &attribute.value);
    assert!(codes.next().is_none(), "status code recorded twice: {:?}", span.attributes);
    code
}

/// Returns the span's "request failed" event.
fn failure_event(span: &SpanData) -> Option<&Event> {
    span.events.iter().find(|event| event.name == "request failed")
}

fn event_attribute(event: &Event, name: &str) -> Option<String> {
    attribute(&event.attributes, name).map(Value::to_string)
}

#[test]
fn successful_requests_record_the_ok_status_code() {
    for status_in in [StatusIn::Headers, StatusIn::Trailers] {
        let span = request_span(&grpc_trace_layer(), &tonic::Status::ok(""), status_in);
        assert_eq!(status_code(&span), Some(&Value::I64(0)), "{status_in:?}");
        assert!(failure_event(&span).is_none(), "{status_in:?}");
        assert_eq!(span.status, Status::Unset, "{status_in:?}");
    }
}

#[test]
fn failed_requests_record_and_log_their_status() {
    for status_in in [StatusIn::Headers, StatusIn::Trailers] {
        let status = tonic::Status::internal("database unavailable");
        let span = request_span(&grpc_trace_layer(), &status, status_in);
        assert_eq!(
            status_code(&span),
            Some(&Value::I64(tonic::Code::Internal as i64)),
            "{status_in:?}"
        );
        let event = failure_event(&span).expect("failure is logged");
        assert_eq!(event_attribute(event, "level").as_deref(), Some("ERROR"), "{status_in:?}");
        assert_eq!(
            event_attribute(event, "grpc.message").as_deref(),
            Some("database unavailable"),
            "{status_in:?}"
        );
        assert_eq!(span.status, Status::error(""), "{status_in:?}");
    }
}

#[test]
fn client_errors_are_logged_at_info() {
    for code in [
        tonic::Code::InvalidArgument,
        tonic::Code::NotFound,
        tonic::Code::FailedPrecondition,
        tonic::Code::ResourceExhausted,
        tonic::Code::Unknown,
        tonic::Code::Unimplemented,
    ] {
        let span =
            request_span(&grpc_trace_layer(), &tonic::Status::new(code, ""), StatusIn::Headers);
        assert_eq!(status_code(&span), Some(&Value::I64(code as i64)), "{code:?}");
        let event = failure_event(&span).expect("failure is logged");
        assert_eq!(event_attribute(event, "level").as_deref(), Some("INFO"), "{code:?}");
        assert_eq!(span.status, Status::Unset, "{code:?}");
    }
}

#[test]
fn server_errors_are_logged_as_errors() {
    for code in [tonic::Code::Internal, tonic::Code::DataLoss, tonic::Code::Unavailable] {
        let span =
            request_span(&grpc_trace_layer(), &tonic::Status::new(code, ""), StatusIn::Headers);
        let event = failure_event(&span).expect("failure is logged");
        assert_eq!(event_attribute(event, "level").as_deref(), Some("ERROR"), "{code:?}");
        assert_eq!(span.status, Status::error(""), "{code:?}");
    }
}
