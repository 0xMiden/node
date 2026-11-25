use std::convert::Infallible;

use http::HeaderMap;
use http_body_util::{BodyExt as _, Empty};
use miden_node_tracing::grpc::client::trace_grpc_client;
use miden_node_tracing::grpc::{GrpcTraceLayer, OtelInterceptor, grpc_trace_layer};
use opentelemetry::trace::{Event, SpanKind, Status, TracerProvider as _};
use opentelemetry::{KeyValue, Value};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tonic::service::interceptor::InterceptedService;
use tower::{Layer as _, ServiceExt as _, service_fn};
use tracing::Instrument as _;
use tracing_subscriber::layer::{Layer as _, SubscriberExt as _};

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
        .with(tracing_subscriber::EnvFilter::new("off,miden::rpc::server=info"))
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
    assert_eq!(spans[0].span_kind, SpanKind::Server);
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
        for attributes in [&event.attributes, &span.attributes] {
            assert_eq!(
                attribute(attributes, "exception.message"),
                Some(&Value::from("database unavailable")),
                "{status_in:?}"
            );
        }
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
        assert_eq!(attribute(&span.attributes, "exception.message"), None, "{code:?}");
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

#[tokio::test]
async fn server_spans_use_the_exported_client_or_caller_as_remote_parent() {
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    for export_client in [true, false] {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
        let filter = if export_client {
            "info"
        } else {
            "info,miden::rpc::client=off"
        };
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink))
            .with(
                tracing_opentelemetry::layer()
                    .with_tracer(provider.tracer("test"))
                    .with_filter(tracing_subscriber::EnvFilter::new(filter)),
            );
        let _guard = tracing::subscriber::set_default(subscriber);

        let server =
            grpc_trace_layer().layer(service_fn(|_: http::Request<tonic::body::Body>| async {
                let mut trailers = HeaderMap::new();
                tonic::Status::not_found("account").add_header(&mut trailers).unwrap();
                let body = Empty::<bytes::Bytes>::new()
                    .with_trailers(std::future::ready(Some(Ok(trailers))));
                Ok::<_, Infallible>(http::Response::new(body))
            }));
        let client = trace_grpc_client(InterceptedService::new(server, OtelInterceptor));
        let request = http::Request::post("/rpc.Api/GetAccount")
            .body(tonic::body::Body::empty())
            .unwrap();
        let response =
            client.oneshot(request).instrument(tracing::info_span!("caller")).await.unwrap();
        assert!(
            !exporter
                .get_finished_spans()
                .unwrap()
                .iter()
                .any(|span| span.span_kind == SpanKind::Client)
        );
        response.into_body().collect().await.unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let caller = spans.iter().find(|span| span.name == "caller").unwrap();
        let client = spans.iter().find(|span| span.span_kind == SpanKind::Client);
        let server = spans.iter().find(|span| span.span_kind == SpanKind::Server).unwrap();
        assert_eq!(client.is_some(), export_client);
        if let Some(client) = client {
            assert_eq!(client.name, "rpc.Api/GetAccount");
            assert!(matches!(client.status, Status::Error { .. }));
            assert_eq!(client.parent_span_id, caller.span_context.span_id());
        }
        assert!(server.parent_span_is_remote);
        assert_eq!(server.span_context.trace_id(), caller.span_context.trace_id());
        assert_eq!(server.parent_span_id, client.unwrap_or(caller).span_context.span_id());
    }
}
