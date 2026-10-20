use std::time::Duration;

use http::header::HeaderName;
use tower_governor::key_extractor::{KeyExtractor, SmartIpKeyExtractor};
use tower_http::classify::GrpcFailureClass;
use tower_http::trace::{
    DefaultOnBodyChunk,
    DefaultOnEos,
    DefaultOnRequest,
    DefaultOnResponse,
    GrpcMakeClassifier,
    MakeSpan,
    OnFailure,
    OnResponse,
    TraceLayer,
};
use tracing::field;

use crate::FailureClass;

/// The [`TraceLayer`] for gRPC servers returned by [`grpc_trace_layer`] and
/// [`public_grpc_trace_layer`].
pub type GrpcTraceLayer = TraceLayer<
    GrpcMakeClassifier,
    GrpcMakeSpan,
    DefaultOnRequest,
    GrpcOnResponse,
    DefaultOnBodyChunk,
    DefaultOnEos,
    GrpcOnFailure,
>;

/// Returns the trace layer for a gRPC server that only trusted components call.
///
/// Each request gets a root span from [`grpc_trace_fn`] that records the response's gRPC status
/// code as `rpc.grpc.status_code`, `0` on success. A failed request also records the
/// [`FailureClass`] of its code as `failure.class` and `failure.kind`. Only a node failure marks
/// the span as failed; a rejected request is logged at `INFO`.
pub fn grpc_trace_layer() -> GrpcTraceLayer {
    trace_layer(GrpcOnFailure { public: false })
}

/// Returns the trace layer for a gRPC server exposed to the public, such as the RPC.
///
/// This is [`grpc_trace_layer`], except that `UNKNOWN` and `UNIMPLEMENTED` responses are
/// rejections rather than faults.
///
/// Scanners probing a public endpoint for paths such as `.env` or for methods that do not exist
/// receive these codes. They describe the request, not a node failure, and would otherwise flood
/// the alerts on failed spans.
pub fn public_grpc_trace_layer() -> GrpcTraceLayer {
    trace_layer(GrpcOnFailure { public: true })
}

fn trace_layer(on_failure: GrpcOnFailure) -> GrpcTraceLayer {
    TraceLayer::new_for_grpc()
        .make_span_with(GrpcMakeSpan)
        .on_response(GrpcOnResponse::default())
        .on_failure(on_failure)
}

/// Creates the root span of each request with [`grpc_trace_fn`].
#[derive(Clone, Copy, Debug)]
pub struct GrpcMakeSpan;

impl<B> MakeSpan<B> for GrpcMakeSpan {
    fn make_span(&mut self, request: &http::Request<B>) -> tracing::Span {
        grpc_trace_fn(request)
    }
}

/// Records the gRPC status code of a response as `rpc.grpc.status_code`.
///
/// A unary error response carries its status in the headers. Other responses carry it in the
/// trailers, so `0` is recorded until [`GrpcOnFailure`] overwrites it with a failed status.
#[derive(Clone, Debug, Default)]
pub struct GrpcOnResponse(DefaultOnResponse);

impl<B> OnResponse<B> for GrpcOnResponse {
    fn on_response(self, response: &http::Response<B>, latency: Duration, span: &tracing::Span) {
        let code = response
            .headers()
            .get("grpc-status")
            .and_then(|code| code.to_str().ok()?.parse::<i32>().ok())
            .unwrap_or(tonic::Code::Ok as i32);
        span.record("rpc.grpc.status_code", code);
        self.0.on_response(response, latency, span);
    }
}

/// Records the status code and failure class of a failed request, and marks its span as failed
/// unless the request was rejected.
#[derive(Clone, Copy, Debug)]
pub struct GrpcOnFailure {
    public: bool,
}

impl GrpcOnFailure {
    fn classify(self, code: tonic::Code) -> FailureClass {
        let class = FailureClass::from_grpc_code(code);
        match code {
            tonic::Code::Unknown | tonic::Code::Unimplemented if self.public => {
                FailureClass::Rejected(class.kind())
            },
            _ => class,
        }
    }
}

impl OnFailure<GrpcFailureClass> for GrpcOnFailure {
    fn on_failure(
        &mut self,
        classification: GrpcFailureClass,
        latency: Duration,
        span: &tracing::Span,
    ) {
        let (code, failure) = match &classification {
            GrpcFailureClass::Code(code) => {
                let code = tonic::Code::from_i32(code.get());
                (code, self.classify(code))
            },
            // The response stream failed without a gRPC status.
            GrpcFailureClass::Error(_) => (tonic::Code::Unknown, FailureClass::Fault("stream")),
        };
        span.record("rpc.grpc.status_code", code as i32);
        failure.record(span);
        if failure.is_rejection() {
            tracing::info!(
                parent: span,
                classification = %classification,
                latency = ?latency,
                "request rejected"
            );
        } else {
            tracing::error!(
                parent: span,
                classification = %classification,
                latency = ?latency,
                "response failed"
            );
        }
    }
}

/// Returns a [`trace_fn`](tonic::transport::server::Server) implementation for gRPC requests
/// which adds open-telemetry information to the span.
///
/// Creates an `info` span following the open-telemetry standard: `{service}/{method}`.
/// The span name is dynamically set using the HTTP path via the `otel.name` field.
/// Additionally also pulls in remote tracing context which allows the server trace to be connected
/// to the client's origin trace.
#[track_caller]
pub fn grpc_trace_fn<T>(request: &http::Request<T>) -> tracing::Span {
    // A gRPC request's path ends with `../<service>/<method>`.
    let mut path_segments = request.uri().path().rsplit('/');

    let method = path_segments.next().unwrap_or_default();
    let service = path_segments.next().unwrap_or_default();

    // Create a span with a generic, static name. Fields to be recorded after needs to be
    // initialized as empty since otherwise the assignment will have no effect.
    let span = tracing::info_span!(
        "rpc",
        otel.name = field::Empty,
        rpc.service = service,
        rpc.method = method,
        rpc.system = field::Empty,
        rpc.request.size = field::Empty,
        rpc.response.size = field::Empty,
        rpc.grpc.status_code = field::Empty,
        server.address = field::Empty,
        server.port = field::Empty,
        client.address = field::Empty,
        client.port = field::Empty,
        network.peer.address = field::Empty,
        network.peer.port = field::Empty,
        network.transport = field::Empty,
        network.type = field::Empty,
    );

    // Set the span name via otel.name
    let otel_name = format!("{service}/{method}");
    span.record("otel.name", otel_name);

    // Pull the open-telemetry parent context using the HTTP extractor
    let otel_ctx = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&MetadataExtractor(&tonic::metadata::MetadataMap::from_headers(
            request.headers().clone(),
        )))
    });
    let _ = tracing_opentelemetry::OpenTelemetrySpanExt::set_parent(&span, otel_ctx);

    // Adds various network attributes to the span, including remote address and port.
    //
    // See [server attributes](https://opentelemetry.io/docs/specs/semconv/rpc/rpc-spans/#server-attributes).

    // Set HTTP attributes.
    span.record("rpc.system", "grpc");
    if let Some(host) = request.uri().host() {
        span.record("server.address", host);
    }
    if let Some(host_port) = request.uri().port() {
        span.record("server.port", host_port.as_u16());
    }
    let remote_addr = request
        .extensions()
        .get::<tonic::transport::server::TcpConnectInfo>()
        .and_then(tonic::transport::server::TcpConnectInfo::remote_addr);

    // client.address should be the resolved IP address of the client, if available. In the case of
    // a reverse proxy, this may not be the same as the remote address.
    if let Ok(ip) = SmartIpKeyExtractor.extract(request) {
        span.record("client.address", field::display(ip));
    } else if let Some(addr) = remote_addr {
        span.record("client.address", field::display(addr.ip()));
        span.record("client.port", addr.port());
    }

    if let Some(addr) = remote_addr {
        span.record("network.peer.address", field::display(addr.ip()));
        span.record("network.peer.port", addr.port());
        span.record("network.transport", "tcp");
        match addr.ip() {
            std::net::IpAddr::V4(_) => span.record("network.type", "ipv4"),
            std::net::IpAddr::V6(_) => span.record("network.type", "ipv6"),
        };
    }

    for header in [
        http::header::ACCEPT,
        http::header::ORIGIN,
        http::header::USER_AGENT,
        http::header::FORWARDED,
        HeaderName::from_static("x-forwarded-for"),
        HeaderName::from_static("x-real-ip"),
        HeaderName::from_static("x-request-id"),
    ] {
        if let Some(value) = request.headers().get(&header) {
            if let Ok(value) = value.to_str() {
                tracing_opentelemetry::OpenTelemetrySpanExt::set_attribute(
                    &span,
                    format!("http.request.header.{header}"),
                    value.to_owned(),
                );
            }
        }
    }

    span
}

/// Injects open-telemetry remote context into traces.
#[derive(Copy, Clone)]
pub struct OtelInterceptor;

impl tonic::service::Interceptor for OtelInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        let ctx = tracing::Span::current().context();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&ctx, &mut MetadataInjector(request.metadata_mut()));
        });

        Ok(request)
    }
}

struct MetadataExtractor<'a>(&'a tonic::metadata::MetadataMap);
impl opentelemetry::propagation::Extractor for MetadataExtractor<'_> {
    /// Get a value for a key from the `MetadataMap`.  If the value can't be converted to &str,
    /// returns None
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|metadata| metadata.to_str().ok())
    }

    /// Collect all the keys from the `MetadataMap`.
    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(|key| match key {
                tonic::metadata::KeyRef::Ascii(v) => v.as_str(),
                tonic::metadata::KeyRef::Binary(v) => v.as_str(),
            })
            .collect::<Vec<_>>()
    }
}

struct MetadataInjector<'a>(&'a mut tonic::metadata::MetadataMap);
impl opentelemetry::propagation::Injector for MetadataInjector<'_> {
    /// Set a key and value in the `MetadataMap`.  Does nothing if the key or value are not valid
    /// inputs
    fn set(&mut self, key: &str, value: String) {
        if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(key.as_bytes())
            && let Ok(val) = tonic::metadata::MetadataValue::try_from(&value)
        {
            self.0.insert(key, val);
        }
    }
}
