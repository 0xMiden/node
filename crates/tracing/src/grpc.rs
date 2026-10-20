use std::time::Duration;

use http::HeaderMap;
use http::header::HeaderName;
use tower_governor::key_extractor::{KeyExtractor, SmartIpKeyExtractor};
use tower_http::classify::GrpcFailureClass;
use tower_http::trace::{
    DefaultOnBodyChunk,
    DefaultOnRequest,
    DefaultOnResponse,
    GrpcMakeClassifier,
    MakeSpan,
    OnEos,
    OnFailure,
    OnResponse,
    TraceLayer,
};
use tracing::{Level, field};

/// The [`TraceLayer`] returned by [`grpc_trace_layer`] and [`public_grpc_trace_layer`].
pub type GrpcTraceLayer = TraceLayer<
    GrpcMakeClassifier,
    GrpcMakeSpan,
    DefaultOnRequest,
    GrpcOnResponse,
    DefaultOnBodyChunk,
    GrpcOnEos,
    GrpcOnFailure,
>;

/// Returns the trace layer for a gRPC server that only trusted components call.
///
/// Each request gets a root span from [`grpc_trace_fn`] that records the response's gRPC status
/// code as `rpc.grpc.status_code`. A failed request is logged once on that span at `ERROR`, with
/// its status code and message.
pub fn grpc_trace_layer() -> GrpcTraceLayer {
    trace_layer(GrpcFailureLevels { public: false })
}

/// Returns the trace layer for a gRPC server exposed to the public, such as the RPC.
///
/// This is [`grpc_trace_layer`], except that only `INTERNAL`, `DATA_LOSS` and `UNAVAILABLE`
/// responses are logged at `ERROR`. Other failed requests are logged at `INFO`.
///
/// Clients cause the other codes, for example by requesting an unknown account or, for scanners,
/// a method that does not exist. Logging them at `INFO` keeps them out of the error logs and
/// leaves the request span's status unset.
pub fn public_grpc_trace_layer() -> GrpcTraceLayer {
    trace_layer(GrpcFailureLevels { public: true })
}

fn trace_layer(levels: GrpcFailureLevels) -> GrpcTraceLayer {
    TraceLayer::new_for_grpc()
        .make_span_with(GrpcMakeSpan)
        .on_response(GrpcOnResponse {
            levels,
            inner: DefaultOnResponse::default(),
        })
        .on_eos(GrpcOnEos { levels })
        .on_failure(GrpcOnFailure)
}

/// Creates the root span of each request with [`grpc_trace_fn`].
#[derive(Clone, Copy, Debug)]
pub struct GrpcMakeSpan;

impl<B> MakeSpan<B> for GrpcMakeSpan {
    fn make_span(&mut self, request: &http::Request<B>) -> tracing::Span {
        grpc_trace_fn(request)
    }
}

/// Records the gRPC status of a response that carries it in its headers.
///
/// A handler's error is returned in the headers. Other responses carry their status in the
/// trailers, which [`GrpcOnEos`] records.
#[derive(Clone, Debug)]
pub struct GrpcOnResponse {
    levels: GrpcFailureLevels,
    inner: DefaultOnResponse,
}

impl<B> OnResponse<B> for GrpcOnResponse {
    fn on_response(self, response: &http::Response<B>, latency: Duration, span: &tracing::Span) {
        if let Some(status) = tonic::Status::from_header_map(response.headers()) {
            self.levels.record(&status, latency, span);
        }
        self.inner.on_response(response, latency, span);
    }
}

/// Records the gRPC status of a response that carries it in its trailers.
#[derive(Clone, Copy, Debug)]
pub struct GrpcOnEos {
    levels: GrpcFailureLevels,
}

impl OnEos for GrpcOnEos {
    fn on_eos(self, trailers: Option<&HeaderMap>, stream_duration: Duration, span: &tracing::Span) {
        if let Some(status) = trailers.and_then(tonic::Status::from_header_map) {
            self.levels.record(&status, stream_duration, span);
        }
    }
}

/// Logs a request that failed without a gRPC status, such as a response stream that failed.
///
/// Failed statuses are logged by [`GrpcOnResponse`] and [`GrpcOnEos`], which can read the status
/// message.
#[derive(Clone, Copy, Debug)]
pub struct GrpcOnFailure;

impl OnFailure<GrpcFailureClass> for GrpcOnFailure {
    fn on_failure(
        &mut self,
        classification: GrpcFailureClass,
        latency: Duration,
        span: &tracing::Span,
    ) {
        if let GrpcFailureClass::Error(error) = classification {
            tracing::error!(parent: span, error = %error, latency = ?latency, "response failed");
        }
    }
}

/// Chooses the level at which a failed request is logged.
#[derive(Clone, Copy, Debug)]
struct GrpcFailureLevels {
    public: bool,
}

impl GrpcFailureLevels {
    /// Records `status` as the request's status code, and logs it if it is a failure.
    fn record(self, status: &tonic::Status, latency: Duration, span: &tracing::Span) {
        let code = status.code();
        span.record("rpc.grpc.status_code", code as i32);
        match code {
            tonic::Code::Ok => {},
            tonic::Code::Internal | tonic::Code::DataLoss | tonic::Code::Unavailable => {
                log_failure(Level::ERROR, status, latency, span);
            },
            _ if self.public => log_failure(Level::INFO, status, latency, span),
            _ => log_failure(Level::ERROR, status, latency, span),
        }
    }
}

fn log_failure(level: Level, status: &tonic::Status, latency: Duration, span: &tracing::Span) {
    macro_rules! log {
        ($level:expr) => {
            tracing::event!(
                parent: span,
                $level,
                grpc.code = ?status.code(),
                grpc.message = status.message(),
                latency = ?latency,
                "request failed"
            )
        };
    }
    if level == Level::ERROR {
        log!(Level::ERROR);
    } else {
        log!(Level::INFO);
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
