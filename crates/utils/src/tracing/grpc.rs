use tracing::field;

use crate::tracing::OpenTelemetrySpanExt;

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
        rpc.method = method
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
    span.set_attribute("rpc.system", "grpc");
    if let Some(host) = request.uri().host() {
        span.set_attribute("server.address", host);
    }
    if let Some(host_port) = request.uri().port() {
        span.set_attribute("server.port", host_port.as_u16());
    }
    let remote_addr = request
        .extensions()
        .get::<tonic::transport::server::TcpConnectInfo>()
        .and_then(tonic::transport::server::TcpConnectInfo::remote_addr);
    if let Some(addr) = remote_addr {
        span.set_attribute("client.address", addr.ip());
        span.set_attribute("client.port", addr.port());
        span.set_attribute("network.peer.address", addr.ip());
        span.set_attribute("network.peer.port", addr.port());
        span.set_attribute("network.transport", "tcp");
        match addr.ip() {
            std::net::IpAddr::V4(_) => span.set_attribute("network.type", "ipv4"),
            std::net::IpAddr::V6(_) => span.set_attribute("network.type", "ipv6"),
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
