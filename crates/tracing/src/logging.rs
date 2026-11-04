use std::str::FromStr;
use std::sync::OnceLock;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, Value};
use opentelemetry_otlp::WithTonicConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::resource::{EnvResourceDetector, TelemetryResourceDetector};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::subscriber::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(any(not(feature = "admin-api"), feature = "testing"))]
use tracing_subscriber::layer::Filter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::{ErrorSpanExt, error};

/// Global tracer provider for flushing traces on panic.
///
/// This is necessary because the panic hook needs access to the tracer provider to flush
/// pending spans before the program terminates.
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Stdout defaults for operator, storage, and RPC server diagnostics with prover noise suppression.
const DEFAULT_STDOUT_FILTER: &str =
    "info,user=debug,miden::storage=debug,miden::rpc::server=debug,miden_prover=warn";
#[cfg(feature = "admin-api")]
pub(crate) static FILTER_CONTROLS: OnceLock<FilterControls> = OnceLock::new();

#[cfg(feature = "admin-api")]
type ReloadFilter = std::sync::Arc<dyn FilterControl>;

/// Reads and replaces an output's active filter through its reload handle.
#[cfg(feature = "admin-api")]
pub(crate) trait FilterControl: Send + Sync {
    fn reload(&self, filter: EnvFilter) -> Result<(), tracing_subscriber::reload::Error>;
    fn current(&self) -> Result<String, tracing_subscriber::reload::Error>;
}

#[cfg(feature = "admin-api")]
impl<S: Subscriber> FilterControl for tracing_subscriber::reload::Handle<EnvFilter, S> {
    fn reload(&self, filter: EnvFilter) -> Result<(), tracing_subscriber::reload::Error> {
        tracing_subscriber::reload::Handle::reload(self, filter)
    }

    fn current(&self) -> Result<String, tracing_subscriber::reload::Error> {
        self.with_current(ToString::to_string)
    }
}

/// Independent controls for the process's configured tracing outputs.
#[cfg(feature = "admin-api")]
#[derive(Clone)]
pub(crate) struct FilterControls {
    pub(crate) stdout: ReloadFilter,
    pub(crate) otel: Option<ReloadFilter>,
}

#[cfg(feature = "admin-api")]
pub(crate) fn reloadable_filter<S: Subscriber>(
    expression: &str,
) -> anyhow::Result<(tracing_subscriber::reload::Layer<EnvFilter, S>, ReloadFilter)> {
    let (filter, handle) = tracing_subscriber::reload::Layer::new(EnvFilter::from_str(expression)?);
    Ok((filter, std::sync::Arc::new(handle)))
}

/// Default OpenTelemetry resource attributes for this process.
#[derive(Clone)]
pub struct ResourceConfig {
    service_name: Option<&'static str>,
    attributes: Vec<(&'static str, &'static str)>,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            service_name: None,
            attributes: vec![("service.version", env!("CARGO_PKG_VERSION"))],
        }
    }
}

impl ResourceConfig {
    #[must_use]
    pub fn with_name(mut self, service_name: &'static str) -> Self {
        self.service_name = Some(service_name);
        self
    }

    #[must_use]
    pub fn with_attribute(mut self, key: &'static str, value: &'static str) -> Self {
        self.attributes.push((key, value));
        self
    }
}

/// Configures [`setup_tracing`] to enable or disable the open-telemetry exporter.
#[derive(Clone)]
pub enum OpenTelemetry {
    Enabled(ResourceConfig),
    Disabled,
}

impl OpenTelemetry {
    pub fn enabled() -> Self {
        OpenTelemetry::Enabled(ResourceConfig::default())
    }

    pub fn from_env() -> Self {
        if otlp_endpoint_configured() {
            OpenTelemetry::enabled()
        } else {
            OpenTelemetry::Disabled
        }
    }

    #[must_use]
    pub fn with_name(self, service_name: &'static str) -> Self {
        match self {
            OpenTelemetry::Enabled(config) => {
                OpenTelemetry::Enabled(config.with_name(service_name))
            },
            OpenTelemetry::Disabled => OpenTelemetry::Disabled,
        }
    }

    #[must_use]
    pub fn with_attribute(self, key: &'static str, value: &'static str) -> Self {
        match self {
            OpenTelemetry::Enabled(config) => {
                OpenTelemetry::Enabled(config.with_attribute(key, value))
            },
            OpenTelemetry::Disabled => OpenTelemetry::Disabled,
        }
    }

    fn is_enabled(&self) -> bool {
        matches!(self, OpenTelemetry::Enabled(_))
    }

    fn resource_config(self) -> Option<ResourceConfig> {
        match self {
            OpenTelemetry::Enabled(config) => Some(config),
            OpenTelemetry::Disabled => None,
        }
    }
}

/// Tracing subscriber configuration.
#[derive(Clone)]
pub struct TracingConfig {
    pub open_telemetry: OpenTelemetry,
    pub stdout_filter: String,
    pub otel_filter: String,
}

impl TracingConfig {
    #[must_use]
    pub fn from_env(open_telemetry: OpenTelemetry) -> Self {
        Self {
            open_telemetry,
            stdout_filter: filter_env_or_default("MIDEN_STDOUT_FILTER", DEFAULT_STDOUT_FILTER),
            otel_filter: filter_env_or_default(
                "MIDEN_OTEL_FILTER",
                "info,axum::rejection=trace,miden_prover=warn",
            ),
        }
    }
}

fn filter_env_or_default(var: &str, default: &str) -> String {
    std::env::var(var)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var(EnvFilter::DEFAULT_ENV)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| default.to_owned())
}

#[cfg(any(not(feature = "admin-api"), feature = "testing"))]
fn filter_from_string<S>(
    filter: &str,
) -> anyhow::Result<Box<dyn Filter<S> + Send + Sync + 'static>> {
    use tracing_subscriber::filter::FilterExt;

    Ok(FilterExt::boxed(EnvFilter::from_str(filter)?))
}

/// A guard that shuts down the tracer provider when dropped. This ensures that the logs are flushed
/// to the exporter before the program exits.
pub struct OtelGuard {
    tracer_provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = self.tracer_provider.shutdown() {
            eprintln!("{err:?}");
        }
    }
}

/// Initializes tracing to stdout and optionally an open-telemetry exporter.
///
/// Stdout trace filtering is configured with `MIDEN_STDOUT_FILTER`, then `RUST_LOG`, then the
/// built-in defaults for operator, storage, and RPC server diagnostics.
/// OpenTelemetry export filtering is configured with `MIDEN_OTEL_FILTER`, then `RUST_LOG`, then
/// `info,axum::rejection=trace,miden_prover=warn`.
///
/// The open-telemetry configuration is controlled via environment variables as defined in the
/// [specification](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md#opentelemetry-protocol-exporter)
///
/// Registers a panic hook so that panic errors are reported to the open-telemetry exporter.
///
/// Returns an [`OtelGuard`] if open-telemetry is enabled, otherwise `None`. When this guard is
/// dropped, the tracer provider is shutdown.
pub fn setup_tracing(otel: OpenTelemetry) -> anyhow::Result<Option<OtelGuard>> {
    setup_tracing_with_config(TracingConfig::from_env(otel))
}

/// Initializes tracing from explicit stdout and OpenTelemetry filter configuration.
///
/// Returns an [`OtelGuard`] if open-telemetry is enabled, otherwise `None`. When this guard is
/// dropped, the tracer provider is shutdown.
pub fn setup_tracing_with_config(config: TracingConfig) -> anyhow::Result<Option<OtelGuard>> {
    let TracingConfig {
        open_telemetry: otel,
        stdout_filter,
        otel_filter,
    } = config;

    if otel.is_enabled() {
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    }

    // Note: open-telemetry requires a tokio-runtime, so this _must_ be lazily evaluated (aka not
    // `then_some`) to avoid crashing sync callers (with OpenTelemetry::Disabled set). Examples of
    // such callers are tests with logging enabled.
    let tracer_provider = if otel.is_enabled() {
        let provider = init_tracer_provider(
            otel.resource_config()
                .expect("resource config is set when OpenTelemetry is enabled"),
        )?;

        // Store the provider globally so the panic hook can flush it. SdkTracerProvider is
        // internally reference-counted, so cloning is cheap.
        TRACER_PROVIDER
            .set(provider.clone())
            .expect("setup_tracing should only be called once");

        Some(provider)
    } else {
        None
    };
    let otel_layer = tracer_provider.as_ref().map(|provider| {
        OpenTelemetryLayer::new(provider.tracer("tracing-otel-subscriber")).boxed()
    });

    #[cfg(feature = "admin-api")]
    let (stdout_filter, stdout_reload) = reloadable_filter(&stdout_filter)?;
    #[cfg(not(feature = "admin-api"))]
    let stdout_filter = filter_from_string(&stdout_filter)?;
    #[cfg(feature = "admin-api")]
    let (otel_filter, otel_reload) = reloadable_filter(&otel_filter)?;
    #[cfg(not(feature = "admin-api"))]
    let otel_filter = filter_from_string(&otel_filter)?;

    let subscriber = Registry::default()
        .with(stdout_layer().with_filter(stdout_filter))
        .with(otel_layer.with_filter(otel_filter));
    tracing::subscriber::set_global_default(subscriber).map_err(Into::<anyhow::Error>::into)?;

    #[cfg(feature = "admin-api")]
    FILTER_CONTROLS
        .set(FilterControls {
            stdout: stdout_reload,
            otel: tracer_provider.as_ref().map(|_| otel_reload),
        })
        .map_err(|_| anyhow::anyhow!("tracing filter controls already initialized"))?;

    // Register panic hook now that tracing is initialized. This chains with the default panic hook
    // to preserve backtrace printing.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let info_str = info.to_string();
        let wrapped = anyhow::Error::msg(info_str);
        error!(&wrapped, "panic", panic = true);

        // Mark the current span as failed for OpenTelemetry.
        tracing::Span::current().set_error(wrapped.as_ref());

        // Flush traces before the program terminates. This ensures the panic trace is exported even
        // though the OtelGuard won't be dropped.
        if let Some(provider) = TRACER_PROVIDER.get() {
            if let Err(err) = provider.force_flush() {
                eprintln!("Failed to flush traces on panic: {err:?}");
            }
        }

        // Call the default hook to print the backtrace.
        default_hook(info);
    }));

    Ok(tracer_provider.map(|tracer_provider| OtelGuard { tracer_provider }))
}

fn init_tracer_provider(resource_config: ResourceConfig) -> anyhow::Result<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_tls_config(tonic::transport::ClientTlsConfig::new().with_enabled_roots())
        .build()?;
    let resource = resource(resource_config);

    Ok(opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}

fn resource(config: ResourceConfig) -> Resource {
    let detected_resource = Resource::builder_empty()
        .with_detector(Box::new(TelemetryResourceDetector))
        .with_detector(Box::new(EnvResourceDetector::new()))
        .build();

    resource_from_detected(config, &detected_resource, otel_service_name_override())
}

fn resource_from_detected(
    config: ResourceConfig,
    detected_resource: &Resource,
    service_name_override: Option<Value>,
) -> Resource {
    const SERVICE_NAME: &str = "service.name";
    const SERVICE_NAMESPACE: &str = "service.namespace";

    let mut attributes =
        std::collections::BTreeMap::from([(SERVICE_NAMESPACE.to_string(), Value::from("miden"))]);

    if let Some(service_name) = config.service_name {
        attributes.insert(SERVICE_NAME.to_string(), Value::from(service_name));
    }

    for (key, value) in config.attributes {
        attributes.insert(key.to_string(), Value::from(value));
    }

    // Environment resource attributes override defaults above, and OTEL_SERVICE_NAME overrides
    // both.
    for (key, value) in detected_resource {
        attributes.insert(key.as_str().to_string(), value.clone());
    }

    if let Some(service_name) = service_name_override {
        attributes.insert(SERVICE_NAME.to_string(), service_name);
    }

    Resource::builder_empty()
        .with_attributes(attributes.into_iter().map(|(key, value)| KeyValue::new(key, value)))
        .build()
}

fn otel_service_name_override() -> Option<Value> {
    std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|value| !value.is_empty())
        .map(Value::from)
}

fn otlp_endpoint_configured() -> bool {
    ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"]
        .into_iter()
        .any(|key| std::env::var(key).is_ok_and(|value| !value.trim().is_empty()))
}

/// Initializes tracing to a test exporter.
///
/// Allows trace content to be inspected via the returned receiver.
///
/// All tests that use this function must be annotated with `#[serial(open_telemetry_tracing)]`.
/// This forces serialization of all such tests. Otherwise, the tested spans could
/// be interleaved during runtime. Also, the global exporter could be re-initialized in
/// the middle of a concurrently running test.
#[cfg(feature = "testing")]
pub fn setup_test_tracing() -> anyhow::Result<(
    tokio::sync::mpsc::UnboundedReceiver<opentelemetry_sdk::trace::SpanData>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
)> {
    let (exporter, rx_export, rx_shutdown) = opentelemetry_sdk::testing::trace::new_test_exporter();

    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let otel_layer =
        OpenTelemetryLayer::new(tracer_provider.tracer("tracing-otel-subscriber")).boxed();
    let subscriber = Registry::default()
        .with(stdout_layer().with_filter(filter_from_string("debug")?))
        .with(otel_layer.with_filter(filter_from_string("info,axum::rejection=trace")?));
    tracing::subscriber::set_global_default(subscriber)?;
    Ok((rx_export, rx_shutdown))
}

#[cfg(not(feature = "tracing-forest"))]
fn stdout_layer<S>() -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync + 'static>
where
    S: Subscriber,
    for<'a> S: tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .compact()
        .with_level(true)
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .boxed()
}

#[cfg(feature = "tracing-forest")]
fn stdout_layer<S>() -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync + 'static>
where
    S: Subscriber,
    for<'a> S: tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_forest::ForestLayer::default().boxed()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use opentelemetry::Key;

    use super::*;

    struct RecordedTargets(Arc<Mutex<Vec<(&'static str, tracing::Level)>>>);

    impl<S: Subscriber> Layer<S> for RecordedTargets {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let metadata = event.metadata();
            self.0.lock().unwrap().push((metadata.target(), *metadata.level()));
        }
    }

    fn default_stdout_events(emit: impl FnOnce()) -> Vec<(&'static str, tracing::Level)> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(
            RecordedTargets(Arc::clone(&events))
                .with_filter(EnvFilter::try_new(DEFAULT_STDOUT_FILTER).unwrap()),
        );
        tracing::subscriber::with_default(subscriber, emit);
        events.lock().unwrap().clone()
    }

    #[test]
    fn default_stdout_preserves_storage_and_operator_debug_events() {
        let events = default_stdout_events(|| {
            tracing::debug!(target: "user::miden-node", "operator debug");
            tracing::debug!(target: "miden::storage", "storage lifecycle");
            tracing::debug!(target: "miden::storage::sqlite", "database debug");
            tracing::trace!(target: "miden::storage", "storage trace");
            tracing::debug!(target: "other_dependency", "dependency debug");
            tracing::info!(target: "other_dependency", "dependency info");
            tracing::info!(target: "miden_prover", "prover info");
            tracing::warn!(target: "miden_prover", "prover warning");
        });

        assert_eq!(
            events,
            [
                ("user::miden-node", tracing::Level::DEBUG),
                ("miden::storage", tracing::Level::DEBUG),
                ("miden::storage::sqlite", tracing::Level::DEBUG),
                ("other_dependency", tracing::Level::INFO),
                ("miden_prover", tracing::Level::WARN),
            ]
        );
    }

    #[test]
    fn resource_uses_configured_defaults() {
        let detected_resource = Resource::builder_empty()
            .with_attributes([KeyValue::new("telemetry.sdk.language", "rust")])
            .build();

        let resource = resource_from_detected(
            ResourceConfig::default()
                .with_name("node")
                .with_attribute("miden.node.role", "sequencer"),
            &detected_resource,
            None,
        );

        assert_eq!(resource_value(&resource, "service.name"), Some(Value::from("node")),);
        assert_eq!(
            resource_value(&resource, "service.version"),
            Some(Value::from(env!("CARGO_PKG_VERSION"))),
        );
        assert_eq!(resource_value(&resource, "service.namespace"), Some(Value::from("miden")),);
        assert_eq!(resource_value(&resource, "miden.node.role"), Some(Value::from("sequencer")),);
        assert_eq!(resource_value(&resource, "telemetry.sdk.language"), Some(Value::from("rust")),);
    }

    #[test]
    fn resource_prefers_detected_attributes_over_configured_defaults() {
        let detected_resource = Resource::builder_empty()
            .with_attributes([
                KeyValue::new("service.name", "custom-node"),
                KeyValue::new("service.version", "custom-version"),
                KeyValue::new("service.namespace", "custom-namespace"),
                KeyValue::new("miden.node.role", "custom-role"),
            ])
            .build();

        let resource = resource_from_detected(
            ResourceConfig::default()
                .with_name("node")
                .with_attribute("miden.node.role", "sequencer"),
            &detected_resource,
            None,
        );

        assert_eq!(resource_value(&resource, "service.name"), Some(Value::from("custom-node")),);
        assert_eq!(
            resource_value(&resource, "service.version"),
            Some(Value::from("custom-version")),
        );
        assert_eq!(
            resource_value(&resource, "service.namespace"),
            Some(Value::from("custom-namespace")),
        );
        assert_eq!(resource_value(&resource, "miden.node.role"), Some(Value::from("custom-role")),);
    }

    #[test]
    fn resource_prefers_explicit_service_name_override() {
        let detected_resource = Resource::builder_empty()
            .with_attributes([KeyValue::new("service.name", "resource-attribute-node")])
            .build();

        let resource = resource_from_detected(
            ResourceConfig::default().with_name("node"),
            &detected_resource,
            Some(Value::from("service-env-node")),
        );

        assert_eq!(
            resource_value(&resource, "service.name"),
            Some(Value::from("service-env-node")),
        );
    }

    fn resource_value(resource: &Resource, key: &'static str) -> Option<Value> {
        resource.get(&Key::from_static_str(key))
    }
}
