use std::str::FromStr;
use std::sync::OnceLock;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, Value};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::resource::{EnvResourceDetector, TelemetryResourceDetector};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::subscriber::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::{Filter, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use crate::tracing::OpenTelemetrySpanExt;

/// Global tracer provider for flushing traces on panic.
///
/// This is necessary because the panic hook needs access to the tracer provider to flush
/// pending spans before the program terminates.
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Default OpenTelemetry resource attributes for this process.
#[derive(Clone, Default)]
pub struct ResourceConfig {
    service_name: Option<&'static str>,
    attributes: Vec<(&'static str, &'static str)>,
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
/// Trace filtering defaults to `INFO` and can be configured using the conventional `RUST_LOG`
/// environment variable.
///
/// The open-telemetry configuration is controlled via environment variables as defined in the
/// [specification](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md#opentelemetry-protocol-exporter)
///
/// Registers a panic hook so that panic errors are reported to the open-telemetry exporter.
///
/// Returns an [`OtelGuard`] if open-telemetry is enabled, otherwise `None`. When this guard is
/// dropped, the tracer provider is shutdown.
pub fn setup_tracing(otel: OpenTelemetry) -> anyhow::Result<Option<OtelGuard>> {
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

    let subscriber = Registry::default()
        .with(stdout_layer().with_filter(env_or_default_filter()))
        .with(otel_layer.with_filter(env_or_default_filter()));
    tracing::subscriber::set_global_default(subscriber).map_err(Into::<anyhow::Error>::into)?;

    // Register panic hook now that tracing is initialized. This chains with the default panic hook
    // to preserve backtrace printing.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = true, info = %info, "panic");

        // Mark the current span as failed for OpenTelemetry.
        let info_str = info.to_string();
        let wrapped = anyhow::Error::msg(info_str);
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
    let builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();

    let exporter = builder.build()?;
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
    let (exporter, rx_export, rx_shutdown) =
        opentelemetry_sdk::testing::trace::new_tokio_test_exporter();

    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let otel_layer =
        OpenTelemetryLayer::new(tracer_provider.tracer("tracing-otel-subscriber")).boxed();
    let subscriber = Registry::default()
        .with(stdout_layer().with_filter(env_or_default_filter()))
        .with(otel_layer.with_filter(env_or_default_filter()));
    tracing::subscriber::set_global_default(subscriber)?;
    Ok((rx_export, rx_shutdown))
}

#[cfg(not(feature = "tracing-forest"))]
fn stdout_layer<S>() -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync + 'static>
where
    S: Subscriber,
    for<'a> S: tracing_subscriber::registry::LookupSpan<'a>,
{
    use tracing_subscriber::fmt::format::FmtSpan;

    tracing_subscriber::fmt::layer()
        .pretty()
        .compact()
        .with_level(true)
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
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

/// Creates a filter from the `RUST_LOG` env var with a default of `INFO` if unset.
///
/// # Panics
///
/// Panics if `RUST_LOG` fails to parse.
fn env_or_default_filter<S>() -> Box<dyn Filter<S> + Send + Sync + 'static> {
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::filter::{FilterExt, Targets};

    // `tracing` does not allow differentiating between invalid and missing env var so we manually
    // do this instead. The alternative is to silently ignore parsing errors which I think is worse.
    match std::env::var(EnvFilter::DEFAULT_ENV) {
        Ok(rust_log) => FilterExt::boxed(
            EnvFilter::from_str(&rust_log)
                .expect("RUST_LOG should contain a valid filter configuration"),
        ),
        Err(std::env::VarError::NotUnicode(_)) => panic!("RUST_LOG contained non-unicode"),
        Err(std::env::VarError::NotPresent) => {
            // Default level is INFO, and additionally enable logs from axum extractor rejections.
            FilterExt::boxed(
                Targets::new()
                    .with_default(LevelFilter::INFO)
                    .with_target("axum::rejection", LevelFilter::TRACE),
            )
        },
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry::Key;

    use super::*;

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
        assert_eq!(resource_value(&resource, "service.namespace"), Some(Value::from("miden")),);
        assert_eq!(resource_value(&resource, "miden.node.role"), Some(Value::from("sequencer")),);
        assert_eq!(resource_value(&resource, "telemetry.sdk.language"), Some(Value::from("rust")),);
    }

    #[test]
    fn resource_prefers_detected_attributes_over_configured_defaults() {
        let detected_resource = Resource::builder_empty()
            .with_attributes([
                KeyValue::new("service.name", "custom-node"),
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
