use std::str::FromStr;
use std::sync::OnceLock;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithTonicConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::subscriber::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::{Filter, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

/// Global tracer provider for flushing traces on panic.
///
/// This is necessary because the panic hook needs access to the tracer provider to flush
/// pending spans before the program terminates.
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Configures [`setup_tracing`] to enable or disable the open-telemetry exporter.
#[derive(Clone, Copy)]
pub enum OpenTelemetry {
    Enabled,
    Disabled,
}

impl OpenTelemetry {
    fn is_enabled(self) -> bool {
        matches!(self, OpenTelemetry::Enabled)
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
        let provider = init_tracer_provider()?;

        // Store the provider globally so the panic hook can flush it.
        // SdkTracerProvider is internally reference-counted, so cloning is cheap.
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

    // Register panic hook now that tracing is initialized.
    // This chains with the default panic hook to preserve backtrace printing.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = true, "{info}");

        // Flush traces before the program terminates.
        // This ensures the panic trace is exported even though the OtelGuard won't be dropped.
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

fn init_tracer_provider() -> anyhow::Result<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
        .build()?;

    Ok(opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build())
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
