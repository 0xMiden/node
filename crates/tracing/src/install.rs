use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::prelude::*;

use crate::filter::{DynamicFilter, FilterError};
use crate::stdout::UserFacingStdoutExporter;
use crate::{DEFAULT_FILTER, internal};

/// Default filter used for user-facing stdout logs.
pub const DEFAULT_USER_LOG_FILTER: &str = "info";

/// Initial tracing configuration.
///
/// Both filters are explicit strings so callers can restore the last persisted admin value during
/// startup before the subscriber is installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracingConfig {
    /// Initial filter for the OTLP/gRPC trace exporter.
    pub otel_filter: String,
    /// Initial filter for the user-facing stdout exporter.
    pub user_log_filter: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            otel_filter: DEFAULT_FILTER.to_owned(),
            user_log_filter: DEFAULT_USER_LOG_FILTER.to_owned(),
        }
    }
}

impl TracingConfig {
    /// Creates a config with both exporters initialized from explicit filter strings.
    pub fn new(otel_filter: impl Into<String>, user_log_filter: impl Into<String>) -> Self {
        Self {
            otel_filter: otel_filter.into(),
            user_log_filter: user_log_filter.into(),
        }
    }
}

/// Installed tracing subscriber/exporter state.
pub struct TracingHandle {
    otel_filter: DynamicFilter,
    user_log_filter: DynamicFilter,
    _guard: TracingGuard,
}

impl TracingHandle {
    /// Returns the current OTLP/gRPC trace exporter filter.
    pub fn get_otel_filter(&self) -> Result<String, FilterError> {
        self.otel_filter.get()
    }

    /// Replaces the OTLP/gRPC trace exporter filter.
    pub fn set_otel_filter(&self, filter: impl Into<String>) -> Result<(), FilterError> {
        self.otel_filter.set(filter)
    }

    /// Returns the current user-facing stdout exporter filter.
    pub fn get_user_filter(&self) -> Result<String, FilterError> {
        self.user_log_filter.get()
    }

    /// Replaces the user-facing stdout exporter filter.
    pub fn set_user_filter(&self, filter: impl Into<String>) -> Result<(), FilterError> {
        self.user_log_filter.set(filter)
    }
}

impl std::fmt::Debug for TracingHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TracingHandle").finish_non_exhaustive()
    }
}

/// Guard which shuts down installed OpenTelemetry tracer providers on drop.
#[derive(Debug)]
pub(crate) struct TracingGuard {
    trace_provider: SdkTracerProvider,
    user_log_provider: SdkTracerProvider,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Err(error) = self.trace_provider.shutdown() {
            eprintln!("failed to shut down OTLP trace provider: {error:?}");
        }
        if let Err(error) = self.user_log_provider.shutdown() {
            eprintln!("failed to shut down user-facing stdout trace provider: {error:?}");
        }
    }
}

/// Installs the Miden tracing subscriber with OTLP/gRPC and user-facing stdout exporters.
///
/// The two exporters are installed together but use independent dynamic filters. The initial
/// filter values come from `config`, which lets callers restore persisted admin settings before
/// tracing starts.
pub fn install(config: TracingConfig) -> Result<TracingHandle, InstallError> {
    let (otel_filter_layer, otel_filter) =
        DynamicFilter::new(config.otel_filter).map_err(InstallError::OtelFilter)?;
    let (user_log_filter_layer, user_log_filter) =
        DynamicFilter::new(config.user_log_filter).map_err(InstallError::UserLogFilter)?;

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let trace_provider = otlp_grpc_trace_provider()?;
    let user_log_provider = user_log_trace_provider();

    let trace_layer = tracing_opentelemetry::layer()
        .with_tracer(trace_provider.tracer("miden-node-tracing-otlp"))
        .with_filter(internal::with_control_plane_events(otel_filter_layer));
    let user_log_layer = tracing_opentelemetry::layer()
        .with_tracer(user_log_provider.tracer("miden-node-tracing-user-stdout"))
        .with_filter(internal::with_control_plane_events(user_log_filter_layer));
    let control_plane_layer =
        internal::ControlPlaneEventLayer.with_filter(internal::OnlyControlPlaneEvents);

    let subscriber = tracing_subscriber::registry()
        .with(control_plane_layer)
        .with(trace_layer)
        .with(user_log_layer);
    tracing::subscriber::set_global_default(subscriber).map_err(InstallError::SetGlobalDefault)?;

    crate::install_panic_hook();

    Ok(TracingHandle {
        otel_filter,
        user_log_filter,
        _guard: TracingGuard { trace_provider, user_log_provider },
    })
}

fn otlp_grpc_trace_provider() -> Result<SdkTracerProvider, InstallError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .map_err(InstallError::OtlpExporter)?;

    Ok(SdkTracerProvider::builder().with_batch_exporter(exporter).build())
}

fn user_log_trace_provider() -> SdkTracerProvider {
    SdkTracerProvider::builder()
        .with_simple_exporter(UserFacingStdoutExporter::stdout())
        .build()
}

/// Error returned while installing tracing.
#[derive(Debug)]
pub enum InstallError {
    /// The initial OTLP trace filter was invalid.
    OtelFilter(FilterError),
    /// The initial user-facing stdout filter was invalid.
    UserLogFilter(FilterError),
    /// The OTLP/gRPC exporter could not be constructed.
    OtlpExporter(opentelemetry_otlp::ExporterBuildError),
    /// A global tracing subscriber was already installed.
    SetGlobalDefault(tracing::subscriber::SetGlobalDefaultError),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtelFilter(error) => write!(f, "invalid OTLP trace filter: {error}"),
            Self::UserLogFilter(error) => write!(f, "invalid user-facing stdout filter: {error}"),
            Self::OtlpExporter(error) => write!(f, "failed to build OTLP/gRPC exporter: {error}"),
            Self::SetGlobalDefault(error) => {
                write!(f, "failed to install global tracing subscriber: {error}")
            },
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OtelFilter(error) | Self::UserLogFilter(error) => Some(error),
            Self::OtlpExporter(error) => Some(error),
            Self::SetGlobalDefault(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_USER_LOG_FILTER, TracingConfig};
    use crate::DEFAULT_FILTER;

    #[test]
    fn default_config_initializes_both_filters() {
        let config = TracingConfig::default();

        assert_eq!(config.otel_filter, DEFAULT_FILTER);
        assert_eq!(config.user_log_filter, DEFAULT_USER_LOG_FILTER);
    }

    #[test]
    fn config_accepts_persisted_filter_values() {
        let config = TracingConfig::new("rpc=debug", "off");

        assert_eq!(config.otel_filter, "rpc=debug");
        assert_eq!(config.user_log_filter, "off");
    }

    #[test]
    fn tracing_handle_exposes_filter_accessors() {
        let (trace_layer, otel_filter) = crate::filter::DynamicFilter::new("info").unwrap();
        let (user_layer, user_log_filter) = crate::filter::DynamicFilter::new("off").unwrap();
        let handle = super::TracingHandle {
            otel_filter,
            user_log_filter,
            _guard: super::TracingGuard {
                trace_provider: opentelemetry_sdk::trace::SdkTracerProvider::builder().build(),
                user_log_provider: opentelemetry_sdk::trace::SdkTracerProvider::builder().build(),
            },
        };
        let _keep_layers_alive = (trace_layer, user_layer);

        assert_eq!(handle.get_otel_filter().unwrap(), "info");
        assert_eq!(handle.get_user_filter().unwrap(), "off");

        handle.set_otel_filter("rpc=debug").unwrap();
        handle.set_user_filter("warn").unwrap();

        assert_eq!(handle.get_otel_filter().unwrap(), "rpc=debug");
        assert_eq!(handle.get_user_filter().unwrap(), "warn");
    }
}
