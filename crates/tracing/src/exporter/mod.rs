mod otel;
mod stdout;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::error::OTelSdkError;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::prelude::*;

use crate::filter::{DynamicFilter, FilterError};
use crate::internal;

/// Default filter used for OpenTelemetry exports.
pub const DEFAULT_OTEL_FILTER: &str = crate::filter::DEFAULT_FILTER;

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
    /// OTLP/gRPC collector endpoint for trace export.
    pub otel_endpoint: String,
    /// OpenTelemetry service name attached to every exported span.
    pub service_name: String,
}

impl TracingConfig {
    /// Creates a config with explicit exporter settings and initial filter strings.
    pub fn new(
        otel_endpoint: impl Into<String>,
        service_name: impl Into<String>,
        otel_filter: impl Into<String>,
        user_log_filter: impl Into<String>,
    ) -> Self {
        Self {
            otel_filter: otel_filter.into(),
            user_log_filter: user_log_filter.into(),
            otel_endpoint: otel_endpoint.into(),
            service_name: service_name.into(),
        }
    }
}

/// Installed tracing subscriber/exporter state.
pub struct TracingHandle {
    otel_filter: DynamicFilter,
    user_log_filter: DynamicFilter,
    error_layer_filter: DynamicFilter,
    active_span_filter: DynamicFilter,
    guard: TracingGuard,
}

impl TracingHandle {
    /// Returns the current OTLP/gRPC trace exporter filter.
    pub fn get_otel_filter(&self) -> Result<String, FilterError> {
        self.otel_filter.get()
    }

    /// Replaces the OTLP/gRPC trace exporter filter.
    pub fn set_otel_filter(&self, filter: impl Into<String>) -> Result<(), FilterError> {
        self.otel_filter.set(filter)?;
        self.reload_plumbing_filters()
    }

    /// Returns the current user-facing stdout exporter filter.
    pub fn get_user_filter(&self) -> Result<String, FilterError> {
        self.user_log_filter.get()
    }

    /// Replaces the user-facing stdout exporter filter.
    pub fn set_user_filter(&self, filter: impl Into<String>) -> Result<(), FilterError> {
        self.user_log_filter.set(filter)?;
        self.reload_plumbing_filters()
    }

    /// Flushes pending spans from both installed exporters.
    pub fn force_flush(&self) -> Result<(), ExportError> {
        self.guard.force_flush()
    }

    /// Flushes and shuts down both installed exporters.
    ///
    /// Dropping the handle also shuts exporters down, but this method lets callers surface shutdown
    /// errors during controlled application termination.
    pub fn shutdown(mut self) -> Result<(), ExportError> {
        self.guard.shutdown()
    }

    fn reload_plumbing_filters(&self) -> Result<(), FilterError> {
        let plumbing_filter =
            combined_filter(&self.otel_filter.get()?, &self.user_log_filter.get()?);
        self.error_layer_filter.set(plumbing_filter.clone())?;
        self.active_span_filter.set(plumbing_filter)
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
    otel_provider: Option<SdkTracerProvider>,
}

impl TracingGuard {
    fn force_flush(&self) -> Result<(), ExportError> {
        if let Some(provider) = &self.otel_provider {
            provider.force_flush().map_err(ExportError::OtelFlush)?;
        }
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), ExportError> {
        let mut result = Ok(());

        if let Some(provider) = self.otel_provider.take() {
            if let Err(error) = provider.shutdown() {
                result = Err(ExportError::OtelShutdown(error));
            }
        }
        result
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            eprintln!("failed to shut down tracing exporters: {error}");
        }
    }
}

/// Installs the Miden tracing subscriber with OTLP/gRPC and user-facing stdout exporters.
///
/// The two exporters are installed together but use independent dynamic filters. The initial
/// filter values come from `config`, which lets callers restore persisted admin settings before
/// tracing starts.
///
/// Installation also registers this crate's panic hook. The hook records panic attributes and an
/// error status on the active span, or on a short fallback span when no span is active, then
/// invokes the previously installed panic hook.
pub fn install(config: TracingConfig) -> Result<TracingHandle, InstallError> {
    let TracingConfig {
        otel_filter: initial_otel_filter,
        user_log_filter: initial_user_log_filter,
        otel_endpoint,
        service_name,
    } = config;
    let (otel_filter_layer, otel_filter) =
        DynamicFilter::new(initial_otel_filter.clone()).map_err(InstallError::OtelFilter)?;
    let (user_log_filter_layer, user_log_filter) =
        DynamicFilter::new(initial_user_log_filter.clone()).map_err(InstallError::UserLogFilter)?;
    let plumbing_filter = combined_filter(&initial_otel_filter, &initial_user_log_filter);
    let (error_layer_filter_layer, error_layer_filter) =
        DynamicFilter::new(plumbing_filter.clone()).map_err(InstallError::PlumbingFilter)?;
    let (active_span_filter_layer, active_span_filter) =
        DynamicFilter::new(plumbing_filter).map_err(InstallError::PlumbingFilter)?;

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let otel_provider = otel::grpc_trace_provider(otel_endpoint, service_name)?;
    let trace_layer = tracing_opentelemetry::layer()
        .with_tracer(otel_provider.tracer("miden-node-tracing-otlp"))
        .with_filter(internal::without_user_log_events(internal::with_control_plane_events(
            otel_filter_layer,
        )));
    let user_log_layer =
        stdout::layer().with_filter(internal::with_control_plane_events(user_log_filter_layer));
    let control_plane_layer =
        internal::ControlPlaneEventLayer.with_filter(internal::ControlPlaneScope);
    let error_layer = tracing_error::ErrorLayer::default()
        .with_filter(internal::with_control_plane_events(error_layer_filter_layer));
    let active_span_layer = internal::ActiveSpanLayer
        .with_filter(internal::with_control_plane_events(active_span_filter_layer));

    let subscriber = tracing_subscriber::registry()
        .with(error_layer)
        .with(active_span_layer)
        .with(control_plane_layer)
        .with(trace_layer)
        .with(user_log_layer);
    tracing::subscriber::set_global_default(subscriber).map_err(InstallError::SetGlobalDefault)?;

    crate::install_panic_hook();

    Ok(TracingHandle {
        otel_filter,
        user_log_filter,
        error_layer_filter,
        active_span_filter,
        guard: TracingGuard { otel_provider: Some(otel_provider) },
    })
}

fn combined_filter(first: &str, second: &str) -> String {
    format!("{first},{second}")
}

/// Error returned while flushing or shutting down installed exporters.
#[derive(Debug)]
pub enum ExportError {
    /// The OTLP/gRPC exporter failed to flush.
    OtelFlush(OTelSdkError),
    /// The OTLP/gRPC exporter failed to shut down.
    OtelShutdown(OTelSdkError),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtelFlush(error) => write!(f, "failed to flush OTLP exporter: {error}"),
            Self::OtelShutdown(error) => write!(f, "failed to shut down OTLP exporter: {error}"),
        }
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OtelFlush(error) | Self::OtelShutdown(error) => Some(error),
        }
    }
}

/// Error returned while installing tracing.
#[derive(Debug)]
pub enum InstallError {
    /// The initial OTLP trace filter was invalid.
    OtelFilter(FilterError),
    /// The initial user-facing stdout filter was invalid.
    UserLogFilter(FilterError),
    /// The internal plumbing filter derived from exporter filters was invalid.
    PlumbingFilter(FilterError),
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
            Self::PlumbingFilter(error) => write!(f, "invalid tracing plumbing filter: {error}"),
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
            Self::OtelFilter(error) | Self::UserLogFilter(error) | Self::PlumbingFilter(error) => {
                Some(error)
            },
            Self::OtlpExporter(error) => Some(error),
            Self::SetGlobalDefault(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::Registry;
    use tracing_subscriber::prelude::*;

    use super::{DEFAULT_OTEL_FILTER, DEFAULT_USER_LOG_FILTER, TracingConfig};

    #[test]
    fn config_requires_exporter_settings_and_filter_values() {
        let config = TracingConfig::new(
            "http://collector.example:4317",
            "miden-validator",
            DEFAULT_OTEL_FILTER,
            DEFAULT_USER_LOG_FILTER,
        );

        assert_eq!(config.otel_endpoint, "http://collector.example:4317");
        assert_eq!(config.service_name, "miden-validator");
        assert_eq!(config.otel_filter, DEFAULT_OTEL_FILTER);
        assert_eq!(config.user_log_filter, DEFAULT_USER_LOG_FILTER);
    }

    #[test]
    fn config_accepts_persisted_filter_values() {
        let config =
            TracingConfig::new("http://collector.example:4317", "miden-store", "rpc=debug", "off");

        assert_eq!(config.otel_filter, "rpc=debug");
        assert_eq!(config.user_log_filter, "off");
    }

    #[test]
    fn tracing_handle_exposes_filter_accessors() {
        let (trace_layer, otel_filter) =
            crate::filter::DynamicFilter::new::<Registry>("info").unwrap();
        let (user_layer, user_log_filter) =
            crate::filter::DynamicFilter::new::<Registry>("off").unwrap();
        let (error_layer, error_layer_filter) =
            crate::filter::DynamicFilter::new::<Registry>(super::combined_filter("info", "off"))
                .unwrap();
        let (active_layer, active_span_filter) =
            crate::filter::DynamicFilter::new::<Registry>(super::combined_filter("info", "off"))
                .unwrap();
        let handle = super::TracingHandle {
            otel_filter,
            user_log_filter,
            error_layer_filter,
            active_span_filter,
            guard: super::TracingGuard {
                otel_provider: Some(opentelemetry_sdk::trace::SdkTracerProvider::builder().build()),
            },
        };
        let _keep_layers_alive = (trace_layer, user_layer, error_layer, active_layer);

        assert_eq!(handle.get_otel_filter().unwrap(), "info");
        assert_eq!(handle.get_user_filter().unwrap(), "off");

        handle.set_otel_filter("rpc=debug").unwrap();
        handle.set_user_filter("warn").unwrap();

        assert_eq!(handle.get_otel_filter().unwrap(), "rpc=debug");
        assert_eq!(handle.get_user_filter().unwrap(), "warn");
        assert_eq!(handle.error_layer_filter.get().unwrap(), "rpc=debug,warn");
        assert_eq!(handle.active_span_filter.get().unwrap(), "rpc=debug,warn");
    }

    #[test]
    fn plumbing_layers_do_not_enable_miden_callsites_when_exporters_are_off() {
        let (error_layer_filter, _error_filter) =
            crate::filter::DynamicFilter::new(super::combined_filter("off", "off")).unwrap();
        let (active_span_filter, _active_filter) =
            crate::filter::DynamicFilter::new(super::combined_filter("off", "off")).unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_error::ErrorLayer::default()
                    .with_filter(crate::internal::with_control_plane_events(error_layer_filter)),
            )
            .with(
                crate::internal::ActiveSpanLayer
                    .with_filter(crate::internal::with_control_plane_events(active_span_filter)),
            )
            .with(
                crate::internal::ControlPlaneEventLayer
                    .with_filter(crate::internal::ControlPlaneScope),
            );

        tracing::subscriber::with_default(subscriber, || {
            assert!(!tracing::enabled!(target: "rpc", tracing::Level::INFO));
            assert!(tracing::enabled!(
                target: crate::internal::CONTROL_PLANE_TARGET,
                tracing::Level::ERROR
            ));
        });
    }

    #[test]
    fn tracing_handle_can_flush_and_shutdown_exporters() {
        let (trace_layer, otel_filter) =
            crate::filter::DynamicFilter::new::<Registry>("info").unwrap();
        let (user_layer, user_log_filter) =
            crate::filter::DynamicFilter::new::<Registry>("off").unwrap();
        let (error_layer, error_layer_filter) =
            crate::filter::DynamicFilter::new::<Registry>(super::combined_filter("info", "off"))
                .unwrap();
        let (active_layer, active_span_filter) =
            crate::filter::DynamicFilter::new::<Registry>(super::combined_filter("info", "off"))
                .unwrap();
        let handle = super::TracingHandle {
            otel_filter,
            user_log_filter,
            error_layer_filter,
            active_span_filter,
            guard: super::TracingGuard {
                otel_provider: Some(opentelemetry_sdk::trace::SdkTracerProvider::builder().build()),
            },
        };
        let _keep_layers_alive = (trace_layer, user_layer, error_layer, active_layer);

        handle.force_flush().unwrap();
        handle.shutdown().unwrap();
    }
}
