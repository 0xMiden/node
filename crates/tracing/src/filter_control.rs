//! Runtime controls for the process's tracing output filters.

use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Context as _;
use tracing::Subscriber;
use tracing_subscriber::EnvFilter;

pub(crate) static FILTER_CONTROLS: OnceLock<FilterControls> = OnceLock::new();

pub(crate) type SharedFilterControl = Arc<dyn FilterControl>;

/// Identifies the tracing output owned by a filter control.
#[derive(Clone, Copy)]
pub(crate) enum FilterOutput {
    Stdout,
    OpenTelemetry,
}

impl FilterOutput {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::OpenTelemetry => "otel",
        }
    }
}

/// Distinguishes invalid expressions from failures to apply a valid expression.
#[derive(Debug)]
pub(crate) enum SetFilterError {
    InvalidExpression(tracing_subscriber::filter::ParseError),
    Internal(anyhow::Error),
}

/// Reads and replaces an output's active filter expression.
pub(crate) trait FilterControl: Send + Sync {
    fn set_expression(&self, expression: String) -> Result<(), SetFilterError>;
    fn current_expression(&self) -> anyhow::Result<String>;
}

/// Keeps the applied expression intact because formatting an `EnvFilter` can change value types.
struct ReloadableFilter<S> {
    handle: tracing_subscriber::reload::Handle<EnvFilter, S>,
    expression: Mutex<String>,
    output: FilterOutput,
}

impl<S: Subscriber> FilterControl for ReloadableFilter<S> {
    fn set_expression(&self, expression: String) -> Result<(), SetFilterError> {
        let filter = EnvFilter::try_new(&expression).map_err(SetFilterError::InvalidExpression)?;
        crate::info_v2!(
            "Setting tracing filter",
            tracing.filter = expression.as_str(),
            tracing.output = self.output.as_str()
        );
        // Serialize updates and reads so the returned expression describes the active filter.
        let mut current = self.expression.lock().map_err(|_| {
            SetFilterError::Internal(anyhow::anyhow!(
                "{} tracing filter expression lock is poisoned",
                self.output.as_str()
            ))
        })?;
        self.handle
            .reload(filter)
            .with_context(|| format!("failed to update {} tracing filter", self.output.as_str()))
            .map_err(SetFilterError::Internal)?;
        *current = expression;
        Ok(())
    }

    fn current_expression(&self) -> anyhow::Result<String> {
        let expression = self.expression.lock().map_err(|_| {
            anyhow::anyhow!("{} tracing filter expression lock is poisoned", self.output.as_str())
        })?;
        self.handle
            .with_current(|_| ())
            .with_context(|| format!("failed to read {} tracing filter", self.output.as_str()))?;
        Ok(expression.clone())
    }
}

/// Independent controls for the process's configured tracing outputs.
#[derive(Clone)]
pub(crate) struct FilterControls {
    pub(crate) stdout: SharedFilterControl,
    pub(crate) otel: Option<SharedFilterControl>,
}

pub(crate) fn reloadable_filter<S: Subscriber>(
    expression: &str,
    output: FilterOutput,
) -> anyhow::Result<(tracing_subscriber::reload::Layer<EnvFilter, S>, SharedFilterControl)> {
    let filter = EnvFilter::try_new(expression)
        .with_context(|| format!("invalid {} tracing filter", output.as_str()))?;
    let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);
    Ok((
        filter,
        Arc::new(ReloadableFilter {
            handle,
            expression: Mutex::new(expression.to_owned()),
            output,
        }),
    ))
}
