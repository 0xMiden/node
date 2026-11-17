//! Runtime controls for the process's tracing output filters.

use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Context as _;
use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{Directive, LevelFilter, ParseError};

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

/// Keeps the effective expression intact because formatting an `EnvFilter` can change value types.
struct ReloadableFilter<S> {
    handle: tracing_subscriber::reload::Handle<EnvFilter, S>,
    expression: Mutex<String>,
    output: FilterOutput,
}

impl<S: Subscriber> FilterControl for ReloadableFilter<S> {
    fn set_expression(&self, expression: String) -> Result<(), SetFilterError> {
        let (filter, expression) =
            parse_filter(&expression).map_err(SetFilterError::InvalidExpression)?;
        crate::info!(
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
    let (filter, expression) = parse_filter(expression)
        .with_context(|| format!("invalid {} tracing filter", output.as_str()))?;
    let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);
    Ok((
        filter,
        Arc::new(ReloadableFilter {
            handle,
            expression: Mutex::new(expression),
            output,
        }),
    ))
}

/// Parses operator filters with dependency output limited to warnings and errors by default.
///
/// Bare levels and the `miden` alias select the `miden::` namespace. A bare `off` disables all
/// targets except explicit overrides. Field values remain verbatim so saved filters retain their
/// matching behavior when restored.
pub(crate) fn parse_filter(expression: &str) -> Result<(EnvFilter, String), ParseError> {
    let mut dependency_level = LevelFilter::WARN;
    let mut node_level = "info".to_owned();
    let mut node_override = None;
    let mut directives = Vec::new();
    for directive in expression.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        directive.parse::<Directive>()?;
        if let Ok(level) = directive.parse::<LevelFilter>() {
            dependency_level = if level == LevelFilter::OFF {
                level
            } else {
                LevelFilter::WARN
            };
            node_level = level.to_string().to_lowercase();
        } else if matches!(directive, "miden" | "miden::") {
            node_override = Some("trace".to_owned());
        } else if let Some(level) =
            directive.strip_prefix("miden=").or_else(|| directive.strip_prefix("miden::="))
        {
            node_override = Some(if level.is_empty() { "trace" } else { level }.to_owned());
        } else if let Some(scope) = directive.strip_prefix("miden[") {
            directives.push(format!("miden::[{scope}"));
        } else {
            directives.push(directive.to_owned());
        }
    }
    let node_level = node_override.unwrap_or(node_level);
    let mut effective = if dependency_level == LevelFilter::OFF && node_level == "off" {
        "off".to_owned()
    } else {
        format!("{},miden::={node_level}", dependency_level.to_string().to_lowercase())
    };
    for directive in directives {
        effective.push(',');
        effective.push_str(&directive);
    }
    Ok((EnvFilter::try_new(&effective)?, effective))
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::{Layer, Registry};

    use super::*;

    #[derive(Clone, Default)]
    struct Recorded(Arc<Mutex<Vec<&'static str>>>);

    impl<S: Subscriber> Layer<S> for Recorded {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _: &tracing::Id,
            _: Context<'_, S>,
        ) {
            self.0.lock().unwrap().push(attrs.metadata().name());
        }

        fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
            self.0.lock().unwrap().push(event.metadata().name());
        }
    }

    fn record(expression: &str) -> Vec<&'static str> {
        let recorded = Recorded::default();
        let (filter, _) = parse_filter(expression).unwrap();
        let subscriber = Registry::default().with(recorded.clone().with_filter(filter));
        tracing::subscriber::with_default(subscriber, || {
            let _ = tracing::info_span!(target: "miden::process", "process.info");
            let _ = tracing::debug_span!(target: "miden::process", "process.debug");
            let _ = tracing::info_span!(target: "miden::rpc::server", "rpc.info");
            let _ = tracing::info_span!(target: "miden_processor::trace", "vm.info");
            let _ = tracing::info_span!(target: "miden_lifted_stark::lmcs", "stark.info");
            let _ = tracing::warn_span!(target: "miden_prover", "prover.warn");
            let _ = tracing::debug_span!(target: "tonic::transport", "tonic.debug");
            let _ = tracing::info_span!(target: "user::application", "user.info");
            tracing::event!(name: "dependency.warn", target: "dependency", tracing::Level::WARN, "dependency warning");
        });
        recorded.0.lock().unwrap().clone()
    }

    #[test]
    fn node_levels_and_aliases_preserve_dependency_warnings_without_enabling_vm_spans() {
        for expression in ["", "info", "miden=info", "miden::=info"] {
            assert_eq!(
                record(expression),
                ["process.info", "rpc.info", "prover.warn", "dependency.warn"],
                "{expression}"
            );
        }
        for expression in ["debug", "miden=debug", "miden::=debug"] {
            assert_eq!(
                record(expression),
                ["process.info", "process.debug", "rpc.info", "prover.warn", "dependency.warn"],
                "{expression}"
            );
        }
        assert_eq!(record("off"), Vec::<&str>::new());
        assert_eq!(record("miden=off"), ["prover.warn", "dependency.warn"]);
        assert_eq!(record("off,miden::process=info"), ["process.info"]);
    }

    #[test]
    fn dependency_targets_can_be_enabled_and_disabled_explicitly() {
        assert_eq!(
            record("info,tonic=debug,miden_processor=info,miden_prover=off"),
            ["process.info", "rpc.info", "vm.info", "tonic.debug", "dependency.warn"]
        );
        assert_eq!(
            record("info,user=info"),
            ["process.info", "rpc.info", "prover.warn", "user.info", "dependency.warn"]
        );
    }

    #[test]
    fn named_node_overrides_take_precedence_over_bare_levels_in_either_order() {
        for expression in ["miden=debug,off", "off,miden=debug", "miden::=debug,off"] {
            assert_eq!(record(expression), ["process.info", "process.debug", "rpc.info"]);
        }
        for expression in ["miden=off,debug", "debug,miden=off", "miden::=off,debug"] {
            assert_eq!(record(expression), ["prover.warn", "dependency.warn"]);
        }
    }

    #[test]
    fn effective_filters_can_be_restored_without_changing_output() {
        for expression in ["info", "debug", "miden=debug", "off", "off,tonic=debug"] {
            let (_, effective) = parse_filter(expression).unwrap();
            assert_eq!(record(expression), record(&effective), "{expression}");
            assert_eq!(parse_filter(&effective).unwrap().1, effective);
        }
        assert!(parse_filter("miden=invalid,miden=info").is_err());
    }
}
