use std::str::FromStr;
use std::sync::{Arc, RwLock};

use tracing_subscriber::filter::ParseError;
use tracing_subscriber::layer::Context;
use tracing_subscriber::{EnvFilter, Layer, Registry, reload};

/// Default trace filter used when `RUST_LOG` is not set.
pub const DEFAULT_FILTER: &str = "info";

const ALLOWED_TARGETS: &[&str] = &[
    "rpc",
    "validator::database",
    "store::database",
    "store::forest",
    "store::grpc::server::rpc",
    "store::grpc::server::ntx",
    "store::grpc::server::sequencer",
    "sequencer::batch_builder",
    "sequencer::block_builder",
    "sequencer::mempool",
    "ntxb::coordinator",
    "ntxb::actor",
    "ntxb::database",
];

/// A reloadable tracing filter layer which only enables Miden targets.
#[derive(Debug)]
pub struct DynamicFilterLayer {
    inner: reload::Layer<EnvFilter, Registry>,
}

/// Handle for reading and replacing a reloadable tracing filter at runtime.
#[derive(Debug)]
pub struct DynamicFilter {
    handle: reload::Handle<EnvFilter, Registry>,
    current: Arc<RwLock<String>>,
}

impl DynamicFilter {
    /// Creates a reloadable filter initialized from `RUST_LOG`, or [`DEFAULT_FILTER`] if unset.
    pub fn from_env() -> Result<(DynamicFilterLayer, Self), DynamicFilterError> {
        from_env()
    }

    /// Creates a reloadable filter initialized from `filter`.
    pub fn new(
        filter: impl Into<String>,
    ) -> Result<(DynamicFilterLayer, Self), DynamicFilterError> {
        new(filter)
    }

    /// Returns the current filter string.
    pub fn get(&self) -> Result<String, DynamicFilterError> {
        self.current
            .read()
            .map(|filter| filter.clone())
            .map_err(|_| DynamicFilterError::StatePoisoned)
    }

    /// Replaces the current filter with `filter`.
    ///
    /// The current filter string is updated only after `filter` parses successfully and the
    /// subscriber reload succeeds.
    pub fn set(&self, filter: impl Into<String>) -> Result<(), DynamicFilterError> {
        let filter = filter.into();
        let env_filter = parse_filter(&filter)?;

        self.handle.reload(env_filter)?;
        self.set_current(filter);

        Ok(())
    }

    fn set_current(&self, filter: String) {
        let mut current = match self.current.write() {
            Ok(current) => current,
            Err(poisoned) => {
                self.current.clear_poison();
                poisoned.into_inner()
            },
        };
        *current = filter;
    }
}

impl Clone for DynamicFilter {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            current: self.current.clone(),
        }
    }
}

fn from_env() -> Result<(DynamicFilterLayer, DynamicFilter), DynamicFilterError> {
    match std::env::var(EnvFilter::DEFAULT_ENV) {
        Ok(filter) => new(filter),
        Err(std::env::VarError::NotPresent) => new(DEFAULT_FILTER),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(DynamicFilterError::EnvVarNotUnicode(EnvFilter::DEFAULT_ENV))
        },
    }
}

fn new(
    filter: impl Into<String>,
) -> Result<(DynamicFilterLayer, DynamicFilter), DynamicFilterError> {
    let filter = filter.into();
    let env_filter = parse_filter(&filter)?;
    let (inner, handle) = reload::Layer::new(env_filter);

    Ok((
        DynamicFilterLayer { inner },
        DynamicFilter {
            handle,
            current: Arc::new(RwLock::new(filter)),
        },
    ))
}

fn parse_filter(filter: &str) -> Result<EnvFilter, DynamicFilterError> {
    let env_filter = EnvFilter::from_str(filter)
        .map_err(|source| DynamicFilterError::Parse { filter: filter.to_owned(), source })?;
    validate_filter(filter)?;
    Ok(env_filter)
}

fn validate_filter(filter: &str) -> Result<(), DynamicFilterError> {
    if filter.contains('{') || filter.contains('}') {
        return Err(DynamicFilterError::UnsupportedDirective {
            directive: filter.to_owned(),
            reason: "field filters are not supported",
        });
    }

    for directive in filter.split(',').map(str::trim).filter(|directive| !directive.is_empty()) {
        let Some(target) = directive_target(directive) else {
            continue;
        };

        if !is_allowed_target_filter(target) {
            return Err(DynamicFilterError::UnsupportedTarget(target.to_owned()));
        }
    }

    Ok(())
}

fn directive_target(directive: &str) -> Option<&str> {
    if directive.starts_with('[') {
        return None;
    }

    let target_end = directive.find(|ch| matches!(ch, '=' | '[')).unwrap_or(directive.len());
    let target = &directive[..target_end];

    if is_level(target) { None } else { Some(target) }
}

fn is_level(value: &str) -> bool {
    matches!(value, "off" | "error" | "warn" | "info" | "debug" | "trace")
}

fn is_allowed_target_filter(target: &str) -> bool {
    is_own_target(target)
        || ALLOWED_TARGETS.iter().any(|allowed| {
            allowed.strip_prefix(target).is_some_and(|suffix| suffix.starts_with("::"))
        })
}

fn is_own_target(target: &str) -> bool {
    ALLOWED_TARGETS.iter().any(|allowed| {
        target == *allowed
            || target.strip_prefix(allowed).is_some_and(|suffix| suffix.starts_with("::"))
    })
}

fn allowed_targets() -> String {
    let mut targets = String::new();
    for target in ALLOWED_TARGETS {
        targets.push_str("\n  - ");
        targets.push_str(target);
    }
    targets
}

/// Error returned while creating, reading, or updating a dynamic tracing filter.
#[derive(Debug)]
pub enum DynamicFilterError {
    /// `RUST_LOG` was set to a non-Unicode value.
    EnvVarNotUnicode(&'static str),
    /// The filter string could not be parsed as a tracing [`EnvFilter`].
    Parse {
        /// The filter string that failed to parse.
        filter: String,
        /// The parse error returned by `tracing-subscriber`.
        source: ParseError,
    },
    /// The filter attempted to enable a target outside the Miden tracing target allowlist.
    UnsupportedTarget(String),
    /// The filter used a directive form that is not supported by Miden tracing.
    UnsupportedDirective {
        /// The unsupported directive.
        directive: String,
        /// Why the directive is unsupported.
        reason: &'static str,
    },
    /// The reloadable filter no longer has an installed subscriber.
    Reload(reload::Error),
    /// The stored current filter value is no longer readable.
    StatePoisoned,
}

impl std::fmt::Display for DynamicFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvVarNotUnicode(env) => write!(f, "{env} contained non-Unicode data"),
            Self::Parse { filter, source } => {
                write!(f, "invalid tracing filter `{filter}`: {source}")
            },
            Self::UnsupportedTarget(target) => {
                write!(
                    f,
                    "unsupported tracing target `{target}`; expected one of:{}",
                    allowed_targets()
                )
            },
            Self::UnsupportedDirective { directive, reason } => {
                write!(f, "unsupported tracing filter directive `{directive}`: {reason}")
            },
            Self::Reload(error) => write!(f, "failed to reload tracing filter: {error}"),
            Self::StatePoisoned => {
                f.write_str("dynamic tracing filter state is poisoned; call `set` to clear it")
            },
        }
    }
}

impl std::error::Error for DynamicFilterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse { source, .. } => Some(source),
            Self::Reload(error) => Some(error),
            Self::EnvVarNotUnicode(_)
            | Self::UnsupportedTarget(_)
            | Self::UnsupportedDirective { .. }
            | Self::StatePoisoned => None,
        }
    }
}

impl From<reload::Error> for DynamicFilterError {
    fn from(error: reload::Error) -> Self {
        Self::Reload(error)
    }
}

impl Layer<Registry> for DynamicFilterLayer {
    fn on_register_dispatch(&self, subscriber: &tracing::Dispatch) {
        self.inner.on_register_dispatch(subscriber);
    }

    fn on_layer(&mut self, subscriber: &mut Registry) {
        self.inner.on_layer(subscriber);
    }

    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_own_target(metadata.target()) {
            self.inner.register_callsite(metadata)
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>, ctx: Context<'_, Registry>) -> bool {
        is_own_target(metadata.target()) && self.inner.enabled(metadata, ctx)
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, Registry>,
    ) {
        if is_own_target(attrs.metadata().target()) {
            self.inner.on_new_span(attrs, id, ctx);
        }
    }

    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, Registry>,
    ) {
        self.inner.on_record(span, values, ctx);
    }

    fn on_follows_from(
        &self,
        span: &tracing::span::Id,
        follows: &tracing::span::Id,
        ctx: Context<'_, Registry>,
    ) {
        self.inner.on_follows_from(span, follows, ctx);
    }

    fn event_enabled(&self, event: &tracing::Event<'_>, ctx: Context<'_, Registry>) -> bool {
        is_own_target(event.metadata().target()) && self.inner.event_enabled(event, ctx)
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, Registry>) {
        if is_own_target(event.metadata().target()) {
            self.inner.on_event(event, ctx);
        }
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, Registry>) {
        self.inner.on_enter(id, ctx);
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, Registry>) {
        self.inner.on_exit(id, ctx);
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, Registry>) {
        self.inner.on_close(id, ctx);
    }

    fn on_id_change(
        &self,
        old: &tracing::span::Id,
        new: &tracing::span::Id,
        ctx: Context<'_, Registry>,
    ) {
        self.inner.on_id_change(old, new, ctx);
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        self.inner.max_level_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::subscriber::with_default;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;

    use super::{DEFAULT_FILTER, DynamicFilter, DynamicFilterError, is_own_target};

    #[test]
    fn dynamic_filter_tracks_current_value() {
        let (_layer, filter) = DynamicFilter::new("info").unwrap();

        assert_eq!(filter.get().unwrap(), "info");
        filter.set("store=debug").unwrap();
        assert_eq!(filter.get().unwrap(), "store=debug");
    }

    #[test]
    fn dynamic_filter_preserves_current_value_when_parse_fails() {
        let (_layer, filter) = DynamicFilter::new("info").unwrap();

        assert!(filter.set(",!").is_err());
        assert_eq!(filter.get().unwrap(), "info");
    }

    #[test]
    fn dynamic_filter_set_recovers_poisoned_current_value() {
        let (_layer, filter) = DynamicFilter::new("info").unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _current = filter.current.write().unwrap();
            panic!("poison current filter value");
        }));

        assert!(panic.is_err());
        assert!(matches!(filter.get(), Err(DynamicFilterError::StatePoisoned)));

        filter.set("store=debug").unwrap();

        assert_eq!(filter.get().unwrap(), "store=debug");
    }

    #[test]
    fn poisoned_current_value_error_mentions_set() {
        let error = DynamicFilterError::StatePoisoned.to_string();

        assert!(error.contains("call `set` to clear it"));
    }

    #[test]
    fn dynamic_filter_default_parses() {
        let (_layer, filter) = DynamicFilter::new(DEFAULT_FILTER).unwrap();

        assert_eq!(filter.get().unwrap(), DEFAULT_FILTER);
    }

    #[test]
    fn dynamic_filter_rejects_third_party_targets() {
        let err = DynamicFilter::new("axum::rejection=trace").unwrap_err();

        assert!(matches!(err, DynamicFilterError::UnsupportedTarget(_)));
    }

    #[test]
    fn dynamic_filter_rejects_field_filters() {
        let err = DynamicFilter::new("[rpc.get_block{request.id=1}]=debug").unwrap_err();

        assert!(matches!(err, DynamicFilterError::UnsupportedDirective { .. }));
    }

    #[test]
    fn dynamic_filter_allows_target_namespaces() {
        DynamicFilter::new("store=debug,store::grpc::server=trace").unwrap();
    }

    #[test]
    fn dynamic_filter_allows_span_filters() {
        DynamicFilter::new("[rpc.get_block]=debug").unwrap();
    }

    #[test]
    fn dynamic_filter_layer_can_be_attached_to_registry() {
        let (layer, _filter) = DynamicFilter::new("info").unwrap();

        let _subscriber = tracing_subscriber::registry().with(layer);
    }

    #[test]
    fn own_target_gate_disables_third_party_targets() {
        let (layer, _filter) = DynamicFilter::new("debug").unwrap();
        let capture = CaptureLayer::default();
        let captured = capture.captured.clone();
        let subscriber = tracing_subscriber::registry().with(layer).with(capture);

        with_default(subscriber, || {
            tracing::debug!(target: "rpc", "own");
            tracing::debug!(target: "h2", "dependency");
        });

        assert_eq!(*captured.lock().unwrap(), vec!["rpc"]);
    }

    #[test]
    fn own_target_gate_still_applies_inside_span_filters() {
        let (layer, _filter) = DynamicFilter::new("[rpc.get_block]=debug").unwrap();
        let capture = CaptureLayer::default();
        let captured = capture.captured.clone();
        let subscriber = tracing_subscriber::registry().with(layer).with(capture);

        with_default(subscriber, || {
            let _span = tracing::info_span!(target: "rpc", "rpc.get_block").entered();
            tracing::debug!(target: "store::database", "own child");
            tracing::debug!(target: "h2", "dependency child");
        });

        assert_eq!(*captured.lock().unwrap(), vec!["store::database"]);
    }

    #[test]
    fn own_target_matches_allowed_targets_and_subtargets() {
        assert!(is_own_target("rpc"));
        assert!(is_own_target("store::database"));
        assert!(is_own_target("store::database::queries"));
        assert!(!is_own_target("h2"));
        assert!(!is_own_target("store"));
    }

    #[derive(Clone, Default)]
    struct CaptureLayer {
        captured: Arc<Mutex<Vec<&'static str>>>,
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            self.captured.lock().unwrap().push(event.metadata().target());
        }
    }
}
