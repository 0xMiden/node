use std::str::FromStr;
use std::sync::{Arc, RwLock};

use tracing_subscriber::filter::ParseError;
use tracing_subscriber::layer::{Context, Filter};
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::internal;

/// Default filter used when callers do not provide an initial exporter filter.
pub(crate) const DEFAULT_FILTER: &str = "info";

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

/// A dynamic tracing filter layer which only enables Miden targets.
#[derive(Debug)]
pub(crate) struct DynamicFilterLayer {
    inner: Arc<RwLock<EnvFilter>>,
}

/// Handle for reading and replacing a dynamic tracing filter at runtime.
#[derive(Debug)]
pub(crate) struct DynamicFilter {
    inner: Arc<RwLock<EnvFilter>>,
    current: Arc<RwLock<String>>,
}

impl DynamicFilter {
    /// Creates a dynamic filter initialized from `filter`.
    pub fn new(filter: impl Into<String>) -> Result<(DynamicFilterLayer, Self), FilterError> {
        new(filter)
    }

    /// Returns the current filter string.
    pub fn get(&self) -> Result<String, FilterError> {
        self.current
            .read()
            .map(|filter| filter.clone())
            .map_err(|_| FilterError::StatePoisoned)
    }

    /// Replaces the current filter with `filter`.
    ///
    /// The current filter string is updated only after `filter` parses successfully.
    pub fn set(&self, filter: impl Into<String>) -> Result<(), FilterError> {
        let filter = filter.into();
        let env_filter = parse_filter(&filter)?;

        self.set_inner(env_filter);
        self.set_current(filter);

        Ok(())
    }

    fn set_inner(&self, filter: EnvFilter) {
        let mut current = match self.inner.write() {
            Ok(current) => current,
            Err(poisoned) => {
                self.inner.clear_poison();
                poisoned.into_inner()
            },
        };
        *current = filter;
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
            inner: self.inner.clone(),
            current: self.current.clone(),
        }
    }
}

impl DynamicFilterLayer {
    fn with_inner<T>(&self, read: impl FnOnce(&EnvFilter) -> T) -> T {
        match self.inner.read() {
            Ok(filter) => read(&filter),
            Err(poisoned) => {
                self.inner.clear_poison();
                let filter = poisoned.into_inner();
                read(&filter)
            },
        }
    }

    fn with_inner_mut<T>(&self, write: impl FnOnce(&mut EnvFilter) -> T) -> T {
        match self.inner.write() {
            Ok(mut filter) => write(&mut filter),
            Err(poisoned) => {
                self.inner.clear_poison();
                let mut filter = poisoned.into_inner();
                write(&mut filter)
            },
        }
    }
}

fn new(filter: impl Into<String>) -> Result<(DynamicFilterLayer, DynamicFilter), FilterError> {
    let filter = filter.into();
    let env_filter = parse_filter(&filter)?;
    let inner = Arc::new(RwLock::new(env_filter));

    Ok((
        DynamicFilterLayer { inner: inner.clone() },
        DynamicFilter {
            inner,
            current: Arc::new(RwLock::new(filter)),
        },
    ))
}

fn parse_filter(filter: &str) -> Result<EnvFilter, FilterError> {
    let env_filter = EnvFilter::from_str(filter)
        .map_err(|source| FilterError::Parse { filter: filter.to_owned(), source })?;
    validate_filter(filter)?;
    Ok(env_filter)
}

fn validate_filter(filter: &str) -> Result<(), FilterError> {
    if filter.contains('{') || filter.contains('}') {
        return Err(FilterError::UnsupportedDirective {
            directive: filter.to_owned(),
            reason: "field filters are not supported",
        });
    }

    for directive in filter.split(',').map(str::trim).filter(|directive| !directive.is_empty()) {
        let Some(target) = directive_target(directive) else {
            continue;
        };

        if !is_allowed_target_filter(target) {
            return Err(FilterError::UnsupportedTarget(target.to_owned()));
        }
    }

    Ok(())
}

fn directive_target(directive: &str) -> Option<&str> {
    if directive.starts_with('[') {
        return None;
    }

    let target_end = directive.find(['=', '[']).unwrap_or(directive.len());
    let target = &directive[..target_end];

    if is_level(target) { None } else { Some(target) }
}

fn is_level(value: &str) -> bool {
    matches!(value, "off" | "error" | "warn" | "info" | "debug" | "trace")
}

fn is_allowed_target_filter(target: &str) -> bool {
    is_allowed_application_target(target)
        || ALLOWED_TARGETS.iter().any(|allowed| {
            allowed.strip_prefix(target).is_some_and(|suffix| suffix.starts_with("::"))
        })
}

fn is_allowed_application_target(target: &str) -> bool {
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

/// Error returned while creating, reading, or updating an exporter filter.
#[derive(Debug)]
pub enum FilterError {
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
    /// The stored current filter value is no longer readable.
    StatePoisoned,
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            Self::StatePoisoned => {
                f.write_str("tracing filter state is poisoned; set the filter again to clear it")
            },
        }
    }
}

impl std::error::Error for FilterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse { source, .. } => Some(source),
            Self::UnsupportedTarget(_)
            | Self::UnsupportedDirective { .. }
            | Self::StatePoisoned => None,
        }
    }
}

impl Layer<Registry> for DynamicFilterLayer {
    /// Forwards dispatch registration to the wrapped filter.
    fn on_register_dispatch(&self, subscriber: &tracing::Dispatch) {
        self.with_inner(|inner| Layer::<Registry>::on_register_dispatch(inner, subscriber));
    }

    /// Forwards layer installation to the wrapped filter.
    fn on_layer(&mut self, subscriber: &mut Registry) {
        self.with_inner_mut(|inner| Layer::<Registry>::on_layer(inner, subscriber));
    }

    /// Registers callsites for allowed application targets and control-plane plumbing.
    ///
    /// Control-plane callsites must remain available even when the user-facing filter is
    /// `off`, otherwise panic capture and similar crate-owned signals could be disabled by the
    /// runtime admin filter.
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if internal::is_control_plane_target(metadata.target()) {
            tracing::subscriber::Interest::always()
        } else if is_allowed_application_target(metadata.target()) {
            self.with_inner(|inner| Layer::<Registry>::register_callsite(inner, metadata))
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    /// Applies the runtime filter to application telemetry while allowing control-plane plumbing.
    ///
    /// This layer is the global target gate. Control-plane records bypass it so they can
    /// be consumed by crate-owned layers independently of the user-selected trace verbosity.
    fn enabled(&self, metadata: &tracing::Metadata<'_>, ctx: Context<'_, Registry>) -> bool {
        internal::is_control_plane_target(metadata.target())
            || (is_allowed_application_target(metadata.target())
                && self.with_inner(|inner| Layer::<Registry>::enabled(inner, metadata, ctx)))
    }

    /// Forwards span creation for allowed application targets.
    ///
    /// Control-plane fallback spans are enabled by this layer, but the wrapped `EnvFilter` does not
    /// need to track them because control-plane routing is handled by the tracing crate's own
    /// layers.
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, Registry>,
    ) {
        if is_allowed_application_target(attrs.metadata().target()) {
            self.with_inner(|inner| Layer::<Registry>::on_new_span(inner, attrs, id, ctx));
        }
    }

    /// Forwards span field updates to the wrapped filter.
    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, Registry>,
    ) {
        self.with_inner(|inner| Layer::<Registry>::on_record(inner, span, values, ctx));
    }

    /// Forwards causal span relationships to the wrapped filter.
    fn on_follows_from(
        &self,
        span: &tracing::span::Id,
        follows: &tracing::span::Id,
        ctx: Context<'_, Registry>,
    ) {
        self.with_inner(|inner| Layer::<Registry>::on_follows_from(inner, span, follows, ctx));
    }

    /// Applies event-level filtering while preserving control-plane delivery.
    ///
    /// Some filters make decisions after seeing event metadata. Control-plane events bypass that
    /// path so operational plumbing cannot be disabled accidentally by a user directive.
    fn event_enabled(&self, event: &tracing::Event<'_>, ctx: Context<'_, Registry>) -> bool {
        internal::is_control_plane_target(event.metadata().target())
            || (is_allowed_application_target(event.metadata().target())
                && self.with_inner(|inner| Layer::<Registry>::event_enabled(inner, event, ctx)))
    }

    /// Forwards user-facing events to the wrapped filter.
    ///
    /// Control-plane events are deliberately not forwarded to the user filter layer; they are
    /// consumed by crate-owned layers and filtered from normal output/export layers.
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, Registry>) {
        if is_allowed_application_target(event.metadata().target()) {
            self.with_inner(|inner| Layer::<Registry>::on_event(inner, event, ctx));
        }
    }

    /// Forwards span enter notifications to the wrapped filter.
    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, Registry>) {
        self.with_inner(|inner| Layer::<Registry>::on_enter(inner, id, ctx));
    }

    /// Forwards span exit notifications to the wrapped filter.
    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, Registry>) {
        self.with_inner(|inner| Layer::<Registry>::on_exit(inner, id, ctx));
    }

    /// Forwards span close notifications to the wrapped filter.
    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, Registry>) {
        self.with_inner(|inner| Layer::<Registry>::on_close(inner, id, ctx));
    }

    /// Forwards span id changes to the wrapped filter.
    fn on_id_change(
        &self,
        old: &tracing::span::Id,
        new: &tracing::span::Id,
        ctx: Context<'_, Registry>,
    ) {
        self.with_inner(|inner| Layer::<Registry>::on_id_change(inner, old, new, ctx));
    }

    /// Avoids a restrictive global level hint.
    ///
    /// The runtime filter may currently be `off`, but control-plane records must still be
    /// able to emit. Returning `None` asks `tracing` to consult `enabled`/`event_enabled` instead
    /// of globally pruning callsites by a static max-level hint.
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        None
    }
}

impl<S> Filter<S> for DynamicFilterLayer
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    /// Applies the runtime filter as a per-exporter layer filter.
    ///
    /// This mirrors the global layer implementation while allowing the OTLP and user-facing
    /// stdout exporters to have independent dynamic filters.
    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_allowed_application_target(metadata.target()) {
            self.with_inner(|inner| Filter::<S>::callsite_enabled(inner, metadata))
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    /// Applies the filter only to Miden application targets.
    fn enabled(&self, metadata: &tracing::Metadata<'_>, ctx: &Context<'_, S>) -> bool {
        is_allowed_application_target(metadata.target())
            && self.with_inner(|inner| Filter::<S>::enabled(inner, metadata, ctx))
    }

    /// Forwards span creation so span-name filters such as `[rpc::get_block]=debug` work.
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        if is_allowed_application_target(attrs.metadata().target()) {
            self.with_inner(|inner| Filter::<S>::on_new_span(inner, attrs, id, ctx));
        }
    }

    /// Forwards span field updates to the wrapped filter.
    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        self.with_inner(|inner| Filter::<S>::on_record(inner, span, values, ctx));
    }

    /// Forwards span enter notifications for filters that need span stack context.
    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        self.with_inner(|inner| Filter::<S>::on_enter(inner, id, ctx));
    }

    /// Forwards span exit notifications for filters that need span stack context.
    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        self.with_inner(|inner| Filter::<S>::on_exit(inner, id, ctx));
    }

    /// Forwards span close notifications so filter state is cleaned up.
    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        self.with_inner(|inner| Filter::<S>::on_close(inner, id, ctx));
    }

    /// Applies event-level filtering while preserving the application target gate.
    fn event_enabled(&self, event: &tracing::Event<'_>, ctx: &Context<'_, S>) -> bool {
        is_allowed_application_target(event.metadata().target())
            && self.with_inner(|inner| Filter::<S>::event_enabled(inner, event, ctx))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::subscriber::with_default;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;

    use super::{DEFAULT_FILTER, DynamicFilter, FilterError, is_allowed_application_target};

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
        assert!(matches!(filter.get(), Err(FilterError::StatePoisoned)));

        filter.set("store=debug").unwrap();

        assert_eq!(filter.get().unwrap(), "store=debug");
    }

    #[test]
    fn poisoned_current_value_error_mentions_set() {
        let error = FilterError::StatePoisoned.to_string();

        assert!(error.contains("set the filter again to clear it"));
    }

    #[test]
    fn dynamic_filter_default_parses() {
        let (_layer, filter) = DynamicFilter::new(DEFAULT_FILTER).unwrap();

        assert_eq!(filter.get().unwrap(), DEFAULT_FILTER);
    }

    #[test]
    fn dynamic_filter_rejects_third_party_targets() {
        let err = DynamicFilter::new("axum::rejection=trace").unwrap_err();

        assert!(matches!(err, FilterError::UnsupportedTarget(_)));
    }

    #[test]
    fn dynamic_filter_rejects_field_filters() {
        let err = DynamicFilter::new("[rpc::get_block{request.id=1}]=debug").unwrap_err();

        assert!(matches!(err, FilterError::UnsupportedDirective { .. }));
    }

    #[test]
    fn dynamic_filter_allows_target_namespaces() {
        DynamicFilter::new("store=debug,store::grpc::server=trace").unwrap();
    }

    #[test]
    fn dynamic_filter_allows_span_filters() {
        DynamicFilter::new("[rpc::get_block]=debug").unwrap();
    }

    #[test]
    fn dynamic_filter_layer_can_be_attached_to_registry() {
        let (layer, _filter) = DynamicFilter::new("info").unwrap();

        let _subscriber = tracing_subscriber::registry().with(layer);
    }

    #[test]
    fn application_target_gate_disables_third_party_targets() {
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
    fn application_target_gate_still_applies_inside_span_filters() {
        let (layer, _filter) = DynamicFilter::new("[rpc::get_block]=debug").unwrap();
        let capture = CaptureLayer::default();
        let captured = capture.captured.clone();
        let subscriber = tracing_subscriber::registry().with(layer).with(capture);

        with_default(subscriber, || {
            let _span = tracing::info_span!(target: "rpc", "rpc::get_block").entered();
            tracing::debug!(target: "store::database", "own child");
            tracing::debug!(target: "h2", "dependency child");
        });

        assert_eq!(*captured.lock().unwrap(), vec!["store::database"]);
    }

    #[test]
    fn control_plane_target_bypasses_dynamic_filter() {
        let (layer, _filter) = DynamicFilter::new("off").unwrap();
        let capture = CaptureLayer::default();
        let captured = capture.captured.clone();
        let subscriber = tracing_subscriber::registry().with(layer).with(capture);

        with_default(subscriber, || {
            tracing::event!(
                target: crate::internal::CONTROL_PLANE_TARGET,
                tracing::Level::ERROR,
                control_plane.kind = "panic",
                panic = true,
            );
            tracing::error!(target: "rpc", "filtered");
        });

        assert_eq!(*captured.lock().unwrap(), vec![crate::internal::CONTROL_PLANE_TARGET]);
    }

    #[test]
    fn allowed_application_target_matches_allowed_targets_and_subtargets() {
        assert!(is_allowed_application_target("rpc"));
        assert!(is_allowed_application_target("store::database"));
        assert!(is_allowed_application_target("store::database::queries"));
        assert!(!is_allowed_application_target("h2"));
        assert!(!is_allowed_application_target("store"));
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
