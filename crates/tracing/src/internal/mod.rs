use std::cell::RefCell;
use std::fmt;
use std::panic::PanicHookInfo;

use opentelemetry::trace::Status;
use opentelemetry::{Key, Value};
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, Filter};

/// Target used for tracing events that carry internal control-plane signals.
pub(crate) const TARGET: &str = "miden_tracing::internal";

/// Event name used for tracing events that carry internal control-plane signals.
pub(crate) const EVENT_NAME: &str = "miden_tracing::internal";

const SPANLESS_PANIC_SPAN_NAME: &str = "spanless_panic";

thread_local! {
    // `tracing::Span::current()` is empty while a subscriber layer is handling an event.
    // Crate-owned internal emitters set this before dispatching so the layer can still mutate the
    // intended OpenTelemetry span through the public `tracing-opentelemetry` extension API.
    static RECORDING_SPAN: RefCell<Option<tracing::Span>> = const { RefCell::new(None) };
}

/// Field names used by internal control-plane events.
pub(crate) mod field {
    /// Internal event kind.
    pub const INTERNAL_KIND: &str = "internal.kind";
    /// Boolean marker for panic control-plane events.
    pub const PANIC: &str = "panic";
    /// Panic message.
    pub const PANIC_MESSAGE: &str = "panic.message";
    /// Source file reported by the panic hook.
    pub const PANIC_LOCATION_FILE: &str = "panic.location.file";
    /// Source line reported by the panic hook.
    pub const PANIC_LOCATION_LINE: &str = "panic.location.line";
    /// Source column reported by the panic hook.
    pub const PANIC_LOCATION_COLUMN: &str = "panic.location.column";
    /// Current thread name when the panic hook ran.
    pub const PANIC_THREAD_NAME: &str = "panic.thread.name";
    /// Forced backtrace captured by the panic hook.
    pub const PANIC_BACKTRACE: &str = "panic.backtrace";
}

/// Internal control-plane event kinds.
pub(crate) mod kind {
    /// Panic event kind.
    pub const PANIC: &str = "panic";
}

/// Layer which consumes internal control-plane events.
///
/// The layer currently handles panic events by copying their `panic.*` fields onto the span
/// selected by the crate-owned emitter and marking the span status as failed. Raw internal events
/// should be filtered from normal output/export layers with [`IgnoreInternalEvents`].
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InternalEventLayer;

impl<S> Layer<S> for InternalEventLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if !is_internal_event(event.metadata()) {
            return;
        }

        let mut fields = InternalEventFields::default();
        event.record(&mut fields);

        if fields.is_panic() {
            fields.record_panic_on_current_span();
        }
    }
}

/// Per-layer filter which hides raw internal control-plane events from normal output/export layers.
///
/// This only rejects the reserved internal event name. Other records on the internal target, such
/// as the `spanless_panic` fallback span, remain visible to the wrapped layer.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IgnoreInternalEvents;

impl<S> Filter<S> for IgnoreInternalEvents {
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        !is_internal_event(metadata)
    }

    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_internal_event(metadata) {
            tracing::subscriber::Interest::never()
        } else {
            tracing::subscriber::Interest::always()
        }
    }
}

/// Per-layer filter which enables only internal control-plane events.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OnlyInternalEvents;

impl<S> Filter<S> for OnlyInternalEvents {
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        is_internal_event(metadata)
    }

    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_internal_event(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }
}

/// Per-layer filter which applies `inner` to normal spans/events while keeping internal plumbing
/// available.
///
/// Raw internal control-plane events are hidden from the wrapped layer, but other records on the
/// internal target, such as the `spanless_panic` fallback span, bypass `inner`.
#[derive(Clone, Debug)]
pub(crate) struct WithInternalEvents<F> {
    inner: F,
}

impl<F> WithInternalEvents<F> {
    /// Creates a filter wrapper around `inner`.
    pub(crate) fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<S, F> Filter<S> for WithInternalEvents<F>
where
    F: Filter<S>,
{
    fn enabled(&self, metadata: &tracing::Metadata<'_>, ctx: &Context<'_, S>) -> bool {
        if is_internal_event(metadata) {
            false
        } else if is_internal_target(metadata.target()) {
            true
        } else {
            self.inner.enabled(metadata, ctx)
        }
    }

    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_internal_event(metadata) {
            tracing::subscriber::Interest::never()
        } else if is_internal_target(metadata.target()) {
            tracing::subscriber::Interest::always()
        } else {
            self.inner.callsite_enabled(metadata)
        }
    }

    fn event_enabled(&self, event: &tracing::Event<'_>, ctx: &Context<'_, S>) -> bool {
        if is_internal_event(event.metadata()) {
            false
        } else if is_internal_target(event.metadata().target()) {
            true
        } else {
            self.inner.event_enabled(event, ctx)
        }
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        None
    }
}

/// Wraps a layer filter so internal tracing plumbing can bypass it.
pub(crate) fn with_internal_events<F>(filter: F) -> WithInternalEvents<F> {
    WithInternalEvents::new(filter)
}

/// Returns `true` if `metadata` describes the reserved internal control-plane event.
pub(crate) fn is_internal_event(metadata: &tracing::Metadata<'_>) -> bool {
    is_internal_target(metadata.target()) && metadata.name() == EVENT_NAME
}

pub(crate) fn is_internal_target(target: &str) -> bool {
    target == TARGET
}

/// Emits the internal panic control-plane event.
///
/// If no tracing span is currently active, this creates a short-lived `spanless_panic` fallback
/// span so OpenTelemetry exporters still have a span to attach the panic attributes to.
pub(crate) fn emit_panic(info: &PanicHookInfo<'_>) {
    if tracing::Span::current().is_disabled() {
        let span = tracing::error_span!(target: TARGET, SPANLESS_PANIC_SPAN_NAME);
        let _guard = span.enter();
        let _recording_span = RecordingSpanGuard::new(span.clone());
        emit_panic_event(info);
    } else {
        let _recording_span = RecordingSpanGuard::new(tracing::Span::current());
        emit_panic_event(info);
    }
}

fn emit_panic_event(info: &PanicHookInfo<'_>) {
    let message = panic_message(info);
    let backtrace = std::backtrace::Backtrace::force_capture().to_string();
    let thread = std::thread::current();
    let thread_name = thread.name().unwrap_or("<unnamed>");
    let location = info.location();
    let file = location.map_or("<unknown>", std::panic::Location::file);
    let line = location.map_or(0, std::panic::Location::line);
    let column = location.map_or(0, std::panic::Location::column);

    tracing::event!(
        name: "miden_tracing::internal",
        target: TARGET,
        tracing::Level::ERROR,
        internal.kind = kind::PANIC,
        panic = true,
        panic.message = %message,
        panic.location.file = file,
        panic.location.line = line,
        panic.location.column = column,
        panic.thread.name = thread_name,
        panic.backtrace = %backtrace,
        "panic"
    );
}

fn panic_message(info: &PanicHookInfo<'_>) -> String {
    if let Some(message) = info.payload().downcast_ref::<&'static str>() {
        (*message).to_owned()
    } else if let Some(message) = info.payload().downcast_ref::<String>() {
        message.clone()
    } else {
        "panic payload is not a string".to_owned()
    }
}

#[derive(Default)]
struct InternalEventFields {
    kind: Option<String>,
    is_panic: bool,
    panic_message: Option<String>,
    panic_attributes: Vec<(Key, Value)>,
}

impl InternalEventFields {
    fn is_panic(&self) -> bool {
        self.is_panic || self.kind.as_deref() == Some(kind::PANIC)
    }

    fn record_panic_on_current_span(self) {
        let span = recording_span().unwrap_or_else(tracing::Span::current);
        if span.is_disabled() {
            return;
        }

        for (key, value) in self.panic_attributes {
            tracing_opentelemetry::OpenTelemetrySpanExt::set_attribute(&span, key, value);
        }

        tracing_opentelemetry::OpenTelemetrySpanExt::set_status(
            &span,
            Status::Error {
                description: self
                    .panic_message
                    .map(|message| format!("panic: {message}"))
                    .unwrap_or_else(|| "panic".to_owned())
                    .into(),
            },
        );
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        let name = field.name();
        if name == field::PANIC && value {
            self.is_panic = true;
        }
        self.record_panic_attribute(name, value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_panic_attribute(field.name(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_panic_attribute(field.name(), u64_to_i64(value).into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_panic_attribute(field.name(), value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == field::INTERNAL_KIND {
            self.kind = Some(value.to_owned());
            return;
        }
        if name == field::PANIC_MESSAGE {
            self.panic_message = Some(value.to_owned());
        }
        self.record_panic_attribute(name, value.to_owned().into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let value = format!("{value:?}");
        let name = field.name();
        if name == field::INTERNAL_KIND {
            self.kind = Some(value);
            return;
        }
        if name == field::PANIC_MESSAGE {
            self.panic_message = Some(value.clone());
        }
        self.record_panic_attribute(name, value.into());
    }

    fn record_panic_attribute(&mut self, name: &'static str, value: Value) {
        if name == field::PANIC || name.starts_with("panic.") {
            self.panic_attributes.push((Key::from_static_str(name), value));
        }
    }
}

impl Visit for InternalEventFields {
    fn record_bool(&mut self, field: &Field, value: bool) {
        InternalEventFields::record_bool(self, field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        InternalEventFields::record_i64(self, field, value);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        InternalEventFields::record_u64(self, field, value);
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        InternalEventFields::record_f64(self, field, value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        InternalEventFields::record_str(self, field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        InternalEventFields::record_debug(self, field, value);
    }
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

struct RecordingSpanGuard {
    previous: Option<tracing::Span>,
}

impl RecordingSpanGuard {
    fn new(span: tracing::Span) -> Self {
        let previous = RECORDING_SPAN.with(|recording_span| recording_span.replace(Some(span)));
        Self { previous }
    }
}

impl Drop for RecordingSpanGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        RECORDING_SPAN.with(|recording_span| {
            recording_span.replace(previous);
        });
    }
}

fn recording_span() -> Option<tracing::Span> {
    RECORDING_SPAN.with(|recording_span| recording_span.borrow().clone())
}

#[cfg(test)]
mod tests {
    use opentelemetry::Value;
    use opentelemetry::trace::Status;
    use opentelemetry_sdk::trace::SpanData;
    use tracing::subscriber::with_default;
    use tracing_subscriber::prelude::*;

    use super::{
        IgnoreInternalEvents,
        InternalEventLayer,
        OnlyInternalEvents,
        RecordingSpanGuard,
        TARGET,
    };
    use crate::test_utils::{TestExporter, assert_attribute};

    #[test]
    fn internal_layer_records_panic_fields_on_current_span() {
        let spans = exported_spans_with_internal_layer(|| {
            let span = tracing::info_span!("panic_parent");
            let _guard = span.enter();
            let _recording_span = RecordingSpanGuard::new(span.clone());

            tracing::event!(
                name: "miden_tracing::internal",
                target: TARGET,
                tracing::Level::ERROR,
                internal.kind = "panic",
                panic = true,
                panic.message = "test panic",
                panic.location.line = 42_u64,
                "panic"
            );
        });
        let span = span_by_name(&spans, "panic_parent");

        assert_attribute(span, "panic", true);
        assert_attribute(span, "panic.message", "test panic");
        assert_attribute(span, "panic.location.line", 42_i64);
        assert_eq!(span.status, Status::Error { description: "panic: test panic".into() });
        assert!(
            span.events.events.is_empty(),
            "raw internal events must not be exported: {:?}",
            span.events.events
        );
    }

    #[test]
    fn internal_event_filter_rejects_only_reserved_event_name() {
        let spans = exported_spans_with_internal_layer(|| {
            let span = tracing::error_span!(target: TARGET, "spanless_panic");
            let _guard = span.enter();
            let _recording_span = RecordingSpanGuard::new(span.clone());
            tracing::event!(
                name: "miden_tracing::internal",
                target: TARGET,
                tracing::Level::ERROR,
                internal.kind = "panic",
                panic = true,
                panic.message = "test panic",
                "panic"
            );
        });
        let span = span_by_name(&spans, "spanless_panic");

        assert_attribute(span, "panic.message", "test panic");
        assert!(span.events.events.is_empty());
    }

    fn exported_spans_with_internal_layer(record: impl FnOnce()) -> Vec<SpanData> {
        let exporter = TestExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let tracer = opentelemetry::trace::TracerProvider::tracer(
            &provider,
            "miden-node-tracing-internal-test",
        );
        let subscriber = tracing_subscriber::registry()
            .with(InternalEventLayer.with_filter(OnlyInternalEvents))
            .with(
                tracing_opentelemetry::layer()
                    .with_tracer(tracer)
                    .with_filter(IgnoreInternalEvents),
            );

        with_default(subscriber, record);

        drop(provider);
        let spans = exporter.0.lock().expect("span exporter lock poisoned");
        spans.clone()
    }

    fn span_by_name<'a>(spans: &'a [SpanData], name: &str) -> &'a SpanData {
        spans
            .iter()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("missing span {name}; spans: {spans:?}"))
    }

    #[test]
    fn u64_values_saturate_when_recorded_as_i64() {
        let mut fields = super::InternalEventFields::default();
        fields.record_panic_attribute("panic.value", Value::I64(super::u64_to_i64(u64::MAX)));

        assert_eq!(fields.panic_attributes[0].1, Value::I64(i64::MAX));
    }
}
