//! Control-plane events used by the tracing crate itself.
//!
//! These are deliberately not public API. They let the crate route operational signals, such as
//! panics, through `tracing` without exposing those signals as user-visible events or exporter
//! output. The subscriber/exporter setup owned by this crate is expected to install
//! [`ControlPlaneEventLayer`] and filter the raw control-plane events from normal layers.

use std::cell::RefCell;
use std::fmt;
use std::panic::PanicHookInfo;

use opentelemetry::trace::Status;
use opentelemetry::{Key, Value};
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, Filter};

/// Target used for tracing events that carry control-plane signals.
pub(crate) const CONTROL_PLANE_TARGET: &str = "miden_tracing::control_plane";

const SPANLESS_PANIC_SPAN_NAME: &str = "spanless_panic";

thread_local! {
    // `tracing::Span::current()` is empty while a subscriber layer is handling an event.
    // Crate-owned emitters set this before dispatching so the layer can still mutate the
    // intended OpenTelemetry span through the public `tracing-opentelemetry` extension API.
    static SELECTED_SPAN: RefCell<Option<tracing::Span>> = const { RefCell::new(None) };
}

/// Field names used by control-plane events.
pub(crate) mod field {
    /// Control-plane event kind.
    pub const CONTROL_PLANE_KIND: &str = "control_plane.kind";
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

/// Control-plane event kinds.
pub(crate) mod kind {
    /// Panic event kind.
    pub const PANIC: &str = "panic";
}

/// Layer which consumes control-plane events.
///
/// The layer currently handles panic events by copying their `panic.*` fields onto the span
/// selected by the crate-owned emitter and marking the span status as failed. Raw control-plane
/// events should be filtered from normal output/export layers with [`IgnoreControlPlaneEvents`].
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ControlPlaneEventLayer;

impl<S> Layer<S> for ControlPlaneEventLayer
where
    S: tracing::Subscriber,
{
    /// Handles a control-plane event.
    ///
    /// Layers cannot consume events in `tracing`, so this layer translates only the reserved
    /// control-plane event and relies on sibling per-layer filters to keep the raw event away from
    /// stdout and OpenTelemetry exporters.
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if !is_control_plane_event(event.metadata()) {
            return;
        }

        // Parse fields from the generic `tracing` event instead of depending on any callsite
        // layout. This keeps the plumbing reusable for future control-plane event kinds.
        let mut fields = ControlPlaneEventFields::default();
        event.record(&mut fields);

        if fields.is_panic() {
            fields.record_panic_on_current_span();
        }
    }
}

/// Per-layer filter which hides raw control-plane events from normal output/export layers.
///
/// This rejects events on the reserved control-plane target. Other records on the control-plane
/// target, such as the `spanless_panic` fallback span, remain visible to the wrapped layer.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IgnoreControlPlaneEvents;

impl<S> Filter<S> for IgnoreControlPlaneEvents {
    /// Returns `false` for raw control-plane events.
    ///
    /// This filter is intended for normal output/export layers. It suppresses the control-plane
    /// event itself while still allowing other records on the control-plane target, such as
    /// fallback spans, to reach the wrapped layer.
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        !is_control_plane_event(metadata)
    }

    /// Enables callsite caching for the static control-plane event decision.
    ///
    /// The reserved target and metadata kind are compile-time metadata, so the decision does not
    /// need per-event context.
    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_control_plane_event(metadata) {
            tracing::subscriber::Interest::never()
        } else {
            tracing::subscriber::Interest::always()
        }
    }
}

/// Per-layer filter which enables only control-plane events.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OnlyControlPlaneEvents;

impl<S> Filter<S> for OnlyControlPlaneEvents {
    /// Returns `true` only for raw control-plane events.
    ///
    /// This is paired with [`ControlPlaneEventLayer`] so that the control-plane layer does not keep
    /// ordinary application spans/events enabled by itself.
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        is_control_plane_event(metadata)
    }

    /// Enables callsite caching for the static control-plane event decision.
    ///
    /// Returning `never` for all other callsites keeps the control-plane layer out of the hot path
    /// for regular application telemetry.
    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_control_plane_event(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }
}

/// Per-layer filter which applies `inner` to normal spans/events while keeping control-plane
/// plumbing available.
///
/// Raw control-plane events are hidden from the wrapped layer, but other records on the
/// control-plane target, such as the `spanless_panic` fallback span, bypass `inner`.
#[derive(Clone, Debug)]
pub(crate) struct WithControlPlaneEvents<F> {
    inner: F,
}

impl<F> WithControlPlaneEvents<F> {
    /// Creates a filter wrapper around `inner`.
    ///
    /// The wrapper preserves the caller's runtime filter for normal telemetry, but reserves a path
    /// for crate-owned control-plane fallback records.
    pub(crate) fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<S, F> Filter<S> for WithControlPlaneEvents<F>
where
    F: Filter<S>,
{
    /// Applies `inner` to application telemetry and bypasses it for control-plane fallback records.
    ///
    /// Raw control-plane events return `false` because they are plumbing messages, not
    /// user-visible telemetry. Other records on the control-plane target return `true` so fallback
    /// spans can still be exported even when the user filter is `off`.
    fn enabled(&self, metadata: &tracing::Metadata<'_>, ctx: &Context<'_, S>) -> bool {
        if is_control_plane_event(metadata) {
            false
        } else if is_control_plane_target(metadata.target()) {
            true
        } else {
            self.inner.enabled(metadata, ctx)
        }
    }

    /// Returns a cacheable callsite decision matching [`Self::enabled`].
    ///
    /// Control-plane target decisions are static from metadata. All other callsites delegate to the
    /// wrapped filter so dynamic runtime filtering continues to behave normally.
    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_control_plane_event(metadata) {
            tracing::subscriber::Interest::never()
        } else if is_control_plane_target(metadata.target()) {
            tracing::subscriber::Interest::always()
        } else {
            self.inner.callsite_enabled(metadata)
        }
    }

    /// Applies the same routing rule once `tracing` has constructed an event.
    ///
    /// This mirrors [`Self::enabled`] because some filters make an additional event-level decision
    /// after seeing field values.
    fn event_enabled(&self, event: &tracing::Event<'_>, ctx: &Context<'_, S>) -> bool {
        if is_control_plane_event(event.metadata()) {
            false
        } else if is_control_plane_target(event.metadata().target()) {
            true
        } else {
            self.inner.event_enabled(event, ctx)
        }
    }

    /// Avoids advertising a restrictive static level hint.
    ///
    /// The wrapped filter may have its own hint, but control-plane fallback telemetry must remain
    /// able to emit at `ERROR` even if the wrapped filter currently resolves to `OFF`.
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        None
    }
}

/// Wraps a layer filter so control-plane tracing plumbing can bypass it.
///
/// Subscriber/exporter construction should use this around user-controlled filters for layers that
/// should see fallback control-plane spans but not raw control-plane events.
pub(crate) fn with_control_plane_events<F>(filter: F) -> WithControlPlaneEvents<F> {
    WithControlPlaneEvents::new(filter)
}

/// Returns `true` if `metadata` describes a control-plane event.
pub(crate) fn is_control_plane_event(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.is_event() && is_control_plane_target(metadata.target())
}

/// Returns `true` when `target` is reserved for this crate's control-plane telemetry.
///
/// This is intentionally narrower than prefix matching: a user target under a similar namespace
/// should not accidentally bypass runtime filters.
pub(crate) fn is_control_plane_target(target: &str) -> bool {
    target == CONTROL_PLANE_TARGET
}

/// Emits the panic control-plane event.
///
/// If no tracing span is currently active, this creates a short-lived `spanless_panic` fallback
/// span so OpenTelemetry exporters still have a span to attach the panic attributes to.
pub(crate) fn emit_panic(info: &PanicHookInfo<'_>) {
    if tracing::Span::current().is_disabled() {
        // A disabled current span means there is no OpenTelemetry span for the layer to mutate.
        // Create a short fallback span so the panic is still exported somewhere useful.
        let span = tracing::error_span!(target: CONTROL_PLANE_TARGET, SPANLESS_PANIC_SPAN_NAME);
        let _guard = span.enter();
        let _selected_span = SelectedSpanGuard::new(span.clone());
        emit_panic_event(info);
    } else {
        let _selected_span = SelectedSpanGuard::new(tracing::Span::current());
        emit_panic_event(info);
    }
}

/// Dispatches the reserved panic control-plane event.
///
/// The event is the synchronization point between the panic hook and the control-plane layer.
/// Normal output/export layers should filter this event out and observe only the translated span
/// attributes/status.
fn emit_panic_event(info: &PanicHookInfo<'_>) {
    let message = panic_message(info);
    // Panics should be rare, and the call site may not have enabled process-wide backtraces. Force
    // a capture here so exported panic telemetry is actionable by default.
    let backtrace = std::backtrace::Backtrace::force_capture().to_string();
    let thread = std::thread::current();
    let thread_name = thread.name().unwrap_or("<unnamed>");
    let location = info.location();
    let file = location.map_or("<unknown>", std::panic::Location::file);
    let line = location.map_or(0, std::panic::Location::line);
    let column = location.map_or(0, std::panic::Location::column);

    tracing::event!(
        target: CONTROL_PLANE_TARGET,
        tracing::Level::ERROR,
        control_plane.kind = kind::PANIC,
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

/// Extracts a stable panic message from the panic payload.
///
/// Rust panic payloads are arbitrary `Any` values. String payloads are the common case; other
/// payloads are represented with a fixed message so tracing never tries to format an unknown type
/// from the panic hook.
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
struct ControlPlaneEventFields {
    kind: Option<String>,
    is_panic: bool,
    panic_message: Option<String>,
    panic_attributes: Vec<(Key, Value)>,
}

impl ControlPlaneEventFields {
    /// Returns `true` when the recorded control-plane event describes a panic.
    ///
    /// Both the explicit kind and boolean marker are accepted so the control-plane schema remains
    /// easy to match in layers while still being extensible for future event kinds.
    fn is_panic(&self) -> bool {
        self.is_panic || self.kind.as_deref() == Some(kind::PANIC)
    }

    /// Writes the parsed panic fields to the span selected by the emitter.
    ///
    /// `tracing::Span::current()` is not reliable from inside a layer callback, so this first uses
    /// the thread-local span installed by [`SelectedSpanGuard`]. Falling back to `current()` keeps
    /// the method robust for tests or future callers that can tolerate best-effort behavior.
    fn record_panic_on_current_span(self) {
        let span = selected_span().unwrap_or_else(tracing::Span::current);
        if span.is_disabled() {
            return;
        }

        // Preserve the field names from the control-plane event as OpenTelemetry span attributes.
        // The raw event itself is filtered from exporters, so these attributes are the
        // exported signal.
        for (key, value) in self.panic_attributes {
            tracing_opentelemetry::OpenTelemetrySpanExt::set_attribute(&span, key, value);
        }

        tracing_opentelemetry::OpenTelemetrySpanExt::set_status(
            &span,
            Status::Error {
                description: self
                    .panic_message
                    .map_or_else(|| "panic".to_owned(), |message| format!("panic: {message}"))
                    .into(),
            },
        );
    }

    /// Records a boolean event field relevant to control-plane panic handling.
    fn record_bool(&mut self, field: &Field, value: bool) {
        let name = field.name();
        if name == field::PANIC && value {
            self.is_panic = true;
        }
        self.record_panic_attribute(name, value.into());
    }

    /// Records a signed integer event field relevant to control-plane panic handling.
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_panic_attribute(field.name(), value.into());
    }

    /// Records an unsigned integer event field relevant to control-plane panic handling.
    ///
    /// OpenTelemetry values do not have an unsigned integer variant, so values are saturated into
    /// `i64` instead of risking lossy wrapping.
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_panic_attribute(field.name(), u64_to_i64(value).into());
    }

    /// Records a floating-point event field relevant to control-plane panic handling.
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_panic_attribute(field.name(), value.into());
    }

    /// Records a string event field relevant to control-plane panic handling.
    ///
    /// The control-plane kind routes the event and is not copied as a panic attribute;
    /// `panic.message` is retained separately so it can also become the span status description.
    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == field::CONTROL_PLANE_KIND {
            self.kind = Some(value.to_owned());
            return;
        }
        if name == field::PANIC_MESSAGE {
            self.panic_message = Some(value.to_owned());
        }
        self.record_panic_attribute(name, value.to_owned().into());
    }

    /// Records a debug-formatted event field relevant to control-plane panic handling.
    ///
    /// This is the fallback visitor path for values without a more specific typed callback.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let value = format!("{value:?}");
        let name = field.name();
        if name == field::CONTROL_PLANE_KIND {
            self.kind = Some(value);
            return;
        }
        if name == field::PANIC_MESSAGE {
            self.panic_message = Some(value.clone());
        }
        self.record_panic_attribute(name, value.into());
    }

    /// Stores a field as a panic span attribute when its key belongs to the panic schema.
    ///
    /// Control-plane fields such as `control_plane.kind` are intentionally ignored here; they
    /// route the control-plane event but are not part of the user-facing panic telemetry.
    fn record_panic_attribute(&mut self, name: &'static str, value: Value) {
        if name == field::PANIC || name.starts_with("panic.") {
            self.panic_attributes.push((Key::from_static_str(name), value));
        }
    }
}

impl Visit for ControlPlaneEventFields {
    // Forward typed visitor callbacks to inherent methods. This avoids recursive calls with the
    // same names while keeping all panic-schema handling in one implementation block.
    fn record_bool(&mut self, field: &Field, value: bool) {
        ControlPlaneEventFields::record_bool(self, field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        ControlPlaneEventFields::record_i64(self, field, value);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        ControlPlaneEventFields::record_u64(self, field, value);
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        ControlPlaneEventFields::record_f64(self, field, value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        ControlPlaneEventFields::record_str(self, field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        ControlPlaneEventFields::record_debug(self, field, value);
    }
}

/// Converts a `u64` into the closest OpenTelemetry integer representation.
///
/// `opentelemetry::Value` only supports signed 64-bit integers, so values above `i64::MAX` are
/// saturated to preserve monotonicity without panicking from the panic path.
fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

struct SelectedSpanGuard {
    previous: Option<tracing::Span>,
}

impl SelectedSpanGuard {
    /// Installs `span` as the OpenTelemetry span to mutate while dispatching a control-plane event.
    ///
    /// The previous value is restored on drop so nested control-plane events do not leak their
    /// selected span into later events on the same thread.
    fn new(span: tracing::Span) -> Self {
        let previous = SELECTED_SPAN.with(|selected_span| selected_span.replace(Some(span)));
        Self { previous }
    }
}

impl Drop for SelectedSpanGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        // Restore rather than clear so nested control-plane events unwind correctly.
        SELECTED_SPAN.with(|selected_span| {
            selected_span.replace(previous);
        });
    }
}

/// Returns the span currently selected for control-plane event translation.
///
/// This is a clone of the `tracing::Span` handle, not a clone of span data.
fn selected_span() -> Option<tracing::Span> {
    SELECTED_SPAN.with(|selected_span| selected_span.borrow().clone())
}

#[cfg(test)]
mod tests {
    use opentelemetry::Value;
    use opentelemetry::trace::Status;
    use opentelemetry_sdk::trace::SpanData;
    use tracing::subscriber::with_default;
    use tracing_subscriber::prelude::*;

    use super::{
        CONTROL_PLANE_TARGET,
        ControlPlaneEventFields,
        ControlPlaneEventLayer,
        IgnoreControlPlaneEvents,
        OnlyControlPlaneEvents,
        SelectedSpanGuard,
    };
    use crate::test_utils::{TestExporter, assert_attribute};

    #[test]
    fn control_plane_layer_records_panic_fields_on_current_span() {
        let spans = exported_spans_with_control_plane_layer(|| {
            let span = tracing::info_span!("panic_parent");
            let _guard = span.enter();
            let _selected_span = SelectedSpanGuard::new(span.clone());

            tracing::event!(
                target: CONTROL_PLANE_TARGET,
                tracing::Level::ERROR,
                control_plane.kind = "panic",
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
            "raw control-plane events must not be exported: {:?}",
            span.events.events
        );
    }

    #[test]
    fn control_plane_event_filter_rejects_reserved_target_events() {
        let spans = exported_spans_with_control_plane_layer(|| {
            let span = tracing::error_span!(target: CONTROL_PLANE_TARGET, "spanless_panic");
            let _guard = span.enter();
            let _selected_span = SelectedSpanGuard::new(span.clone());
            tracing::event!(
                target: CONTROL_PLANE_TARGET,
                tracing::Level::ERROR,
                control_plane.kind = "panic",
                panic = true,
                panic.message = "test panic",
                "panic"
            );
        });
        let span = span_by_name(&spans, "spanless_panic");

        assert_attribute(span, "panic.message", "test panic");
        assert!(span.events.events.is_empty());
    }

    fn exported_spans_with_control_plane_layer(record: impl FnOnce()) -> Vec<SpanData> {
        let exporter = TestExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let tracer = opentelemetry::trace::TracerProvider::tracer(
            &provider,
            "miden-node-tracing-control-plane-test",
        );
        let subscriber = tracing_subscriber::registry()
            .with(ControlPlaneEventLayer.with_filter(OnlyControlPlaneEvents))
            .with(
                tracing_opentelemetry::layer()
                    .with_tracer(tracer)
                    .with_filter(IgnoreControlPlaneEvents),
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
        let mut fields = ControlPlaneEventFields::default();
        fields.record_panic_attribute("panic.value", Value::I64(super::u64_to_i64(u64::MAX)));

        assert_eq!(fields.panic_attributes[0].1, Value::I64(i64::MAX));
    }
}
