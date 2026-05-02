//! Control-plane events used by the tracing crate itself.
//!
//! These are deliberately not public API. They let the crate route operational signals, such as
//! panics, through `tracing` without exposing those signals as user-visible events or exporter
//! output. The subscriber/exporter setup owned by this crate is expected to install
//! [`ControlPlaneEventLayer`] and filter the raw control-plane events from normal layers.

use std::cell::RefCell;
use std::fmt;
use std::future::Future;
use std::panic::PanicHookInfo;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use opentelemetry::trace::Status;
use opentelemetry::{Key, Value};
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, Filter};
use tracing_subscriber::registry::LookupSpan;

/// Target used for tracing events that carry control-plane signals.
pub(crate) const CONTROL_PLANE_TARGET: &str = "miden_tracing::control_plane";

const TRACING_PANIC_TARGET: &str = "tracing_panic";
const SPANLESS_PANIC_SPAN_NAME: &str = "spanless_panic";

thread_local! {
    // `tracing::Span::current()` is empty while a subscriber layer is handling an event.
    // Crate-owned emitters set this before dispatching so the layer can still mutate the
    // intended OpenTelemetry span through the public `tracing-opentelemetry` extension API.
    static SELECTED_SPAN: RefCell<Option<tracing::Span>> = const { RefCell::new(None) };
    static ACTIVE_SPANS: RefCell<Vec<tracing::Span>> = const { RefCell::new(Vec::new()) };
}

/// Field names used by control-plane events.
pub(crate) mod field {
    /// Panic payload reported by `tracing-panic`.
    pub const PANIC_PAYLOAD: &str = "panic.payload";
}

/// Field marker used for tracing events emitted only for local user-facing stdout.
pub(crate) const USER_LOG_EVENT: &str = "miden.user.log";

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

/// Layer which tracks entered spans for panic fallback routing.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ActiveSpanLayer;

impl<S> Layer<S> for ActiveSpanLayer
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_enter(&self, _id: &tracing::span::Id, _ctx: Context<'_, S>) {
        push_active_span(tracing::Span::current());
    }

    fn on_exit(&self, id: &tracing::span::Id, _ctx: Context<'_, S>) {
        pop_active_span(id);
    }
}

/// Layer which tracks only entered spans that are explicitly marked for user-facing output.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UserFacingActiveSpanLayer;

impl<S> Layer<S> for UserFacingActiveSpanLayer
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(
        &self,
        _attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        span.extensions_mut().insert(UserFacingActiveSpanState::default());
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut visitor = UserFacingMarkerVisitor::default();
        values.record(&mut visitor);
        if !visitor.user {
            return;
        }

        let mut extensions = span.extensions_mut();
        let Some(state) = extensions.get_mut::<UserFacingActiveSpanState>() else {
            return;
        };
        state.user = true;
        if tracing::Span::current().id().as_ref() != Some(id) {
            return;
        }
        while state.pushed_count < state.entered_count {
            if !push_active_span(tracing::Span::current()) {
                break;
            }
            state.pushed_count += 1;
        }
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        let Some(state) = extensions.get_mut::<UserFacingActiveSpanState>() else {
            return;
        };
        state.entered_count += 1;
        if state.user && push_active_span(tracing::Span::current()) {
            state.pushed_count += 1;
        }
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        let Some(state) = extensions.get_mut::<UserFacingActiveSpanState>() else {
            return;
        };
        state.entered_count = state.entered_count.saturating_sub(1);
        if state.pushed_count > 0 {
            state.pushed_count -= 1;
            pop_active_span(id);
        }
    }
}

#[derive(Debug, Default)]
struct UserFacingActiveSpanState {
    user: bool,
    entered_count: usize,
    pushed_count: usize,
}

#[derive(Debug, Default)]
struct UserFacingMarkerVisitor {
    user: bool,
}

impl Visit for UserFacingMarkerVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == crate::user::ATTRIBUTE_KEY && value {
            self.user = true;
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == crate::user::ATTRIBUTE_KEY && format!("{value:?}") == "true" {
            self.user = true;
        }
    }
}

/// Per-layer filter which hides raw control-plane events from normal output/export layers.
///
/// This rejects events on the reserved control-plane target. Other records on the control-plane
/// target, such as the `spanless_panic` fallback span, remain visible to the wrapped layer.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IgnoreControlPlaneEvents;

#[cfg(test)]
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

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        self.inner.on_new_span(attrs, id, ctx);
    }

    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        self.inner.on_record(span, values, ctx);
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_enter(id, ctx);
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_exit(id, ctx);
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_close(id, ctx);
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

/// Per-layer filter which hides synthetic user-facing stdout events from normal trace export.
#[derive(Clone, Debug)]
pub(crate) struct WithoutUserLogEvents<F> {
    inner: F,
}

impl<F> WithoutUserLogEvents<F> {
    pub(crate) fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<S, F> Filter<S> for WithoutUserLogEvents<F>
where
    F: Filter<S>,
{
    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        self.inner.callsite_enabled(metadata)
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>, ctx: &Context<'_, S>) -> bool {
        self.inner.enabled(metadata, ctx)
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        self.inner.on_new_span(attrs, id, ctx);
    }

    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        self.inner.on_record(span, values, ctx);
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_enter(id, ctx);
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_exit(id, ctx);
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_close(id, ctx);
    }

    fn event_enabled(&self, event: &tracing::Event<'_>, ctx: &Context<'_, S>) -> bool {
        !is_user_log_event(event) && self.inner.event_enabled(event, ctx)
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        self.inner.max_level_hint()
    }
}

pub(crate) fn without_user_log_events<F>(filter: F) -> WithoutUserLogEvents<F> {
    WithoutUserLogEvents::new(filter)
}

fn is_user_log_event(event: &tracing::Event<'_>) -> bool {
    let mut visitor = UserLogEventVisitor::default();
    event.record(&mut visitor);
    visitor.is_user_log_event
}

#[derive(Default)]
struct UserLogEventVisitor {
    is_user_log_event: bool,
}

impl Visit for UserLogEventVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == USER_LOG_EVENT && value {
            self.is_user_log_event = true;
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == USER_LOG_EVENT && format!("{value:?}") == "true" {
            self.is_user_log_event = true;
        }
    }
}

/// Returns `true` if `metadata` describes a control-plane event.
pub(crate) fn is_control_plane_event(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.is_event()
        && (is_control_plane_target(metadata.target()) || metadata.target() == TRACING_PANIC_TARGET)
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
    let current = tracing::Span::current();
    if let Some(span) = exportable_or_active_span(&current) {
        let _selected_span = SelectedSpanGuard::new(span);
        tracing_panic::panic_hook(info);
        return;
    }

    // No exportable span is active. Create a short fallback span so the panic is still exported
    // somewhere useful.
    let span = tracing::error_span!(target: CONTROL_PLANE_TARGET, SPANLESS_PANIC_SPAN_NAME);
    let _guard = span.enter();
    let _selected_span = SelectedSpanGuard::new(span.clone());
    tracing_panic::panic_hook(info);
}

fn exportable_or_active_span(current: &tracing::Span) -> Option<tracing::Span> {
    if is_control_plane_span(current) {
        Some(current.clone())
    } else {
        active_span()
    }
}

fn is_control_plane_span(span: &tracing::Span) -> bool {
    !span.is_disabled()
        && span
            .metadata()
            .is_some_and(|metadata| is_control_plane_target(metadata.target()))
}

fn is_exportable_span(span: &tracing::Span) -> bool {
    if span.is_disabled() {
        return false;
    }

    span.metadata().is_some_and(|metadata| is_exportable_target(metadata.target()))
}

fn is_exportable_target(target: &str) -> bool {
    is_control_plane_target(target)
        || miden_node_tracing_targets::is_allowed_application_target(target)
}

/// Guard returned when a Miden span becomes the active enabled span on this thread.
#[derive(Debug)]
pub struct ActiveSpanGuard {
    span: Option<tracing::Span>,
}

impl ActiveSpanGuard {
    pub(crate) fn none() -> Self {
        Self { span: None }
    }
}

impl Drop for ActiveSpanGuard {
    fn drop(&mut self) {
        let Some(span) = self.span.take() else {
            return;
        };
        if let Some(id) = span.id() {
            pop_active_span(&id);
        }
    }
}

/// Tracks an enabled span as a panic fallback parent while it is entered.
pub(crate) fn enter_span(span: &tracing::Span) -> ActiveSpanGuard {
    if !is_exportable_span(span) || span.id().is_none() {
        return ActiveSpanGuard::none();
    }
    if duplicate_active_span(span) {
        ActiveSpanGuard { span: Some(span.clone()) }
    } else {
        ActiveSpanGuard::none()
    }
}

/// Tracks the current span when code is running inside an upstream `#[instrument]` span.
pub fn enter_current_span() -> ActiveSpanGuard {
    enter_span(&tracing::Span::current())
}

/// Tracks the current span as active only while `future` is being polled.
pub fn track_current_span<F>(future: F) -> ActiveSpanFuture<F> {
    ActiveSpanFuture { span: tracing::Span::current(), future }
}

/// Future wrapper which exposes an enabled span to panic fallback routing during each poll.
#[derive(Debug)]
pub struct ActiveSpanFuture<F> {
    span: tracing::Span,
    future: F,
}

impl<F> Future for ActiveSpanFuture<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        // SAFETY: `future` is pinned in place by `self`; this projection never moves it.
        let this = unsafe { self.get_unchecked_mut() };
        let _active_span = enter_span(&this.span);
        // SAFETY: see the projection note above.
        unsafe { Pin::new_unchecked(&mut this.future) }.poll(cx)
    }
}

fn active_span() -> Option<tracing::Span> {
    ACTIVE_SPANS.with(|active_spans| {
        active_spans
            .borrow()
            .iter()
            .rev()
            .find(|span| is_exportable_span(span))
            .cloned()
    })
}

fn push_active_span(span: tracing::Span) -> bool {
    if !is_exportable_span(&span) {
        return false;
    }

    ACTIVE_SPANS.with(|active_spans| {
        let mut active_spans = active_spans.borrow_mut();
        active_spans.push(span);
        true
    })
}

fn duplicate_active_span(span: &tracing::Span) -> bool {
    let Some(id) = span.id() else {
        return false;
    };

    ACTIVE_SPANS.with(|active_spans| {
        let mut active_spans = active_spans.borrow_mut();
        if active_spans.iter().any(|active_span| active_span.id().as_ref() == Some(&id)) {
            active_spans.push(span.clone());
            true
        } else {
            false
        }
    })
}

fn pop_active_span(id: &tracing::span::Id) {
    ACTIVE_SPANS.with(|active_spans| {
        let mut active_spans = active_spans.borrow_mut();
        if let Some(index) = active_spans
            .iter()
            .rposition(|active_span| active_span.id().as_ref() == Some(id))
        {
            active_spans.remove(index);
        }
    });
}

/// Mirrors a user-facing span attribute into a predeclared tracing field for local output.
pub(crate) fn record_user_field_bridge(span: &tracing::Span, key: &Key, value: &Value) {
    span.record(
        crate::user::FIELD_BRIDGE_KEY,
        tracing::field::display(crate::user::format_field(key.as_str(), &value.as_str())),
    );
}

#[derive(Default)]
struct ControlPlaneEventFields {
    is_panic: bool,
    panic_payload: Option<String>,
    panic_attributes: Vec<(Key, Value)>,
}

impl ControlPlaneEventFields {
    fn is_panic(&self) -> bool {
        self.is_panic
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

        let description = self
            .panic_payload
            .map_or_else(|| "panic".to_owned(), |payload| format!("panic: {payload}"));
        span.record("miden.error", tracing::field::display(&description));
        tracing_opentelemetry::OpenTelemetrySpanExt::set_status(
            &span,
            Status::Error { description: description.into() },
        );
    }

    /// Records a boolean event field relevant to control-plane panic handling.
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_panic_attribute(field.name(), value.into());
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
    /// `panic.payload` is retained separately so it can also become the span status description.
    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == field::PANIC_PAYLOAD {
            self.is_panic = true;
            self.panic_payload = Some(value.to_owned());
        }
        self.record_panic_attribute(name, value.to_owned().into());
    }

    /// Records a debug-formatted event field relevant to control-plane panic handling.
    ///
    /// This is the fallback visitor path for values without a more specific typed callback.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let value = format!("{value:?}");
        let name = field.name();
        if name == field::PANIC_PAYLOAD {
            self.is_panic = true;
            let value = clean_panic_payload_debug(&value);
            self.panic_payload = Some(value.clone());
            self.record_panic_attribute(name, value.into());
            return;
        }
        self.record_panic_attribute(name, value.into());
    }

    /// Stores a field as a panic span attribute when its key belongs to the panic schema.
    fn record_panic_attribute(&mut self, name: &'static str, value: Value) {
        if name.starts_with("panic.") {
            self.is_panic = true;
            self.panic_attributes.push((Key::from_static_str(name), value));
        }
    }
}

fn clean_panic_payload_debug(value: &str) -> String {
    if value == "None" {
        return "panic payload is not a string".to_owned();
    }

    value
        .strip_prefix("Some(")
        .and_then(|value| value.strip_suffix(')'))
        .and_then(|value| value.strip_prefix('"').and_then(|value| value.strip_suffix('"')))
        .unwrap_or(value)
        .to_owned()
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
    use std::future::{Future, pending};
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context as TaskContext, Poll, RawWaker, RawWakerVTable, Waker};

    use opentelemetry::Value;
    use opentelemetry::trace::Status;
    use opentelemetry_sdk::trace::SpanData;
    use tracing::field::{Field, Visit};
    use tracing::subscriber::with_default;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;

    use super::{
        ActiveSpanLayer,
        CONTROL_PLANE_TARGET,
        ControlPlaneEventFields,
        ControlPlaneEventLayer,
        IgnoreControlPlaneEvents,
        OnlyControlPlaneEvents,
        SelectedSpanGuard,
        TRACING_PANIC_TARGET,
        active_span,
        enter_span,
        exportable_or_active_span,
        track_current_span,
    };
    use crate::test_utils::{TestExporter, assert_attribute};

    #[test]
    fn control_plane_layer_records_panic_fields_on_current_span() {
        let spans = exported_spans_with_control_plane_layer(|| {
            let span = tracing::info_span!("panic_parent");
            let _guard = span.enter();
            let _selected_span = SelectedSpanGuard::new(span.clone());

            tracing::event!(
                target: TRACING_PANIC_TARGET,
                tracing::Level::ERROR,
                panic.payload = "test panic",
                panic.location = "src/lib.rs:42:7",
                "A panic occurred"
            );
        });
        let span = span_by_name(&spans, "panic_parent");

        assert_attribute(span, "panic.payload", "test panic");
        assert_attribute(span, "panic.location", "src/lib.rs:42:7");
        assert_eq!(span.status, Status::Error { description: "panic: test panic".into() });
        assert!(
            span.events.events.is_empty(),
            "raw control-plane events must not be exported: {:?}",
            span.events.events
        );
    }

    #[test]
    fn control_plane_layer_bridges_panic_status_to_tracing_error_field() {
        #[derive(Clone, Default)]
        struct ErrorRecordLayer {
            error: Arc<Mutex<Option<String>>>,
        }

        impl<S> Layer<S> for ErrorRecordLayer
        where
            S: tracing::Subscriber,
        {
            fn on_record(
                &self,
                _span: &tracing::span::Id,
                values: &tracing::span::Record<'_>,
                _ctx: Context<'_, S>,
            ) {
                let mut visitor = ErrorFieldVisitor::default();
                values.record(&mut visitor);
                if let Some(error) = visitor.error {
                    *self.error.lock().expect("error field lock poisoned") = Some(error);
                }
            }
        }

        #[derive(Default)]
        struct ErrorFieldVisitor {
            error: Option<String>,
        }

        impl Visit for ErrorFieldVisitor {
            fn record_str(&mut self, field: &Field, value: &str) {
                if field.name() == "miden.error" {
                    self.error = Some(value.to_owned());
                }
            }

            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "miden.error" {
                    self.error = Some(format!("{value:?}").trim_matches('"').to_owned());
                }
            }
        }

        let error_layer = ErrorRecordLayer::default();
        let captured = error_layer.error.clone();
        let subscriber = tracing_subscriber::registry()
            .with(ControlPlaneEventLayer.with_filter(OnlyControlPlaneEvents))
            .with(error_layer);

        with_default(subscriber, || {
            let span = tracing::info_span!(
                target: "rpc",
                "panic_parent",
                miden.error = tracing::field::Empty
            );
            let _guard = span.enter();
            let _selected_span = SelectedSpanGuard::new(span.clone());

            tracing::event!(
                target: TRACING_PANIC_TARGET,
                tracing::Level::ERROR,
                panic.payload = "panic visible to stdout",
                "A panic occurred"
            );
        });

        assert_eq!(
            captured.lock().expect("error field lock poisoned").as_deref(),
            Some("panic: panic visible to stdout")
        );
    }

    #[test]
    fn control_plane_event_filter_rejects_tracing_panic_events() {
        let spans = exported_spans_with_control_plane_layer(|| {
            let span = tracing::error_span!(target: CONTROL_PLANE_TARGET, "spanless_panic");
            let _guard = span.enter();
            let _selected_span = SelectedSpanGuard::new(span.clone());
            tracing::event!(
                target: TRACING_PANIC_TARGET,
                tracing::Level::ERROR,
                panic.payload = Some("test panic"),
                "A panic occurred"
            );
        });
        let span = span_by_name(&spans, "spanless_panic");

        assert_attribute(span, "panic.payload", "test panic");
        assert_eq!(span.status, Status::Error { description: "panic: test panic".into() });
        assert!(span.events.events.is_empty());
    }

    #[test]
    fn control_plane_layer_records_panic_on_active_parent_when_child_span_is_disabled() {
        let spans = exported_spans_with_filter("info", || {
            let root = tracing::info_span!(target: "rpc", "panic_root");
            let _root_guard = root.enter();
            let _active_root = enter_span(&root);

            let disabled_child = tracing::debug_span!(target: "rpc", "disabled_child");
            let _disabled_guard = disabled_child.enter();
            let selected = active_span().unwrap_or_else(tracing::Span::current);
            let _selected_span = SelectedSpanGuard::new(selected);

            tracing::event!(
                target: TRACING_PANIC_TARGET,
                tracing::Level::ERROR,
                panic.payload = "panic in disabled child",
                "A panic occurred"
            );
        });
        let span = span_by_name(&spans, "panic_root");

        assert_attribute(span, "panic.payload", "panic in disabled child");
        assert_eq!(
            span.status,
            Status::Error {
                description: "panic: panic in disabled child".into(),
            }
        );
        assert!(spans.iter().all(|span| span.name != "disabled_child"));
        assert!(spans.iter().all(|span| span.name != "spanless_panic"));
    }

    #[test]
    fn active_span_future_tracks_span_only_during_poll() {
        let root = tracing::info_span!(target: "rpc", "async_panic_root");
        let future = {
            let _guard = root.enter();
            track_current_span(pending::<()>())
        };

        assert!(active_span().is_none());

        let mut future = pin!(future);
        let waker = noop_waker();
        let mut cx = TaskContext::from_waker(&waker);
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        assert!(active_span().is_none());
    }

    #[test]
    fn active_span_layer_tracks_public_entered_span() {
        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let root = tracing::info_span!(target: "rpc", "layer_tracked_root");
            let expected_id = root.id();

            {
                let _guard = root.enter();
                let active_id = active_span().and_then(|span| span.id());
                assert_eq!(active_id, expected_id);
            }

            assert!(active_span().is_none());
        });
    }

    #[test]
    fn explicit_active_span_guard_does_not_pop_layer_tracked_span() {
        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let root = tracing::info_span!(target: "rpc", "layer_and_macro_tracked_root");
            let expected_id = root.id();
            let _span_guard = root.enter();

            {
                let _macro_guard = enter_span(&root);
            }

            let active_id = active_span().and_then(|span| span.id());
            assert_eq!(active_id, expected_id);
        });

        assert!(active_span().is_none());
    }

    #[test]
    fn active_span_selection_ignores_third_party_current_span() {
        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let third_party = tracing::info_span!(target: "tokio::runtime", "third_party_root");
            let _third_party_guard = third_party.enter();

            assert!(active_span().is_none());
            assert!(exportable_or_active_span(&tracing::Span::current()).is_none());
        });

        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let root = tracing::info_span!(target: "rpc", "exported_root");
            let expected_id = root.id();
            let _root_guard = root.enter();

            let third_party = tracing::info_span!(target: "tokio::runtime", "third_party_child");
            let _third_party_guard = third_party.enter();

            let active_id = active_span().and_then(|span| span.id());
            let selected_id =
                exportable_or_active_span(&tracing::Span::current()).and_then(|span| span.id());
            assert_eq!(active_id, expected_id);
            assert_eq!(selected_id, expected_id);
        });
    }

    #[test]
    fn active_span_layer_keeps_outer_enter_active_when_same_span_is_reentered() {
        let subscriber = tracing_subscriber::registry().with(ActiveSpanLayer);

        with_default(subscriber, || {
            let root = tracing::info_span!(target: "rpc", "nested_layer_tracked_root");
            let expected_id = root.id();
            let outer = root.enter();

            {
                let _inner = root.enter();
                let active_id = active_span().and_then(|span| span.id());
                assert_eq!(active_id, expected_id);
            }

            let active_id = active_span().and_then(|span| span.id());
            assert_eq!(active_id, expected_id);

            drop(outer);
            assert!(active_span().is_none());
        });
    }

    fn exported_spans_with_control_plane_layer(record: impl FnOnce()) -> Vec<SpanData> {
        exported_spans_with_filter("trace", record)
    }

    fn exported_spans_with_filter(filter: &str, record: impl FnOnce()) -> Vec<SpanData> {
        let exporter = TestExporter::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let tracer = opentelemetry::trace::TracerProvider::tracer(
            &provider,
            "miden-node-tracing-control-plane-test",
        );
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(filter))
            .with(ActiveSpanLayer)
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

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            noop_raw_waker()
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}

        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

        fn noop_raw_waker() -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        // SAFETY: the vtable functions do not dereference the null data pointer.
        unsafe { Waker::from_raw(noop_raw_waker()) }
    }

    #[test]
    fn u64_values_saturate_when_recorded_as_i64() {
        let mut fields = ControlPlaneEventFields::default();
        fields.record_panic_attribute("panic.value", Value::I64(super::u64_to_i64(u64::MAX)));

        assert_eq!(fields.panic_attributes[0].1, Value::I64(i64::MAX));
    }
}
