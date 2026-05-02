use std::fmt;

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Filter};

use super::control_plane::{is_control_plane_event, is_control_plane_target};

/// Field marker used for tracing events emitted only for local user-facing stdout.
pub(crate) const USER_LOG_EVENT: &str = "miden.user.log";

/// Per-layer filter which hides raw control-plane events from normal output/export layers.
///
/// This rejects events on the reserved control-plane target. Other records on the control-plane
/// target, such as the `spanless_panic` fallback span, remain visible to the wrapped layer.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct IgnoreControlPlaneEvents;

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
    /// This is paired with `ControlPlaneEventLayer` so that the control-plane layer does not keep
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
