use std::fmt;

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Filter};

use super::control_plane::{is_control_plane_event, is_control_plane_target};

/// Field marker used for tracing events emitted only for local user-facing stdout.
pub(crate) const USER_LOG_EVENT: &str = "miden.user.log";

/// Per-layer filter which lets the control-plane layer read span scope and control-plane events.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ControlPlaneScope;

impl<S> Filter<S> for ControlPlaneScope {
    /// Returns `true` for spans that may appear in a control-plane event scope and for raw
    /// control-plane events.
    ///
    /// This lets `ControlPlaneEventLayer` choose the panic parent with
    /// `Context::event_scope` without treating ordinary application events as input.
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        metadata.is_span() || is_control_plane_event(metadata)
    }

    /// Enables span scope tracking and control-plane event delivery.
    ///
    /// Ordinary application events return `never`, so this layer does not keep them enabled when
    /// the exporters are off.
    fn callsite_enabled(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.is_span() || is_control_plane_event(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn event_enabled(&self, event: &tracing::Event<'_>, _ctx: &Context<'_, S>) -> bool {
        is_control_plane_event(event.metadata())
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
    WithControlPlaneEvents { inner: filter }
}

/// Per-layer filter which hides synthetic user-facing stdout events from normal trace export.
#[derive(Clone, Debug)]
pub(crate) struct WithoutUserLogEvents<F> {
    inner: F,
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
    WithoutUserLogEvents { inner: filter }
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
