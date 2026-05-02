use std::cell::RefCell;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::control_plane::is_control_plane_target;

thread_local! {
    static ACTIVE_SPANS: RefCell<Vec<tracing::Span>> = const { RefCell::new(Vec::new()) };
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

pub(super) fn active_span() -> Option<tracing::Span> {
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
