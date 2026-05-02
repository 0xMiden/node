use std::panic::PanicHookInfo;

use super::active_span::active_span;
use super::control_plane::{CONTROL_PLANE_TARGET, SelectedSpanGuard, is_control_plane_target};

const SPANLESS_PANIC_SPAN_NAME: &str = "spanless_panic";

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

pub(super) fn exportable_or_active_span(current: &tracing::Span) -> Option<tracing::Span> {
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
