use std::fmt;

use opentelemetry::trace::Status;
use opentelemetry::{Key, Value};
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::active_span::active_span_by_id;

/// Target used for tracing events that carry control-plane signals.
pub(crate) const CONTROL_PLANE_TARGET: &str = "miden_tracing::control_plane";

pub(super) const TRACING_PANIC_TARGET: &str = "tracing_panic";
const SPANLESS_PANIC_SPAN_NAME: &str = "spanless_panic";

/// Field names used by control-plane events.
pub(crate) mod field {
    /// Panic payload reported by `tracing-panic`.
    pub const PANIC_PAYLOAD: &str = "panic.payload";
}

/// Layer which consumes control-plane events.
///
/// The layer currently handles panic events by copying their `panic.*` fields onto the span
/// selected by the crate-owned emitter and marking the span status as failed. Raw control-plane
/// events should be filtered from normal output/export layers with `IgnoreControlPlaneEvents`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ControlPlaneEventLayer;

impl<S> Layer<S> for ControlPlaneEventLayer
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    /// Handles a control-plane event.
    ///
    /// Layers cannot consume events in `tracing`, so this layer translates only the reserved
    /// control-plane event and relies on sibling per-layer filters to keep the raw event away from
    /// stdout and OpenTelemetry exporters.
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        if !is_control_plane_event(event.metadata()) {
            return;
        }

        // Parse fields from the generic `tracing` event instead of depending on any callsite
        // layout. This keeps the plumbing reusable for future control-plane event kinds.
        let mut fields = ControlPlaneEventFields::default();
        event.record(&mut fields);

        if fields.is_panic() {
            if let Some(span) = panic_span(event, &ctx) {
                fields.record_panic_on_span(&span);
            } else {
                let span =
                    tracing::error_span!(target: CONTROL_PLANE_TARGET, SPANLESS_PANIC_SPAN_NAME);
                fields.record_panic_on_span(&span);
            }
        }
    }
}

fn panic_span<S>(event: &tracing::Event<'_>, ctx: &Context<'_, S>) -> Option<tracing::Span>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    ctx.event_scope(event)?
        .filter(|span| is_exportable_target(span.metadata().target()))
        .find_map(|span| active_span_by_id(&span.id()))
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

pub(crate) fn is_exportable_target(target: &str) -> bool {
    is_control_plane_target(target)
        || miden_node_tracing_targets::is_allowed_application_target(target)
}

#[derive(Default)]
pub(super) struct ControlPlaneEventFields {
    is_panic: bool,
    panic_payload: Option<String>,
    pub(super) panic_attributes: Vec<(Key, Value)>,
}

impl ControlPlaneEventFields {
    fn is_panic(&self) -> bool {
        self.is_panic
    }

    fn record_panic_on_span(&mut self, span: &tracing::Span) {
        if span.is_disabled() {
            return;
        }

        // Preserve the field names from the control-plane event as OpenTelemetry span attributes.
        // The raw event itself is filtered from exporters, so these attributes are the
        // exported signal.
        for (key, value) in self.panic_attributes.drain(..) {
            tracing_opentelemetry::OpenTelemetrySpanExt::set_attribute(span, key, value);
        }

        let description = self
            .panic_payload
            .take()
            .map_or_else(|| "panic".to_owned(), |payload| format!("panic: {payload}"));
        span.record("miden.error", tracing::field::display(&description));
        tracing_opentelemetry::OpenTelemetrySpanExt::set_status(
            span,
            Status::Error { description: description.into() },
        );
    }

    /// Stores a field as a panic span attribute when its key belongs to the panic schema.
    pub(super) fn record_panic_attribute(&mut self, name: &'static str, value: Value) {
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
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_panic_attribute(field.name(), value.into());
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
        if name == field::PANIC_PAYLOAD {
            self.is_panic = true;
            self.panic_payload = Some(value.to_owned());
        }
        self.record_panic_attribute(name, value.to_owned().into());
    }

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
}

/// Converts a `u64` into the closest OpenTelemetry integer representation.
///
/// `opentelemetry::Value` only supports signed 64-bit integers, so values above `i64::MAX` are
/// saturated to preserve monotonicity without panicking from the panic path.
pub(super) fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
