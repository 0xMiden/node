use opentelemetry::{Key, Value};

/// Mirrors a user-facing span attribute into a predeclared tracing field for local output.
pub(crate) fn record_user_field_bridge(span: &tracing::Span, key: &Key, value: &Value) {
    span.record(
        crate::user::FIELD_BRIDGE_KEY,
        tracing::field::display(crate::user::format_field(key.as_str(), &value.as_str())),
    );
}
