mod protocol;

use opentelemetry::Value;

/// A value that can be recorded as an OpenTelemetry attribute.
pub trait OpenTelemetryField {
    /// The default OpenTelemetry attribute key for this field when recorded directly on a span.
    const DEFAULT_KEY: &'static str;

    /// The default OpenTelemetry attribute key suffix for this field when recorded as part of an
    /// object.
    const DEFAULT_KEY_SUFFIX: &'static str = Self::DEFAULT_KEY;

    /// Converts this object into an OpenTelemetry attribute value.
    fn to_otel_value(&self) -> Value;
}
