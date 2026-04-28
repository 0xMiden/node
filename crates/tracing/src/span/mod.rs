mod error;

use std::error::Error;

use opentelemetry::Key;
use opentelemetry::trace::Status;

use crate::{OpenTelemetryField, OpenTelemetryObject, OpenTelemetryObjectRecorder};

/// A tracing span with Miden OpenTelemetry recording helpers.
#[derive(Clone, Debug)]
pub struct Span(tracing::Span);

impl Span {
    /// Creates a new wrapper around `span`.
    pub fn new(span: tracing::Span) -> Self {
        Self(span)
    }

    /// Returns a wrapper around the current tracing span.
    pub fn current() -> Self {
        Self(tracing::Span::current())
    }

    /// Returns the wrapped tracing span.
    pub fn as_tracing_span(&self) -> &tracing::Span {
        &self.0
    }

    /// Consumes this wrapper and returns the wrapped tracing span.
    pub fn into_tracing_span(self) -> tracing::Span {
        self.0
    }

    /// Records `field` using its default key.
    pub fn record_field<F>(&self, field: &F)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.record_field_as(field, F::DEFAULT_KEY);
    }

    /// Records `field` using `key` instead of its default key.
    pub fn record_field_as<F>(&self, field: &F, key: impl Into<Key>)
    where
        F: OpenTelemetryField + ?Sized,
    {
        tracing_opentelemetry::OpenTelemetrySpanExt::set_attribute(
            &self.0,
            key,
            field.to_otel_value(),
        );
    }

    /// Records `object` using its default key prefix.
    pub fn record_object<O>(&self, object: &O)
    where
        O: OpenTelemetryObject + ?Sized,
    {
        self.record_object_as(object, O::DEFAULT_KEY_PREFIX);
    }

    /// Records `object` using `key_prefix` instead of its default key prefix.
    pub fn record_object_as<O>(&self, object: &O, key_prefix: &str)
    where
        O: OpenTelemetryObject + ?Sized,
    {
        let mut recorder = OpenTelemetryObjectRecorder::new(&self.0, key_prefix);
        object.record_otel_fields(&mut recorder);
    }

    /// Records `error` on this span by setting the span status to error.
    pub fn record_error<E>(&self, error: &E)
    where
        E: Error + ?Sized,
    {
        tracing_opentelemetry::OpenTelemetrySpanExt::set_status(
            &self.0,
            Status::Error {
                description: error::error_report(error).into(),
            },
        );
    }
}

impl From<tracing::Span> for Span {
    fn from(span: tracing::Span) -> Self {
        Self::new(span)
    }
}

impl AsRef<tracing::Span> for Span {
    fn as_ref(&self) -> &tracing::Span {
        self.as_tracing_span()
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt;

    use opentelemetry::trace::Status;

    use super::Span;
    use crate::test_utils::{assert_attribute, exported_span};
    use crate::{OpenTelemetryField, OpenTelemetryObject, OpenTelemetryObjectRecorder};

    struct TestField;

    impl OpenTelemetryField for TestField {
        const DEFAULT_KEY: &'static str = "test.field";
        const DEFAULT_KEY_SUFFIX: &'static str = "field";

        fn to_otel_value(&self) -> opentelemetry::Value {
            "value".into()
        }
    }

    struct NestedObject;

    impl OpenTelemetryObject for NestedObject {
        const DEFAULT_KEY_PREFIX: &'static str = "nested";

        fn record_otel_fields(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
            recorder.record_field(&TestField);
        }
    }

    struct TestObject;

    impl OpenTelemetryObject for TestObject {
        const DEFAULT_KEY_PREFIX: &'static str = "test";

        fn record_otel_fields(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
            recorder.record_field(&TestField);
            recorder.record_object(&NestedObject);
        }
    }

    #[test]
    fn span_records_fields_with_default_and_override_keys() {
        let span = exported_span(|span| {
            span.record_field(&TestField);
            span.record_field_as(&TestField, "custom.field");
        });

        assert_attribute(&span, "test.field", "value");
        assert_attribute(&span, "custom.field", "value");
    }

    #[test]
    fn span_records_objects_with_default_and_override_prefixes() {
        let span = exported_span(|span| {
            span.record_object(&TestObject);
            span.record_object_as(&TestObject, "custom");
        });

        assert_attribute(&span, "test.field", "value");
        assert_attribute(&span, "test.nested.field", "value");
        assert_attribute(&span, "custom.field", "value");
        assert_attribute(&span, "custom.nested.field", "value");
    }

    #[derive(Debug)]
    struct SourceError;

    impl fmt::Display for SourceError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("source error")
        }
    }

    impl Error for SourceError {}

    #[derive(Debug)]
    struct TestError {
        source: SourceError,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("parent error")
        }
    }

    impl Error for TestError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.source)
        }
    }

    #[test]
    fn span_records_error_status() {
        let error = TestError { source: SourceError };
        let span = exported_span(|span| span.record_error(&error));

        assert_eq!(
            span.status,
            Status::Error {
                description: "parent error\ncaused by: source error".into(),
            }
        );
        assert!(!span.attributes.iter().any(|attribute| attribute.key.as_str() == "error.type"));
        assert!(span.events.events.is_empty());
    }

    #[test]
    fn span_wraps_current_tracing_span() {
        let span = exported_span(|_| Span::current().record_field(&TestField));

        assert_attribute(&span, "test.field", "value");
    }
}
