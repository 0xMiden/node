mod block;

use std::borrow::Cow;

use opentelemetry::Key;

use crate::OpenTelemetryField;
use crate::event::OpenTelemetryAttributeSink;

/// An object that can record a set of OpenTelemetry attributes with a common key prefix.
pub trait OpenTelemetryObject {
    /// The default OpenTelemetry attribute key prefix for this object.
    const DEFAULT_KEY_PREFIX: &'static str;

    /// Records this object's OpenTelemetry fields onto `recorder`.
    fn record_otel_fields(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>);
}

/// Records OpenTelemetry fields and nested objects under a common key prefix.
pub struct OpenTelemetryObjectRecorder<'a> {
    sink: &'a mut dyn OpenTelemetryAttributeSink,
    key_prefix: Cow<'a, str>,
}

impl<'a> OpenTelemetryObjectRecorder<'a> {
    /// Creates a recorder that writes attributes to `sink` under `key_prefix`.
    pub(crate) fn new(
        sink: &'a mut dyn OpenTelemetryAttributeSink,
        key_prefix: impl Into<Cow<'a, str>>,
    ) -> Self {
        Self { sink, key_prefix: key_prefix.into() }
    }

    /// Records `field` using this recorder's key prefix and the field's default key suffix.
    pub fn record_field<F>(&mut self, field: &F)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.sink.record_attribute(
            join_key(self.key_prefix.as_ref(), F::DEFAULT_KEY_SUFFIX),
            field.to_otel_value(),
        );
    }

    /// Records `object` using this recorder's key prefix and the object's default key prefix.
    pub fn record_object<O>(&mut self, object: &O)
    where
        O: OpenTelemetryObject + ?Sized,
    {
        let key_prefix = join_key_parts(self.key_prefix.as_ref(), O::DEFAULT_KEY_PREFIX);
        let mut recorder = OpenTelemetryObjectRecorder::new(self.sink, Cow::Owned(key_prefix));
        object.record_otel_fields(&mut recorder);
    }
}

fn join_key(prefix: &str, suffix: &str) -> Key {
    Key::new(join_key_parts(prefix, suffix))
}

fn join_key_parts(prefix: &str, suffix: &str) -> String {
    match (prefix.is_empty(), suffix.is_empty()) {
        (true, true) => String::new(),
        (true, false) => suffix.to_owned(),
        (false, true) => prefix.to_owned(),
        (false, false) => format!("{prefix}.{suffix}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenTelemetryObject, OpenTelemetryObjectRecorder};
    use crate::OpenTelemetryField;
    use crate::event::SpanAttributeSink;
    use crate::test_utils::{assert_attribute, exported_span};

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
    fn recorder_records_prefixed_fields_and_nested_objects() {
        let span = exported_span(|span| {
            let mut sink = SpanAttributeSink { span: span.as_tracing_span() };
            let mut recorder = OpenTelemetryObjectRecorder::new(&mut sink, "root");
            recorder.record_field(&TestField);
            recorder.record_object(&TestObject);
        });

        assert_attribute(&span, "root.field", "value");
        assert_attribute(&span, "root.test.field", "value");
        assert_attribute(&span, "root.test.nested.field", "value");
    }
}
