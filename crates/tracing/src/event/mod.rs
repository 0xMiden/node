use std::borrow::Cow;

use opentelemetry::{Key, KeyValue, Value};

use crate::{OpenTelemetryField, OpenTelemetryObject, OpenTelemetryObjectRecorder};

/// Records typed attributes for a macro-created event.
#[derive(Debug, Default)]
pub struct OpenTelemetryEventRecorder {
    attributes: Vec<KeyValue>,
}

impl OpenTelemetryEventRecorder {
    /// Creates an empty event recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a raw event attribute.
    pub fn record_attribute(&mut self, key: impl Into<Key>, value: impl Into<Value>) {
        self.attributes.push(KeyValue::new(key, value));
    }

    /// Marks this event as appropriate for user-facing logs.
    ///
    /// This exists for the Miden event macros. The public marker is the macro-level `user`
    /// argument; this method keeps the concrete OpenTelemetry attribute name centralized here.
    #[doc(hidden)]
    pub fn __mark_user_facing(&mut self) {
        self.record_attribute(crate::user::ATTRIBUTE_KEY, true);
    }

    /// Records `field` using its default key.
    pub fn record_field<F>(&mut self, field: &F)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.record_field_as(field, F::DEFAULT_KEY);
    }

    /// Records `field` using `key` instead of its default key.
    pub fn record_field_as<F>(&mut self, field: &F, key: impl Into<Key>)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.attributes.push(KeyValue::new(key, field.to_otel_value()));
    }

    /// Records `object` using its default key prefix.
    pub fn record_object<O>(&mut self, object: &O)
    where
        O: OpenTelemetryObject + ?Sized,
    {
        self.record_object_as(object, O::DEFAULT_KEY_PREFIX);
    }

    /// Records `object` using `key_prefix` instead of its default key prefix.
    pub fn record_object_as<O>(&mut self, object: &O, key_prefix: &str)
    where
        O: OpenTelemetryObject + ?Sized,
    {
        let mut sink = EventAttributeSink { attributes: &mut self.attributes };
        let mut recorder = OpenTelemetryObjectRecorder::new(&mut sink, key_prefix);
        object.record_attributes(&mut recorder);
    }

    pub(crate) fn into_attributes(self) -> Vec<KeyValue> {
        self.attributes
    }
}

pub(crate) trait OpenTelemetryAttributeSink {
    fn record_attribute(&mut self, key: Key, value: Value);
}

pub(crate) struct SpanAttributeSink<'a> {
    pub(crate) span: &'a tracing::Span,
}

impl OpenTelemetryAttributeSink for SpanAttributeSink<'_> {
    fn record_attribute(&mut self, key: Key, value: Value) {
        tracing_opentelemetry::OpenTelemetrySpanExt::set_attribute(self.span, key, value);
    }
}

struct EventAttributeSink<'a> {
    attributes: &'a mut Vec<KeyValue>,
}

impl OpenTelemetryAttributeSink for EventAttributeSink<'_> {
    fn record_attribute(&mut self, key: Key, value: Value) {
        self.attributes.push(KeyValue::new(key, value));
    }
}

pub(crate) fn record_event_on_span(
    span: &tracing::Span,
    name: impl Into<Cow<'static, str>>,
    recorder: OpenTelemetryEventRecorder,
) {
    tracing_opentelemetry::OpenTelemetrySpanExt::add_event(span, name, recorder.into_attributes());
}

#[cfg(test)]
mod tests {
    use super::OpenTelemetryEventRecorder;
    use crate::test_utils::exported_spans;
    use crate::{
        OpenTelemetryField,
        OpenTelemetryObject,
        OpenTelemetryObjectRecorder,
        SpanLevel,
        TelemetryMetadata,
        registered_events,
        registered_user_facing_metadata,
    };

    struct TestField;

    impl OpenTelemetryField for TestField {
        const DEFAULT_KEY: &'static str = "field.default";
        const DEFAULT_KEY_SUFFIX: &'static str = "field";

        fn to_otel_value(&self) -> opentelemetry::Value {
            "value".into()
        }
    }

    struct TestObject;

    impl OpenTelemetryObject for TestObject {
        const DEFAULT_KEY_PREFIX: &'static str = "object";

        fn record_attributes(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
            recorder.record_field(&TestField);
        }
    }

    #[test]
    fn recorder_records_fields_and_objects() {
        let mut recorder = OpenTelemetryEventRecorder::new();

        recorder.record_field(&TestField);
        recorder.record_field_as(&TestField, "custom.field");
        recorder.record_object(&TestObject);
        recorder.record_object_as(&TestObject, "custom_object");

        let attributes = recorder.into_attributes();
        assert_attribute(&attributes, "field.default", "value");
        assert_attribute(&attributes, "custom.field", "value");
        assert_attribute(&attributes, "object.field", "value");
        assert_attribute(&attributes, "custom_object.field", "value");
    }

    #[test]
    fn event_macro_records_fields_and_objects() {
        let spans = exported_spans(|| {
            let span = tracing::info_span!("event_parent");
            let _guard = span.enter();

            crate::info!(
                target = rpc,
                user,
                field(TestField),
                field(custom.field = TestField),
                object(TestObject),
                object(custom = TestObject),
                "recorded {}",
                "event"
            );
            crate::info!(target = rpc, "internal event");
        });
        let span = spans
            .iter()
            .find(|span| span.name == "event_parent")
            .unwrap_or_else(|| panic!("missing event_parent span; spans: {spans:?}"));
        let event = span
            .events
            .events
            .iter()
            .find(|event| event.name == "recorded event")
            .unwrap_or_else(|| panic!("missing recorded event; events: {:?}", span.events.events));

        assert_attribute(&event.attributes, "level", "INFO");
        assert_attribute(&event.attributes, "target", "rpc");
        assert_attribute(&event.attributes, crate::user::ATTRIBUTE_KEY, true);
        assert_attribute(&event.attributes, "field.default", "value");
        assert_attribute(&event.attributes, "custom.field", "value");
        assert_attribute(&event.attributes, "object.field", "value");
        assert_registered_event("rpc", SpanLevel::Info, "recorded {}", true);
        assert_registered_event("rpc", SpanLevel::Info, "internal event", false);
        assert_registered_user_event("rpc", SpanLevel::Info, "recorded {}");
        assert_no_registered_user_event("internal event");
    }

    fn assert_registered_event(target: &str, level: SpanLevel, message: &str, user: bool) {
        assert!(
            registered_events().any(|event| event.target == target
                && event.level == level
                && event.message == message
                && event.user == user),
            "missing registered event {target} {level} {message}",
        );
    }

    fn assert_registered_user_event(target: &str, level: SpanLevel, message: &str) {
        assert!(
            registered_user_facing_metadata().any(|metadata| matches!(
                metadata,
                TelemetryMetadata::Event(event)
                    if event.target == target && event.level == level && event.message == message
            )),
            "missing registered user event {target} {level} {message}",
        );
    }

    fn assert_no_registered_user_event(message: &str) {
        assert!(
            !registered_user_facing_metadata().any(|metadata| matches!(
                metadata,
                TelemetryMetadata::Event(event) if event.message == message
            )),
            "unexpected registered user event {message}",
        );
    }

    fn assert_attribute(
        attributes: &[opentelemetry::KeyValue],
        key: &str,
        expected: impl Into<opentelemetry::Value>,
    ) {
        let actual = attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == key)
            .unwrap_or_else(|| panic!("missing attribute {key}; attributes: {attributes:?}"));

        assert_eq!(actual.value, expected.into());
    }
}
