use std::borrow::Cow;
use std::cell::RefCell;

use opentelemetry::{Key, KeyValue, Value};

use crate::span::Span;
use crate::{OpenTelemetryField, OpenTelemetryObject, OpenTelemetryObjectRecorder};

/// A macro-created event with Miden OpenTelemetry recording helpers.
///
/// Events are emitted when this value is dropped. Using an event macro as a standalone statement
/// therefore emits immediately, while binding the returned value lets callers record typed
/// attributes first.
#[derive(Debug)]
pub struct Event {
    span: Option<Span>,
    name: Option<Cow<'static, str>>,
    recorder: RefCell<Option<OpenTelemetryEventRecorder>>,
    user_log_emitter: Option<fn(&str, &[KeyValue])>,
}

impl Event {
    /// Creates an enabled event wrapper.
    ///
    /// This exists for the Miden event macros. Create events with `event!`, `trace!`, `debug!`,
    /// `info!`, `warn!`, or `error!` so target validation and metadata registration are applied
    /// consistently.
    #[doc(hidden)]
    pub fn __new(
        span: Span,
        name: impl Into<Cow<'static, str>>,
        recorder: OpenTelemetryEventRecorder,
        user_log_emitter: Option<fn(&str, &[KeyValue])>,
    ) -> Self {
        Self {
            span: Some(span),
            name: Some(name.into()),
            recorder: RefCell::new(Some(recorder)),
            user_log_emitter,
        }
    }

    /// Creates a disabled event wrapper.
    ///
    /// This exists for the event macros when tracing filters reject the target or level. Recording
    /// methods become no-ops, so callers can use the same code path for enabled and disabled
    /// events.
    #[doc(hidden)]
    pub fn __disabled() -> Self {
        Self {
            span: None,
            name: None,
            recorder: RefCell::new(None),
            user_log_emitter: None,
        }
    }

    /// Records `field` using its default key.
    pub fn record_field<F>(&self, field: &F)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.with_recorder(|recorder| recorder.record_field(field));
    }

    /// Records `field` using `key` instead of its default key.
    pub fn record_field_as<F>(&self, field: &F, key: impl Into<Key>)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.with_recorder(|recorder| recorder.record_field_as(field, key));
    }

    /// Records `field` as both an OpenTelemetry attribute and a user-facing log field.
    ///
    /// User-facing fields are explicitly selected to keep local stdout logs focused. The stored
    /// attribute key is prefixed so exporters can strip the marker prefix for display while still
    /// distinguishing these fields from trace-only attributes.
    pub fn record_user_field<F>(&self, field: &F)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.with_recorder(|recorder| recorder.record_user_field(field));
    }

    /// Records `field` as a user-facing log field using `key` instead of its default key.
    pub fn record_user_field_as<F>(&self, field: &F, key: impl Into<Key>)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.with_recorder(|recorder| recorder.record_user_field_as(field, key));
    }

    /// Records `object` using its default key prefix.
    pub fn record_object<O>(&self, object: &O)
    where
        O: OpenTelemetryObject + ?Sized,
    {
        self.with_recorder(|recorder| recorder.record_object(object));
    }

    /// Records `object` using `key_prefix` instead of its default key prefix.
    pub fn record_object_as<O>(&self, object: &O, key_prefix: &str)
    where
        O: OpenTelemetryObject + ?Sized,
    {
        self.with_recorder(|recorder| recorder.record_object_as(object, key_prefix));
    }

    /// Emits this event immediately.
    ///
    /// Calling this is optional because events also emit on drop. Use it when the exact emission
    /// point matters after recording attributes.
    pub fn emit(mut self) {
        self.emit_inner();
    }

    fn with_recorder(&self, record: impl FnOnce(&mut OpenTelemetryEventRecorder)) {
        let mut recorder = self.recorder.borrow_mut();
        if let Some(recorder) = recorder.as_mut() {
            record(recorder);
        }
    }

    fn emit_inner(&mut self) {
        let Some(span) = self.span.take() else {
            return;
        };
        let Some(name) = self.name.take() else {
            return;
        };
        let Some(recorder) = self.recorder.get_mut().take() else {
            return;
        };
        let attributes = recorder.into_attributes();

        span.__record_event(name.clone(), attributes.clone());
        if let Some(emit_user_log) = self.user_log_emitter.take() {
            emit_user_log(&name, &attributes);
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        self.emit_inner();
    }
}

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

    /// Records `field` as both an OpenTelemetry attribute and a user-facing log field.
    pub fn record_user_field<F>(&mut self, field: &F)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.record_user_field_as(field, F::DEFAULT_KEY);
    }

    /// Records `field` as a user-facing log field using `key` instead of its default key.
    pub fn record_user_field_as<F>(&mut self, field: &F, key: impl Into<Key>)
    where
        F: OpenTelemetryField + ?Sized,
    {
        self.record_field_as(field, crate::user::field_key(key));
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
    attributes: Vec<KeyValue>,
) {
    tracing_opentelemetry::OpenTelemetrySpanExt::add_event(span, name, attributes);
}

#[doc(hidden)]
pub fn format_user_attributes(attributes: &[KeyValue]) -> String {
    let mut rendered = String::new();

    for attribute in attributes {
        let Some(key) = attribute.key.as_str().strip_prefix(crate::user::FIELD_PREFIX) else {
            continue;
        };
        rendered.push_str(&crate::user::format_field(key, &attribute.value.as_str()));
    }

    rendered
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
        recorder.record_user_field(&TestField);
        recorder.record_user_field_as(&TestField, "custom_user.field");
        recorder.record_object(&TestObject);
        recorder.record_object_as(&TestObject, "custom_object");

        let attributes = recorder.into_attributes();
        assert_attribute(&attributes, "field.default", "value");
        assert_attribute(&attributes, "custom.field", "value");
        assert_attribute(&attributes, "miden.user.field.default", "value");
        assert_attribute(&attributes, "miden.user.custom_user.field", "value");
        assert_attribute(&attributes, "object.field", "value");
        assert_attribute(&attributes, "custom_object.field", "value");
    }

    #[test]
    fn event_macro_returns_recordable_event() {
        let spans = exported_spans(|| {
            let span = tracing::info_span!("event_parent");
            let _guard = span.enter();

            let event = crate::info!(
                rpc,
                "recorded event",
                user,
                justification = "tests event attribute recording"
            );
            event.record_field(&TestField);
            event.record_field_as(&TestField, "custom.field");
            event.record_user_field(&TestField);
            event.record_user_field_as(&TestField, "custom_user.field");
            event.record_object(&TestObject);
            event.record_object_as(&TestObject, "custom_object");
            event.emit();

            crate::info!(
                rpc,
                "internal event",
                justification = "tests non-user event metadata registration"
            );
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
        assert_attribute(&event.attributes, "miden.user.field.default", "value");
        assert_attribute(&event.attributes, "miden.user.custom_user.field", "value");
        assert_attribute(&event.attributes, "object.field", "value");
        assert_attribute(&event.attributes, "custom_object.field", "value");
        assert_registered_event("rpc", SpanLevel::Info, "recorded event", true);
        assert_registered_event("rpc", SpanLevel::Info, "internal event", false);
        assert_registered_user_event("rpc", SpanLevel::Info, "recorded event");
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
