mod error;

use std::error::Error;

use opentelemetry::Key;
use opentelemetry::trace::Status;

use crate::event::{OpenTelemetryEventRecorder, SpanAttributeSink, record_event_on_span};
use crate::{OpenTelemetryField, OpenTelemetryObject, OpenTelemetryObjectRecorder};

/// A tracing span with Miden OpenTelemetry recording helpers.
#[derive(Clone, Debug)]
pub struct Span(tracing::Span);

impl Span {
    /// Creates a new wrapper around `span`.
    ///
    /// This exists for the Miden tracing macros. Create spans with `trace_span!`, `debug_span!`,
    /// `info_span!`, `warn_span!`, or `error_span!` so target/name validation and metadata
    /// registration are applied consistently.
    #[doc(hidden)]
    pub fn __from_tracing_span(span: tracing::Span) -> Self {
        Self(span)
    }

    /// Returns a wrapper around the current tracing span.
    pub fn current() -> Self {
        Self(tracing::Span::current())
    }

    /// Returns the wrapped tracing span.
    #[cfg(test)]
    pub(crate) fn as_tracing_span(&self) -> &tracing::Span {
        &self.0
    }

    /// Marks this span as appropriate for user-facing logs.
    ///
    /// This exists for the Miden span and instrument macros. User-log support is opt-in so
    /// high-volume internal tracing spans do not leak into local stdout output.
    #[doc(hidden)]
    pub fn __mark_user_facing(&self) {
        tracing_opentelemetry::OpenTelemetrySpanExt::set_attribute(
            &self.0,
            crate::user::ATTRIBUTE_KEY,
            true,
        );
    }

    /// Enters this span for the current scope.
    pub fn enter(&self) -> tracing::span::Entered<'_> {
        self.0.enter()
    }

    /// Enters this span, consuming it and returning a guard that exits the span on drop.
    pub fn entered(self) -> tracing::span::EnteredSpan {
        self.0.entered()
    }

    /// Executes `f` in the context of this span.
    pub fn in_scope<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        self.0.in_scope(f)
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
        let mut sink = SpanAttributeSink { span: &self.0 };
        let mut recorder = OpenTelemetryObjectRecorder::new(&mut sink, key_prefix);
        object.record_attributes(&mut recorder);
    }

    /// Records an event on this span.
    ///
    /// This exists for the Miden event macros. Emit events with `event!`, `trace!`, `debug!`,
    /// `info!`, `warn!`, or `error!` so target validation and typed record handling are applied.
    #[doc(hidden)]
    pub fn __record_event(
        &self,
        name: impl Into<std::borrow::Cow<'static, str>>,
        recorder: OpenTelemetryEventRecorder,
    ) {
        record_event_on_span(&self.0, name, recorder);
    }

    /// Records `error` on this span by setting the span status to error.
    ///
    /// This exists for the Miden `instrument` macro, which records returned errors automatically.
    #[doc(hidden)]
    pub fn __record_error<E>(&self, error: &E)
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt;

    use opentelemetry::trace::Status;

    use super::Span;
    use crate::test_utils::{assert_attribute, exported_span, exported_spans};
    use crate::{
        OpenTelemetryField,
        OpenTelemetryObject,
        OpenTelemetryObjectRecorder,
        SpanLevel,
        registered_spans,
    };

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

        fn record_attributes(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
            recorder.record_field(&TestField);
        }
    }

    struct TestObject;

    impl OpenTelemetryObject for TestObject {
        const DEFAULT_KEY_PREFIX: &'static str = "test";

        fn record_attributes(&self, recorder: &mut OpenTelemetryObjectRecorder<'_>) {
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

    /// Exercises error status recording for instrumented functions.
    #[crate::instrument(target = rpc, name = "instrumented_error")]
    fn instrumented_error(value: u32) -> Result<(), TestError> {
        let _ = value;
        Err(TestError { source: SourceError })
    }

    #[crate::instrument(target = rpc, name = "instrumented_ok")]
    fn instrumented_ok(value: u32) -> Result<(), TestError> {
        let _ = value;
        Ok(())
    }

    #[crate::instrument(target = rpc, name = "instrumented_user", user)]
    fn instrumented_user() -> Result<(), TestError> {
        Ok(())
    }

    #[crate::instrument(target = store::database, name = "instrumented_async_error")]
    async fn instrumented_async_error(value: u32) -> Result<(), TestError> {
        let _ = value;
        Err(TestError { source: SourceError })
    }

    #[allow(dead_code)]
    fn unused_manual_span_declaration() {
        let _span = crate::error_span!(target = rpc, "unused_manual_span");
    }

    struct InstrumentedMethod;

    impl InstrumentedMethod {
        /// Uses the method name as the default span name.
        #[crate::instrument(target = rpc, level = debug)]
        fn method_with_default_name(&self) -> Result<(), TestError> {
            Ok(())
        }
    }

    trait InstrumentedTrait {
        fn trait_method_with_default_name(&self) -> Result<(), TestError>;
    }

    impl InstrumentedTrait for InstrumentedMethod {
        /// Uses the trait method name as the default span name.
        ///
        /// This also verifies trait impl methods.
        #[crate::instrument(target = rpc, level = trace)]
        fn trait_method_with_default_name(&self) -> Result<(), TestError> {
            Ok(())
        }
    }

    #[test]
    fn span_records_error_status() {
        let error = TestError { source: SourceError };
        let span = exported_span(|span| span.__record_error(&error));

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

    #[test]
    fn span_macro_creates_recordable_span() {
        let spans = exported_spans(|| {
            let span = crate::info_span!(target = rpc, "manual_span");
            span.record_field(&TestField);
            let _guard = span.entered();
        });
        let span = exported_span_by_name(&spans, "manual_span");

        assert_attribute(span, "test.field", "value");
    }

    #[test]
    fn span_macro_registers_metadata() {
        let _span = crate::warn_span!(target = store::database, "manual_metadata_span", user);

        assert_registered_span("store::database", SpanLevel::Warn, "manual_metadata_span");
        assert_span_user_marker("manual_metadata_span", true);
    }

    #[test]
    fn instrument_macro_registers_metadata() {
        let method = InstrumentedMethod;
        method.method_with_default_name().unwrap();
        method.trait_method_with_default_name().unwrap();
        instrumented_user().unwrap();

        assert_registered_span("rpc", SpanLevel::Info, "instrumented_error");
        assert_registered_span("rpc", SpanLevel::Info, "instrumented_user");
        assert_registered_span("store::database", SpanLevel::Info, "instrumented_async_error");
        assert_registered_span("rpc", SpanLevel::Debug, "method_with_default_name");
        assert_registered_span("rpc", SpanLevel::Trace, "trait_method_with_default_name");
        assert_registered_span("rpc", SpanLevel::Error, "unused_manual_span");
        assert_span_description(
            "instrumented_error",
            Some("Exercises error status recording for instrumented functions."),
        );
        assert_span_description(
            "method_with_default_name",
            Some("Uses the method name as the default span name."),
        );
        assert_span_description(
            "trait_method_with_default_name",
            Some(
                "Uses the trait method name as the default span name.\n\nThis also verifies trait \
                 impl methods.",
            ),
        );
        assert_span_description("unused_manual_span", None);
        assert_span_user_marker("instrumented_user", true);
        assert_span_user_marker("instrumented_error", false);
    }

    #[test]
    fn instrument_macro_records_returned_errors() {
        let spans = exported_spans(|| {
            let result = instrumented_error(42);
            assert!(result.is_err());
        });
        let span = exported_span_by_name(&spans, "instrumented_error");

        assert_eq!(
            span.status,
            Status::Error {
                description: "parent error\ncaused by: source error".into(),
            }
        );
        assert!(!span.attributes.iter().any(|attribute| attribute.key.as_str() == "value"));
        assert!(!span.attributes.iter().any(|attribute| attribute.key.as_str() == "error.type"));
        assert!(span.events.events.is_empty());
    }

    #[test]
    fn instrument_macro_leaves_success_status_unset() {
        let spans = exported_spans(|| {
            let result = instrumented_ok(42);
            assert!(result.is_ok());
        });
        let span = exported_span_by_name(&spans, "instrumented_ok");

        assert_eq!(span.status, Status::Unset);
        assert!(!span.attributes.iter().any(|attribute| attribute.key.as_str() == "value"));
        assert!(span.events.events.is_empty());
    }

    #[test]
    fn span_macro_marks_user_facing_span() {
        let spans = exported_spans(|| {
            let span = crate::info_span!(target = rpc, "manual_user_span", user);
            let _guard = span.entered();
        });
        let span = exported_span_by_name(&spans, "manual_user_span");

        assert_attribute(span, crate::user::ATTRIBUTE_KEY, true);
    }

    #[test]
    fn instrument_macro_marks_user_facing_span() {
        let spans = exported_spans(|| instrumented_user().unwrap());
        let span = exported_span_by_name(&spans, "instrumented_user");

        assert_attribute(span, crate::user::ATTRIBUTE_KEY, true);
    }

    fn exported_span_by_name<'a>(
        spans: &'a [opentelemetry_sdk::trace::SpanData],
        name: &str,
    ) -> &'a opentelemetry_sdk::trace::SpanData {
        spans
            .iter()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("missing span {name}; spans: {spans:?}"))
    }

    fn assert_registered_span(target: &str, level: SpanLevel, name: &str) {
        assert!(
            registered_spans()
                .any(|span| span.target == target && span.level == level && span.name == name),
            "missing registered span {target} {level} {name}"
        );
    }

    fn assert_span_description(name: &str, description: Option<&str>) {
        let span = registered_spans()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("missing registered span {name}"));

        assert_eq!(span.description, description);
    }

    fn assert_span_user_marker(name: &str, user: bool) {
        let span = registered_spans()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("missing registered span {name}"));

        assert_eq!(span.user, user);
    }
}
