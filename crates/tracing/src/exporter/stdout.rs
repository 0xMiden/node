use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

pub(super) fn layer() -> UserFacingStdoutLayer {
    UserFacingStdoutLayer::stdout()
}

/// Writes user-facing spans and events as compact stdout log lines from tracing data.
#[derive(Clone)]
pub(crate) struct UserFacingStdoutLayer {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl UserFacingStdoutLayer {
    pub(crate) fn stdout() -> Self {
        Self::new(std::io::stdout())
    }

    pub(crate) fn new(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Arc::new(Mutex::new(Box::new(writer))),
        }
    }

    fn write_line(&self, line: impl fmt::Display) {
        let Ok(mut writer) = self.writer.lock() else {
            eprintln!("failed to write user-facing stdout log: writer lock poisoned");
            return;
        };
        if let Err(error) = writeln!(writer, "{line}") {
            eprintln!("failed to write user-facing stdout log: {error}");
        } else if let Err(error) = writer.flush() {
            eprintln!("failed to flush user-facing stdout log: {error}");
        }
    }
}

impl fmt::Debug for UserFacingStdoutLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserFacingStdoutLayer").finish_non_exhaustive()
    }
}

impl<S> Layer<S> for UserFacingStdoutLayer
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        span.extensions_mut().insert(UserSpanLog {
            name: attrs.metadata().name().to_owned(),
            started_at: Instant::now(),
            user: false,
            fields: Vec::new(),
            error: None,
        });
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
        let mut extensions = span.extensions_mut();
        let Some(log) = extensions.get_mut::<UserSpanLog>() else {
            return;
        };

        let mut visitor = UserLogVisitor::default();
        values.record(&mut visitor);
        log.apply(visitor);
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let Some(log) = span.extensions_mut().remove::<UserSpanLog>() else {
            return;
        };
        if !log.user {
            return;
        }

        self.write_line(log.format_closed());
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = UserLogVisitor::default();
        event.record(&mut visitor);
        if !visitor.user_log_event {
            return;
        }

        let level = event.metadata().level().as_str();
        let message = visitor.message.unwrap_or_else(|| event.metadata().name().to_owned());
        let fields = format_field_suffix(&visitor.fields);
        self.write_line(format!("{level} {message}{fields}"));
    }
}

#[derive(Debug)]
struct UserSpanLog {
    name: String,
    started_at: Instant,
    user: bool,
    fields: Vec<UserField>,
    error: Option<String>,
}

impl UserSpanLog {
    fn apply(&mut self, visitor: UserLogVisitor) {
        self.user |= visitor.user;
        for field in visitor.fields {
            self.record_field(field);
        }
        if visitor.error.is_some() {
            self.error = visitor.error;
        }
    }

    fn record_field(&mut self, field: String) {
        let parsed = UserField::parse(field);
        if let Some(existing) = self.fields.iter_mut().find(|field| field.key == parsed.key) {
            *existing = parsed;
        } else {
            self.fields.push(parsed);
        }
    }

    fn format_closed(self) -> String {
        let duration = self.started_at.elapsed();
        let fields = self.fields.into_iter().map(|field| field.rendered).collect::<Vec<_>>();
        let fields = format_field_suffix(&fields);
        let duration = format_duration_suffix(duration);

        if let Some(error) = self.error {
            format!("ERROR {} failed: {error}{duration}{fields}", self.name)
        } else {
            format!("INFO {} completed{duration}{fields}", self.name)
        }
    }
}

#[derive(Debug)]
struct UserField {
    key: String,
    rendered: String,
}

impl UserField {
    fn parse(rendered: String) -> Self {
        let key = rendered
            .split_once('=')
            .map_or_else(|| rendered.clone(), |(key, _)| key.to_owned());

        Self { key, rendered }
    }
}

#[derive(Default)]
struct UserLogVisitor {
    user: bool,
    user_log_event: bool,
    message: Option<String>,
    fields: Vec<String>,
    error: Option<String>,
}

impl UserLogVisitor {
    fn record_value(&mut self, field: &Field, value: String) {
        match field.name() {
            crate::user::ATTRIBUTE_KEY => {
                self.user = value == "true";
            },
            "miden.user.log" => {
                self.user_log_event = value == "true";
            },
            "message" => {
                self.message = Some(value);
            },
            crate::user::FIELD_BRIDGE_KEY => self.record_fields(&value),
            "miden.error" => {
                self.error = Some(value);
            },
            _ => {},
        }
    }

    fn record_fields(&mut self, fields: &str) {
        crate::user::parse_fields(fields, |field| self.fields.push(field.to_owned()));
    }
}

impl Visit for UserLogVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, format!("{value:?}").trim_matches('"').to_owned());
    }
}

fn format_field_suffix(fields: &[String]) -> String {
    if fields.is_empty() {
        String::new()
    } else {
        format!(" {}", fields.join(" "))
    }
}

fn format_duration_suffix(duration: Duration) -> String {
    format!(" duration_ms={}", duration.as_millis())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::prelude::*;

    use super::UserFacingStdoutLayer;
    use crate::OpenTelemetryField;

    #[derive(Clone, Default)]
    struct TestWriter {
        output: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<Mutex<usize>>,
    }

    impl io::Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.lock().expect("test writer lock poisoned").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            *self.flushes.lock().expect("test flush lock poisoned") += 1;
            Ok(())
        }
    }

    struct TestField;

    impl OpenTelemetryField for TestField {
        const DEFAULT_KEY: &'static str = "test.field";
        const DEFAULT_KEY_SUFFIX: &'static str = "field";

        fn to_otel_value(&self) -> opentelemetry::Value {
            "value".into()
        }
    }

    struct SpacedField;

    impl OpenTelemetryField for SpacedField {
        const DEFAULT_KEY: &'static str = "test.spaced";
        const DEFAULT_KEY_SUFFIX: &'static str = "spaced";

        fn to_otel_value(&self) -> opentelemetry::Value {
            "value with spaces".into()
        }
    }

    struct UpdatedField;

    impl OpenTelemetryField for UpdatedField {
        const DEFAULT_KEY: &'static str = "test.updated";
        const DEFAULT_KEY_SUFFIX: &'static str = "updated";

        fn to_otel_value(&self) -> opentelemetry::Value {
            "updated".into()
        }
    }

    #[test]
    fn layer_logs_user_spans_and_events() {
        let writer = TestWriter::default();
        let output = writer.output.clone();
        let flushes = writer.flushes.clone();
        let subscriber = tracing_subscriber::registry().with(UserFacingStdoutLayer::new(writer));

        tracing::subscriber::with_default(subscriber, || {
            let span = crate::info_span!(rpc, "sync block", user);
            span.record_field_as(&TestField, "trace.only");
            span.record_user_field(&TestField);
            span.record_user_field(&SpacedField);
            span.record_user_field_as(&TestField, "replace.field");
            span.record_user_field_as(&UpdatedField, "replace.field");
            let _guard = span.entered();

            let event = crate::info!(
                rpc,
                "block accepted",
                user,
                justification = "tests user-facing event stdout output"
            );
            event.record_field_as(&TestField, "trace.event");
            event.record_user_field_as(&TestField, "event.field");
            event.record_user_field_as(&SpacedField, "event.spaced");
            event.emit();
        });

        let output = output.lock().expect("test writer lock poisoned");
        let output = String::from_utf8(output.clone()).expect("stdout output should be utf8");

        assert!(output.contains("INFO sync block completed"));
        assert!(output.contains("test.field=value"));
        assert!(output.contains("test.spaced=value with spaces"));
        assert!(output.contains("replace.field=updated"));
        assert!(!output.contains("replace.field=value"));
        assert!(output.contains("INFO block accepted"));
        assert!(output.contains("event.field=value"));
        assert!(output.contains("event.spaced=value with spaces"));
        assert!(!output.contains("trace.only"));
        assert!(!output.contains("trace.event"));
        assert_eq!(*flushes.lock().expect("test flush lock poisoned"), 2);
    }

    #[test]
    fn layer_ignores_non_user_spans_and_events() {
        let writer = TestWriter::default();
        let output = writer.output.clone();
        let subscriber = tracing_subscriber::registry().with(UserFacingStdoutLayer::new(writer));

        tracing::subscriber::with_default(subscriber, || {
            let span = crate::info_span!(rpc, "internal span");
            let _guard = span.entered();

            let event = crate::info!(
                rpc,
                "internal event",
                justification = "tests non-user event stdout suppression"
            );
            event.emit();
        });

        let output = output.lock().expect("test writer lock poisoned");

        assert!(output.is_empty());
    }

    #[test]
    fn layer_does_not_inherit_user_event_marker_from_span() {
        let writer = TestWriter::default();
        let output = writer.output.clone();
        let subscriber = tracing_subscriber::registry().with(UserFacingStdoutLayer::new(writer));

        tracing::subscriber::with_default(subscriber, || {
            let span = crate::info_span!(rpc, "user span", user);
            let _guard = span.entered();

            let event = crate::info!(
                rpc,
                "internal event",
                justification = "tests that user-facing spans do not make child events user-facing"
            );
            event.emit();
        });

        let output = output.lock().expect("test writer lock poisoned");
        let output = String::from_utf8(output.clone()).expect("stdout output should be utf8");

        assert!(output.contains("INFO user span completed"));
        assert!(!output.contains("internal event"));
    }

    #[test]
    fn fmt_layer_does_not_render_open_telemetry_span_attributes() {
        let writer = TestWriter::default();
        let output = writer.output.clone();
        let exporter = crate::test_utils::TestExporter::default();
        let provider = SdkTracerProvider::builder().with_simple_exporter(exporter).build();
        let tracer = provider.tracer("miden-node-tracing-fmt-test");
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_writer(move || writer.clone()),
            );

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("fmt_parent");
            span.set_attribute("otel.only", "hidden");
            let _guard = span.enter();

            tracing::info!(tracing_field = "visible", "fmt sees tracing fields");
        });

        drop(provider);
        let output = output.lock().expect("test writer lock poisoned");
        let output = String::from_utf8(output.clone()).expect("stdout output should be utf8");

        assert!(output.contains("tracing_field=\"visible\""));
        assert!(!output.contains("otel.only"));
        assert!(!output.contains("hidden"));
    }

    #[test]
    fn user_facing_span_data_can_be_rendered_by_fmt_layer() {
        let writer = TestWriter::default();
        let output = writer.output.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .without_time()
                .with_span_events(FmtSpan::CLOSE)
                .with_writer(move || writer.clone()),
        );

        tracing::subscriber::with_default(subscriber, || {
            let span = crate::info_span!(rpc, "fmt_bridge");
            span.record_field_as(&TestField, "otel.hidden");
            span.record_user_field_as(&TestField, "otel.visible");
            let _guard = span.entered();
            tracing::info!(target: "rpc", "inside fmt bridge");
        });

        let output = output.lock().expect("test writer lock poisoned");
        let output = String::from_utf8(output.clone()).expect("stdout output should be utf8");

        assert!(output.contains("otel.visible=value"), "{output}");
        assert!(!output.contains("otel.hidden"), "{output}");
    }
}
