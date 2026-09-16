use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use miden_node_tracing::{debug, error, info, miden_instrument, miden_span_record, trace, warn};
use miden_protocol::block::BlockNumber;
use tracing::field::{Field, Visit};
use tracing::{Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;

#[derive(Clone, Default)]
struct RecordedFields(Arc<Mutex<BTreeMap<String, String>>>);

impl RecordedFields {
    fn get(&self, key: &str) -> Option<String> {
        self.0.lock().unwrap().get(key).cloned()
    }
}

#[derive(Clone, Default)]
struct RecordedEvents(Arc<Mutex<Vec<RecordedEvent>>>);

#[derive(Clone)]
struct RecordedEvent {
    level: Level,
    target: String,
    fields: BTreeMap<String, String>,
}

impl RecordedEvents {
    fn events(&self) -> Vec<RecordedEvent> {
        self.0.lock().unwrap().clone()
    }
}

impl<S> Layer<S> for RecordedEvents
where
    S: Subscriber,
    for<'a> S: LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let fields = Arc::new(Mutex::new(BTreeMap::new()));
        event.record(&mut FieldVisitor(Arc::clone(&fields)));
        let fields = fields.lock().unwrap().clone();
        let metadata = event.metadata();

        self.0.lock().unwrap().push(RecordedEvent {
            level: *metadata.level(),
            target: metadata.target().to_owned(),
            fields,
        });
    }
}

impl<S> Layer<S> for RecordedFields
where
    S: Subscriber,
    for<'a> S: LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::Id,
        _ctx: Context<'_, S>,
    ) {
        attrs.record(&mut FieldVisitor(self.0.clone()));
    }

    fn on_record(
        &self,
        _span: &tracing::Id,
        values: &tracing::span::Record<'_>,
        _ctx: Context<'_, S>,
    ) {
        values.record(&mut FieldVisitor(self.0.clone()));
    }
}

struct FieldVisitor(Arc<Mutex<BTreeMap<String, String>>>);

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field, format!("{value:?}"));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record(field, value.to_string());
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.record(field, value.to_string());
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record(field, value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record(field, value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, value.to_owned());
    }
}

impl FieldVisitor {
    fn record(&self, field: &Field, value: String) {
        self.0.lock().unwrap().insert(field.name().to_owned(), value);
    }
}

#[miden_instrument(target = "miden-node-tracing-test", name = "records_delayed_fields")]
fn records_inferred_fields() {
    let parsed_value = 42;
    let parsed_text = "parsed";
    let omitted = None::<u32>;

    miden_span_record!(
        block.number = parsed_value,
        service.name = parsed_text,
        batch.expires_at = Some(3_u32),
        batch.expiration_height = omitted
    );
}

#[miden_instrument(
    target = "miden-node-tracing-test",
    name = "records_explicit_fields",
    fields(
        account.id,
        account.updated,
    ),
)]
fn records_explicit_fields() {
    tracing::Span::current().record("account.id", tracing::field::display("explicit-account"));
    tracing::Span::current().record("account.updated", true);
}

#[miden_instrument(
    target = "miden-node-tracing-test",
    name = "records_explicit_argument_field",
    fields(
        service.name = service_name,
    ),
)]
fn records_explicit_argument_field(service_name: &str) {}

#[miden_instrument(
    target = "miden-node-tracing-test",
    name = "records_explicit_and_inferred_fields",
    fields(
        account.id,
    ),
)]
fn records_explicit_and_inferred_fields() {
    let block_number = 9;

    tracing::Span::current().record("account.id", tracing::field::display("mixed-account"));
    miden_span_record!(block.number = block_number, service.name = "mixed-service");
}

#[miden_instrument(target = "miden-node-tracing-test", name = "records_fields_from_multiple_calls")]
fn records_fields_from_multiple_calls() {
    let block_number = 14;
    let service_name = "multi-call-service";

    miden_span_record!(block.number = block_number);
    miden_span_record!(service.name = service_name);
}

#[miden_instrument(target = "miden-node-tracing-test", name = "records_canonical_types")]
fn records_canonical_types() {
    miden_span_record!(block.number = BlockNumber::from(42));
}

#[miden_instrument(target = "miden-node-tracing-test", name = "records_count_field")]
fn records_count_field() {
    miden_span_record!(unregistered.item.count = 3_usize);
}

#[miden_instrument(
    target = "miden-node-tracing-test",
    name = "records_nonstandard_explicit_field",
    fields(custom.explicit = value #[nonstandard]),
)]
fn records_nonstandard_explicit_field(value: &str) {}

#[miden_instrument(target = "miden-node-tracing-test", name = "records_nonstandard_delayed_field")]
fn records_nonstandard_delayed_field() {
    miden_span_record!(custom.delayed = "delayed" #[nonstandard]);
}

#[derive(Debug, thiserror::Error)]
#[error("source error")]
struct SourceError;

#[derive(Debug, thiserror::Error)]
#[error("outer error")]
struct OuterError(#[source] SourceError);

fn records_events() {
    const TARGET: &str = "miden-node-tracing-event-test";

    trace!(
        target: TARGET,
        "trace.event",
        block.number = BlockNumber::from(1),
        custom.attribute = "custom" #[nonstandard]
    );
    debug!(target: TARGET, "debug.event", block.number = BlockNumber::from(2));

    let parent = tracing::info_span!("event-parent");
    info!(
        target: TARGET,
        parent: &parent,
        "info.event",
        block.number = BlockNumber::from(3)
    );

    warn!(target: TARGET, "warn.event", block.number = BlockNumber::from(4));
    warn!(
        OuterError(SourceError),
        target: TARGET,
        "warn.error.event",
        block.number = BlockNumber::from(5)
    );
    error!(
        OuterError(SourceError),
        target: TARGET,
        "error.event",
        block.number = BlockNumber::from(6)
    );
}

#[test]
fn inferred_fields_can_be_recorded_after_span_creation() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_inferred_fields);

    assert_eq!(recorded.get("block.number").as_deref(), Some("42"));
    assert_eq!(recorded.get("service.name").as_deref(), Some("parsed"));
    assert_eq!(recorded.get("batch.expires_at").as_deref(), Some("3"));
    assert_eq!(recorded.get("batch.expiration_height"), None);
}

#[test]
fn explicit_fields_can_be_recorded_after_span_creation() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_explicit_fields);

    assert_eq!(recorded.get("account.id").as_deref(), Some("explicit-account"));
    assert_eq!(recorded.get("account.updated").as_deref(), Some("true"));
}

#[test]
fn explicit_argument_fields_are_recorded_at_span_creation() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, || {
        records_explicit_argument_field("argument-service");
    });

    assert_eq!(recorded.get("service.name").as_deref(), Some("argument-service"));
}

#[test]
fn explicit_and_inferred_fields_can_be_recorded_after_span_creation() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_explicit_and_inferred_fields);

    assert_eq!(recorded.get("account.id").as_deref(), Some("mixed-account"));
    assert_eq!(recorded.get("block.number").as_deref(), Some("9"));
    assert_eq!(recorded.get("service.name").as_deref(), Some("mixed-service"));
}

#[test]
fn multiple_span_record_macros_can_record_fields_after_span_creation() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_fields_from_multiple_calls);

    assert_eq!(recorded.get("block.number").as_deref(), Some("14"));
    assert_eq!(recorded.get("service.name").as_deref(), Some("multi-call-service"));
}

#[test]
fn domain_types_use_their_canonical_attribute_type() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_canonical_types);

    assert_eq!(recorded.get("block.number").as_deref(), Some("42"));
}

#[test]
fn count_fields_do_not_require_registration() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_count_field);

    assert_eq!(recorded.get("unregistered.item.count").as_deref(), Some("3"));
}

#[test]
fn nonstandard_fields_retain_canonical_attribute_encoding() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, || {
        records_nonstandard_explicit_field("explicit");
        records_nonstandard_delayed_field();
    });

    assert_eq!(recorded.get("custom.explicit").as_deref(), Some("explicit"));
    assert_eq!(recorded.get("custom.delayed").as_deref(), Some("delayed"));
}

#[test]
fn event_macros_record_canonical_attributes() {
    let recorded = RecordedEvents::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_events);

    let events = recorded.events();
    let expected = [
        (Level::TRACE, "trace.event", "1"),
        (Level::DEBUG, "debug.event", "2"),
        (Level::INFO, "info.event", "3"),
        (Level::WARN, "warn.event", "4"),
        (Level::WARN, "warn.error.event", "5"),
        (Level::ERROR, "error.event", "6"),
    ];
    assert_eq!(events.len(), expected.len());

    for (event, (level, name, block_number)) in events.iter().zip(expected) {
        assert_eq!(event.level, level);
        assert_eq!(event.target, "miden-node-tracing-event-test");
        assert_eq!(event.fields.get("message").unwrap(), name);
        assert_eq!(event.fields.get("block.number").unwrap(), block_number);
    }

    assert!(!events[3].fields.contains_key("error"));
    assert_eq!(events[0].fields.get("custom.attribute").unwrap(), "custom");
    assert_eq!(events[4].fields.get("error").unwrap(), "outer error");
    assert_eq!(events.last().unwrap().fields.get("error").unwrap(), "outer error");
}

#[test]
fn ui_tests() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/tracing_macros/pass.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_field_name.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_field_annotation.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_field_type.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_count_type.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_scalar_plural.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_collection_singular.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_instrument_field_name.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_skip.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_skip_all.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_record_attribute.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_nonstandard_attribute.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_instrument_attribute.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_record_formatter.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_instrument_formatter.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_err_formatter.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_ret.rs");
    tests.compile_fail("tests/ui/tracing_macros/outside_miden_instrument.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_event_field_name.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_event_field_type.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_event_attribute.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_event_formatter.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_event_trailing_comma.rs");
    tests.compile_fail("tests/ui/tracing_macros/missing_event_name.rs");
    tests.compile_fail("tests/ui/tracing_macros/missing_error.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_error_type.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_optional_error_type.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_event_exception_message.rs");
}
