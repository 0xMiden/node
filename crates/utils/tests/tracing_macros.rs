use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use miden_node_utils::tracing::{miden_instrument, miden_span_record};
use tracing::Subscriber;
use tracing::field::{Field, Visit};
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
        self.0.lock().unwrap().insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[miden_instrument(
    target = "miden-node-utils-test",
    name = "records_delayed_fields",
    skip_all,
)]
fn records_inferred_fields() {
    let parsed_value = 42;
    let parsed_text = "parsed";

    miden_span_record!(
        block.number = parsed_value,
        transaction.id = %parsed_text,
    );
}

#[miden_instrument(
    target = "miden-node-utils-test",
    name = "records_explicit_fields",
    skip_all,
    fields(
        account.id = tracing::field::Empty,
        account.updated = tracing::field::Empty,
    ),
)]
fn records_explicit_fields() {
    tracing::Span::current().record("account.id", tracing::field::display("explicit-account"));
    tracing::Span::current().record("account.updated", true);
}

#[miden_instrument(
    target = "miden-node-utils-test",
    name = "records_explicit_argument_field",
    skip_all,
    fields(
        account.id = %account_id,
    ),
)]
fn records_explicit_argument_field(account_id: &str) {}

#[miden_instrument(
    target = "miden-node-utils-test",
    name = "records_explicit_and_inferred_fields",
    skip_all,
    fields(
        account.id = tracing::field::Empty,
    ),
)]
fn records_explicit_and_inferred_fields() {
    let block_number = 9;

    tracing::Span::current().record("account.id", tracing::field::display("mixed-account"));
    miden_span_record!(
        block.number = block_number,
        transaction.id = %"mixed-tx",
    );
}

#[test]
fn inferred_fields_can_be_recorded_after_span_creation() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_inferred_fields);

    assert_eq!(recorded.get("block.number").as_deref(), Some("42"));
    assert_eq!(recorded.get("transaction.id").as_deref(), Some("parsed"));
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
        records_explicit_argument_field("argument-account");
    });

    assert_eq!(recorded.get("account.id").as_deref(), Some("argument-account"));
}

#[test]
fn explicit_and_inferred_fields_can_be_recorded_after_span_creation() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_explicit_and_inferred_fields);

    assert_eq!(recorded.get("account.id").as_deref(), Some("mixed-account"));
    assert_eq!(recorded.get("block.number").as_deref(), Some("9"));
    assert_eq!(recorded.get("transaction.id").as_deref(), Some("mixed-tx"));
}

#[test]
fn ui_tests() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/tracing_macros/pass.rs");
    tests.compile_fail("tests/ui/tracing_macros/invalid_field_name.rs");
    tests.compile_fail("tests/ui/tracing_macros/outside_miden_instrument.rs");
}
