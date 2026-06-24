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

#[miden_instrument(target = "miden-node-utils-test", name = "records_delayed_fields", skip_all)]
fn records_delayed_fields() {
    let parsed_value = 42;
    let parsed_text = "parsed";

    miden_span_record!(
        parsed.value = parsed_value,
        parsed.text = %parsed_text,
    );
}

#[test]
fn inferred_fields_can_be_recorded_after_span_creation() {
    let recorded = RecordedFields::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());

    tracing::subscriber::with_default(subscriber, records_delayed_fields);

    assert_eq!(recorded.get("parsed.value").as_deref(), Some("42"));
    assert_eq!(recorded.get("parsed.text").as_deref(), Some("parsed"));
}

#[test]
fn ui_tests() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/tracing_macros/pass.rs");
}
