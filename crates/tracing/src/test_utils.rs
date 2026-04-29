use std::sync::{Arc, Mutex};

use opentelemetry::Value;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use tracing_subscriber::prelude::*;

use crate::Span;

#[derive(Clone, Debug, Default)]
pub(crate) struct TestExporter(pub(crate) Arc<Mutex<Vec<SpanData>>>);

impl SpanExporter for TestExporter {
    async fn export(&self, mut batch: Vec<SpanData>) -> OTelSdkResult {
        self.0.lock().expect("span exporter lock poisoned").append(&mut batch);
        Ok(())
    }
}

pub(crate) fn exported_span(record: impl FnOnce(&Span)) -> SpanData {
    let spans = exported_spans(|| {
        let span = tracing::info_span!("test_span");
        let _guard = span.enter();
        let wrapped = Span::new(span.clone());
        record(&wrapped);
    });

    assert_eq!(spans.len(), 1, "expected exactly one exported span");
    spans[0].clone()
}

pub(crate) fn exported_spans(record: impl FnOnce()) -> Vec<SpanData> {
    let exporter = TestExporter::default();
    let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
    let tracer = provider.tracer("miden-node-tracing-test");
    let subscriber =
        tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));

    tracing::subscriber::with_default(subscriber, record);

    drop(provider);
    let spans = exporter.0.lock().expect("span exporter lock poisoned");
    spans.clone()
}

pub(crate) fn assert_attribute(span: &SpanData, key: &str, expected: impl Into<Value>) {
    let actual = span
        .attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == key)
        .unwrap_or_else(|| panic!("missing attribute {key}; attributes: {:?}", span.attributes));

    assert_eq!(actual.value, expected.into(), "attribute {key} had the wrong value");
}
