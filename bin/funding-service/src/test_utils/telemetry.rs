//! Captures exported spans without changing the process-wide subscriber.

use opentelemetry::Value;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

pub(crate) struct Telemetry {
    exporter: InMemorySpanExporter,
    provider: SdkTracerProvider,
}

impl Telemetry {
    pub(crate) fn capture() -> (Self, impl Drop) {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("funding-test")));
        let guard = subscriber.set_default();
        (Self { exporter, provider }, guard)
    }

    pub(crate) fn spans(&self) -> Vec<SpanData> {
        self.provider.force_flush().unwrap();
        self.exporter.get_finished_spans().unwrap()
    }

    pub(crate) fn span(&self, name: &str) -> SpanData {
        self.spans()
            .into_iter()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("missing exported span {name}"))
    }
}

pub(crate) fn attribute(span: &SpanData, name: &str) -> Option<Value> {
    span.attributes
        .iter()
        .find(|attr| attr.key.as_str() == name)
        .map(|attr| attr.value.clone())
}
