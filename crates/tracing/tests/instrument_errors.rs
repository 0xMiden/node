use std::error::Error;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use miden_node_tracing::{miden_instrument, miden_span_record};
use opentelemetry::trace::{Status, TracerProvider as _};
use opentelemetry::{Array, KeyValue, Value};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tracing_subscriber::layer::SubscriberExt as _;

#[derive(Debug, thiserror::Error)]
#[error("root cause")]
struct Root;

#[derive(Debug, thiserror::Error)]
#[error("middle error")]
struct Middle(#[source] Root);

#[derive(Debug, thiserror::Error)]
#[error("outer error")]
struct Outer(#[source] Middle);

fn failure() -> Outer {
    Outer(Middle(Root))
}

#[miden_instrument(err, fields(service.name = "test"))]
fn sync_result(mode: u8) -> Result<usize, Outer> {
    miden_span_record!(block.number = 42_u32);
    if mode == 1 {
        return Err(failure());
    }
    match mode {
        0 => Ok(7),
        2 => {
            Err(failure())?;
            Ok(0)
        },
        _ => Err(failure()),
    }
}

#[miden_instrument(err)]
async fn async_result(mode: u8) -> Result<usize, Outer> {
    tokio::task::yield_now().await;
    if mode == 1 {
        return Err(failure());
    }
    match mode {
        0 => Ok(7),
        2 => {
            Err(failure())?;
            Ok(0)
        },
        _ => Err(failure()),
    }
}

#[miden_instrument(err)]
fn future_result() -> impl Future<Output = Result<(), Outer>> {
    let error = failure();
    async move {
        tokio::task::yield_now().await;
        Err(error)
    }
}

#[miden_instrument(err)]
fn maybe_send_result() -> impl miden_protocol::vm::FutureMaybeSend<Result<(), Outer>> {
    async move {
        tokio::task::yield_now().await;
        Err(failure())?;
        Ok(())
    }
}

#[miden_instrument(err)]
fn boxed_future_result() -> std::pin::Pin<Box<dyn Future<Output = Result<(), Outer>> + Send>> {
    Box::pin(async move {
        tokio::task::yield_now().await;
        Err(failure())?;
        Ok(())
    })
}

#[miden_instrument(err)]
fn anyhow_result() -> anyhow::Result<()> {
    Err(anyhow::Error::new(Root).context("middle error").context("outer error"))
}

#[miden_instrument(err)]
fn boxed_error_result() -> Result<(), Box<dyn Error + Send + Sync>> {
    Err(Box::new(failure()))
}

#[miden_instrument(err)]
fn borrowed_error_result() -> Result<(), &'static (dyn Error + Sync)> {
    static ERROR: Outer = Outer(Middle(Root));
    Err(&ERROR)
}

#[miden_instrument(err)]
fn opaque_result(fail: bool) -> Result<impl std::fmt::Debug, Outer> {
    if fail { Err(failure()) } else { Ok(7) }
}

#[miden_instrument(
    parent = None,
    target = "error-test",
    name = "configured",
    level = "debug",
    err(level = "warn"),
)]
fn configured_result(success: bool) -> Result<usize, Outer> {
    if success { Ok(7) } else { Err(failure()) }
}

fn export(run: impl FnOnce()) -> Vec<SpanData> {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::OpenTelemetryLayer::new(provider.tracer("test")));
    tracing::subscriber::with_default(subscriber, run);
    provider.force_flush().unwrap();
    exporter.get_finished_spans().unwrap()
}

fn attribute<'a>(attributes: &'a [KeyValue], name: &str) -> Option<&'a Value> {
    attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == name)
        .map(|attr| &attr.value)
}

fn assert_exception_attributes(attributes: &[KeyValue]) {
    assert_eq!(attribute(attributes, "exception.message"), Some(&Value::from("outer error")));
    assert_eq!(
        attribute(attributes, "exception.stacktrace"),
        Some(&Value::Array(Array::String(vec!["middle error".into(), "root cause".into()])))
    );
}

fn assert_error_chain(span: &SpanData) {
    assert_eq!(span.events.len(), 1, "{span:?}");
    let event = &span.events[0];
    assert_eq!(event.name, "exception");
    assert_exception_attributes(&event.attributes);
    assert_exception_attributes(&span.attributes);
    assert_eq!(span.status, Status::error(""));
}

#[test]
fn sync_errors_export_source_chains_and_preserve_results() {
    let spans = export(|| {
        assert_eq!(sync_result(0).unwrap(), 7);
        for mode in 1..=3 {
            assert_eq!(sync_result(mode).unwrap_err().to_string(), "outer error");
        }
    });
    assert_eq!(spans.len(), 4);
    assert!(spans[0].events.is_empty());
    assert_eq!(spans[0].status, Status::Unset);
    for span in &spans[1..] {
        assert_error_chain(span);
        assert_eq!(attribute(&span.attributes, "service.name"), Some(&Value::from("test")));
        assert_eq!(attribute(&span.attributes, "block.number"), Some(&Value::from("42")));
    }
}

#[test]
fn async_errors_export_source_chains_after_suspension() {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let spans = export(|| {
        runtime.block_on(async {
            assert_eq!(async_result(0).await.unwrap(), 7);
            for mode in 1..=3 {
                assert_eq!(async_result(mode).await.unwrap_err().to_string(), "outer error");
            }
            assert!(future_result().await.is_err());
            assert!(maybe_send_result().await.is_err());
            assert!(boxed_future_result().await.is_err());
        });
    });
    assert_eq!(spans.len(), 7);
    assert!(spans[0].events.is_empty());
    for span in &spans[1..] {
        assert_error_chain(span);
    }
}

#[test]
fn error_wrappers_export_complete_source_chains() {
    let spans = export(|| {
        assert!(anyhow_result().is_err());
        assert!(boxed_error_result().is_err());
        assert!(borrowed_error_result().is_err());
        assert!(opaque_result(true).is_err());
    });
    assert_eq!(spans.len(), 4);
    for span in &spans {
        assert_error_chain(span);
    }
}

#[test]
fn configured_errors_keep_levels_targets_and_parents() {
    let spans = export(|| {
        assert_eq!(configured_result(true).unwrap(), 7);
        assert!(configured_result(false).is_err());
    });
    assert_eq!(spans.len(), 2);
    for span in &spans {
        assert_eq!(span.name, "configured");
        assert_eq!(span.parent_span_id, opentelemetry::trace::SpanId::INVALID);
    }
    assert!(spans[0].events.is_empty());
    assert_eq!(spans[0].status, Status::Unset);
    assert_eq!(spans[1].events.len(), 1);
    assert_eq!(
        attribute(&spans[1].events[0].attributes, "target"),
        Some(&Value::from("error-test"))
    );
    assert_eq!(attribute(&spans[1].events[0].attributes, "level"), Some(&Value::from("WARN")));
    assert_eq!(spans[1].status, Status::Unset);
    assert_exception_attributes(&spans[1].events[0].attributes);
}

#[test]
fn event_macros_export_typed_errors_at_every_level() {
    let cases: [(&str, fn()); 6] = [
        ("TRACE", || miden_node_tracing::trace!(failure(), "typed.event")),
        ("DEBUG", || miden_node_tracing::debug!(&failure(), "typed.event")),
        ("INFO", || {
            miden_node_tracing::info!(
                Box::new(failure()) as Box<dyn Error + Send + Sync>,
                "typed.event"
            );
        }),
        ("INFO", || {
            let error: Arc<dyn miden_node_tracing::ErrorReport + Send + Sync> = Arc::new(failure());
            miden_node_tracing::info!(error.as_ref(), "typed.event");
        }),
        ("WARN", || {
            miden_node_tracing::warn!(
                anyhow::Error::new(Root).context("middle error").context("outer error"),
                "typed.event"
            );
        }),
        ("ERROR", || {
            miden_node_tracing::error!(failure(), "typed.event");
        }),
    ];
    let spans = export(|| {
        for (_, emit) in cases {
            let parent = tracing::info_span!("event-parent");
            let other = tracing::info_span!("unrelated");
            let _guard = other.enter();
            parent.in_scope(emit);
        }
    });
    let parents = spans.iter().filter(|span| span.name == "event-parent").collect::<Vec<_>>();
    assert_eq!(parents.len(), cases.len());
    assert!(
        spans
            .iter()
            .filter(|span| span.name == "unrelated")
            .all(|span| span.events.is_empty())
    );
    for (span, (level, _)) in parents.into_iter().zip(cases) {
        assert_eq!(span.events.len(), 1);
        let event = &span.events[0];
        assert_eq!(event.name, "typed.event");
        assert_eq!(attribute(&event.attributes, "level"), Some(&Value::from(level)));
        assert_exception_attributes(&event.attributes);
        assert_exception_attributes(&span.attributes);
        let status = if level == "ERROR" {
            Status::error("")
        } else {
            Status::Unset
        };
        assert_eq!(span.status, status);
    }
}

#[test]
fn explicit_error_event_parent_receives_the_sources() {
    let spans = export(|| {
        let parent = tracing::info_span!("explicit-parent");
        let other = tracing::info_span!("current-parent");
        let _guard = other.enter();
        miden_node_tracing::error!(
            failure(),
            target: "error-test",
            parent: &parent,
            "explicit.error",
            block.number = 42_u32
        );
    });
    let parent = spans.iter().find(|span| span.name == "explicit-parent").unwrap();
    assert_eq!(parent.events.len(), 1);
    let event = &parent.events[0];
    assert_eq!(event.name, "explicit.error");
    assert_eq!(attribute(&event.attributes, "target"), Some(&Value::from("error-test")));
    assert_eq!(attribute(&event.attributes, "block.number"), Some(&Value::from("42")));
    assert_exception_attributes(&event.attributes);
    assert!(
        spans
            .iter()
            .find(|span| span.name == "current-parent")
            .unwrap()
            .events
            .is_empty()
    );
}

#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn compact_stdout_includes_error_sources() {
    let output = Output::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .compact()
            .with_level(true)
            .with_file(false)
            .with_line_number(false)
            .with_target(false)
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone()),
    );
    tracing::subscriber::with_default(subscriber, || {
        assert!(sync_result(3).is_err());
        miden_node_tracing::error!(failure(), "explicit.error");
    });
    let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert_eq!(output.lines().count(), 2, "{output}");
    assert!(output.contains("ERROR"), "{output}");
    assert!(output.contains("sync_result"), "{output}");
    assert!(output.contains("explicit.error"), "{output}");
    for line in output.lines() {
        assert!(line.contains("error=outer error"), "{output}");
        assert!(line.contains("error.sources=[middle error, root cause]"), "{output}");
    }
}

#[cfg(feature = "tracing-forest")]
#[test]
fn forest_stdout_records_only_the_outer_message() {
    let output = Output::default();
    let writer = output.clone();
    let printer = tracing_forest::printer::PrettyPrinter::new().writer(move || writer.clone());
    let subscriber = tracing_subscriber::registry()
        .with(tracing_forest::ForestLayer::new(printer, tracing_forest::tag::NoTag));
    tracing::subscriber::with_default(subscriber, || {
        assert!(sync_result(3).is_err());
        miden_node_tracing::error!(failure(), "explicit.error");
    });
    let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("outer error"), "{output}");
    assert!(output.contains("explicit.error"), "{output}");
    assert!(!output.contains("middle error"), "{output}");
    assert!(!output.contains("root cause"), "{output}");
}
