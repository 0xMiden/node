use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use tracing::Subscriber;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::router_with_controls;
use crate::filter_control::{FilterControls, FilterOutput, reloadable_filter};

#[derive(Clone, Default)]
struct Recorded(Arc<Mutex<Vec<&'static str>>>);

#[derive(Clone, Default)]
struct RecordedErrors(Arc<Mutex<Vec<String>>>);

impl tracing::field::Visit for RecordedErrors {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}

    fn record_error(
        &mut self,
        _: &tracing::field::Field,
        error: &(dyn std::error::Error + 'static),
    ) {
        self.0.lock().unwrap().push(error.to_string());
        let mut source = error.source();
        while let Some(error) = source {
            self.0.lock().unwrap().push(error.to_string());
            source = error.source();
        }
    }
}

impl<S: Subscriber> Layer<S> for RecordedErrors {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        event.record(&mut self.clone());
    }
}

impl<S: Subscriber> Layer<S> for Recorded {
    fn on_event(&self, _: &tracing::Event<'_>, _: Context<'_, S>) {
        self.0.lock().unwrap().push("event");
    }

    fn on_new_span(&self, _: &tracing::span::Attributes<'_>, _: &tracing::Id, _: Context<'_, S>) {
        self.0.lock().unwrap().push("span");
    }
}

fn setup(otel_enabled: bool) -> (Router, tracing::Dispatch, Recorded, Recorded) {
    setup_with_filters(otel_enabled, "off", "off")
}

fn setup_with_filters(
    otel_enabled: bool,
    stdout_expression: &str,
    otel_expression: &str,
) -> (Router, tracing::Dispatch, Recorded, Recorded) {
    let stdout = Recorded::default();
    let otel = Recorded::default();
    let (stdout_filter, stdout_reload) =
        reloadable_filter(stdout_expression, FilterOutput::Stdout).unwrap();
    let (otel_filter, otel_reload) =
        reloadable_filter(otel_expression, FilterOutput::OpenTelemetry).unwrap();
    let subscriber = Registry::default()
        .with(stdout.clone().with_filter(stdout_filter))
        .with(otel.clone().with_filter(otel_filter));
    let app = router_with_controls(Some(FilterControls {
        stdout: stdout_reload,
        otel: otel_enabled.then_some(otel_reload),
    }));
    (app, tracing::Dispatch::new(subscriber), stdout, otel)
}

fn emit(dispatch: &tracing::Dispatch) {
    tracing::dispatcher::with_default(dispatch, || {
        let _span = tracing::info_span!(target: "admin_test", "test_span");
        tracing::info!(target: "admin_test", "test_event");
    });
}

async fn put(app: &Router, output: &str, filter: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::put(format!("/admin/tracing/{output}-filter"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"filter": filter}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn get(app: &Router, output: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/admin/tracing/{output}-filter"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn saved_filters_preserve_float_value_matching_when_restored() {
    let expression = "off,[scope{value=1.0}]=info";
    let (app, dispatch, stdout, otel) = setup_with_filters(true, expression, expression);
    async {
        let emit_float = || {
            let span = tracing::info_span!("scope", value = 1.0_f64);
            let _entered = span.enter();
            tracing::info!("float event");
        };
        emit_float();
        for recorded in [&stdout, &otel] {
            assert_eq!(
                recorded.0.lock().unwrap().iter().filter(|kind| **kind == "event").count(),
                1
            );
        }

        for output in ["stdout", "otel"] {
            let (status, saved) = get(&app, output).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(saved, json!({"filter": expression}));
            assert_eq!(put(&app, output, "off").await, StatusCode::NO_CONTENT);
            assert_eq!(
                put(&app, output, saved["filter"].as_str().unwrap()).await,
                StatusCode::NO_CONTENT
            );
            assert_eq!(get(&app, output).await.1, saved);
        }

        emit_float();
        for recorded in [&stdout, &otel] {
            assert_eq!(
                recorded.0.lock().unwrap().iter().filter(|kind| **kind == "event").count(),
                2
            );
        }
    }
    .with_subscriber(dispatch)
    .await;
}

#[tokio::test]
async fn get_returns_the_active_filter_for_each_output() {
    let (app, _dispatch, ..) = setup(true);
    for output in ["stdout", "otel"] {
        assert_eq!(get(&app, output).await, (StatusCode::OK, json!({"filter": "off"})));
    }

    assert_eq!(put(&app, "stdout", "admin_test=info").await, StatusCode::NO_CONTENT);
    assert_eq!(
        get(&app, "stdout").await,
        (StatusCode::OK, json!({"filter": "admin_test=info"}))
    );
    assert_eq!(get(&app, "otel").await, (StatusCode::OK, json!({"filter": "off"})));

    assert_eq!(put(&app, "stdout", "admin_test=invalid").await, StatusCode::BAD_REQUEST);
    assert_eq!(
        get(&app, "stdout").await,
        (StatusCode::OK, json!({"filter": "admin_test=info"}))
    );

    assert_eq!(put(&app, "otel", "warn").await, StatusCode::NO_CONTENT);
    assert_eq!(get(&app, "otel").await, (StatusCode::OK, json!({"filter": "warn"})));
    assert_eq!(put(&app, "otel", "admin_test=invalid").await, StatusCode::BAD_REQUEST);
    assert_eq!(get(&app, "otel").await, (StatusCode::OK, json!({"filter": "warn"})));
    assert_eq!(
        get(&app, "stdout").await,
        (StatusCode::OK, json!({"filter": "admin_test=info"}))
    );
}

#[tokio::test]
async fn filters_change_independently_and_reenable_existing_callsites() {
    let (app, dispatch, stdout, otel) = setup(true);
    // Reloading rebuilds callsite interest using the current dispatcher when only one subscriber is
    // registered, so keep this subscriber active during requests as well as emissions.
    async {
        emit(&dispatch);
        assert!(stdout.0.lock().unwrap().is_empty());
        assert!(otel.0.lock().unwrap().is_empty());

        assert_eq!(put(&app, "stdout", "off,admin_test=info").await, StatusCode::NO_CONTENT);
        emit(&dispatch);
        assert_eq!(*stdout.0.lock().unwrap(), ["span", "event"]);
        assert!(otel.0.lock().unwrap().is_empty());

        assert_eq!(put(&app, "stdout", "admin_test=invalid").await, StatusCode::BAD_REQUEST);
        emit(&dispatch);
        assert_eq!(*stdout.0.lock().unwrap(), ["span", "event", "span", "event"]);

        assert_eq!(put(&app, "otel", "off,admin_test=info").await, StatusCode::NO_CONTENT);
        assert_eq!(put(&app, "stdout", "off").await, StatusCode::NO_CONTENT);
        emit(&dispatch);
        assert_eq!(*stdout.0.lock().unwrap(), ["span", "event", "span", "event"]);
        assert_eq!(*otel.0.lock().unwrap(), ["span", "event"]);

        assert_eq!(put(&app, "otel", "admin_test=invalid").await, StatusCode::BAD_REQUEST);
        emit(&dispatch);
        assert_eq!(*otel.0.lock().unwrap(), ["span", "event", "span", "event"]);
    }
    .with_subscriber(dispatch.clone())
    .await;
}

#[tokio::test]
async fn reloaded_otel_filter_preserves_span_attributes_and_export() {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
    let (stdout_filter, stdout_reload) = reloadable_filter("off", FilterOutput::Stdout).unwrap();
    let (otel_filter, otel_reload) = reloadable_filter("off", FilterOutput::OpenTelemetry).unwrap();
    let subscriber = Registry::default().with(Recorded::default().with_filter(stdout_filter)).with(
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("admin_test"))
            .with_filter(otel_filter),
    );
    let dispatch = tracing::Dispatch::new(subscriber);
    let app = router_with_controls(Some(FilterControls {
        stdout: stdout_reload,
        otel: Some(otel_reload),
    }));
    assert_eq!(put(&app, "otel", "off,admin_test=info").await, StatusCode::NO_CONTENT);
    tracing::dispatcher::with_default(&dispatch, || {
        let span = tracing::info_span!(target: "admin_test", "exported");
        span.set_attribute("test.attribute", "value");
    });
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].name, "exported");
    assert!(
        spans[0]
            .attributes
            .contains(&opentelemetry::KeyValue::new("test.attribute", "value"))
    );
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn disabled_exporter_cannot_be_enabled_by_changing_its_filter() {
    let (app, _dispatch, ..) = setup(false);
    assert_eq!(put(&app, "otel", "debug").await, StatusCode::CONFLICT);
    assert_eq!(put(&app, "stdout", "info").await, StatusCode::NO_CONTENT);
    assert_eq!(get(&app, "otel").await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn unavailable_controls_return_service_unavailable() {
    let app = router_with_controls(None);
    assert_eq!(put(&app, "stdout", "debug").await, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(put(&app, "otel", "debug").await, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(get(&app, "stdout").await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(get(&app, "otel").await.0, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn failed_reload_returns_an_error() {
    let (app, dispatch, ..) = setup(true);
    drop(dispatch);
    let errors = RecordedErrors::default();
    async {
        for output in ["stdout", "otel"] {
            assert_eq!(put(&app, output, "debug").await, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                get(&app, output).await,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "failed to read tracing filter"})
                )
            );
        }
    }
    .with_subscriber(Registry::default().with(errors.clone()))
    .await;

    let errors = errors.0.lock().unwrap();
    for output in ["stdout", "otel"] {
        assert!(errors.contains(&format!("failed to update {output} tracing filter")));
        assert!(errors.contains(&format!("failed to read {output} tracing filter")));
    }
    assert!(errors.iter().any(|error| error.contains("subscriber no longer exists")));
}

#[tokio::test]
async fn targets_are_available_without_tracing_initialization() {
    let response = router_with_controls(None)
        .oneshot(Request::get("/admin/tracing/targets").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body, json!({"targets": crate::declared_targets()}));
}
