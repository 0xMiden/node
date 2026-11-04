use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::router_with_controls;
use crate::logging::{FilterControls, reloadable_filter};

#[derive(Clone, Default)]
struct Recorded(Arc<Mutex<Vec<&'static str>>>);

impl<S: Subscriber> Layer<S> for Recorded {
    fn on_event(&self, _: &tracing::Event<'_>, _: Context<'_, S>) {
        self.0.lock().unwrap().push("event");
    }

    fn on_new_span(&self, _: &tracing::span::Attributes<'_>, _: &tracing::Id, _: Context<'_, S>) {
        self.0.lock().unwrap().push("span");
    }
}

fn setup(otel_enabled: bool) -> (Router, tracing::Dispatch, Recorded, Recorded) {
    let stdout = Recorded::default();
    let otel = Recorded::default();
    let (stdout_filter, stdout_reload) = reloadable_filter("off").unwrap();
    let (otel_filter, otel_reload) = reloadable_filter("off").unwrap();
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

#[tokio::test]
async fn filters_change_independently_and_reenable_existing_callsites() {
    let (app, dispatch, stdout, otel) = setup(true);
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

#[tokio::test]
async fn reloaded_otel_filter_preserves_span_attributes_and_export() {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder().with_simple_exporter(exporter.clone()).build();
    let (stdout_filter, stdout_reload) = reloadable_filter("off").unwrap();
    let (otel_filter, otel_reload) = reloadable_filter("off").unwrap();
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
}

#[tokio::test]
async fn unavailable_controls_return_service_unavailable() {
    let app = router_with_controls(None);
    assert_eq!(put(&app, "stdout", "debug").await, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(put(&app, "otel", "debug").await, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn failed_reload_returns_an_error() {
    let (app, dispatch, ..) = setup(true);
    drop(dispatch);
    assert_eq!(put(&app, "stdout", "debug").await, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(put(&app, "otel", "debug").await, StatusCode::INTERNAL_SERVER_ERROR);
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
