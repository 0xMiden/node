#![cfg(feature = "admin-api")]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use miden_node_tracing::{OpenTelemetry, TracingConfig, setup_tracing_with_config};
use tower::ServiceExt;

#[tokio::test]
async fn production_setup_exposes_reload_controls_without_an_exporter() {
    let guard = setup_tracing_with_config(TracingConfig {
        open_telemetry: OpenTelemetry::Disabled,
        stdout_filter: "warn".to_owned(),
        otel_filter: "off".to_owned(),
    })
    .unwrap();
    assert!(guard.is_none());
    let app = miden_node_tracing::admin::router();
    let response = app
        .clone()
        .oneshot(Request::get("/admin/tracing/stdout-filter").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body, serde_json::json!({"filter": "warn"}));
    for (output, expected) in [("stdout", StatusCode::NO_CONTENT), ("otel", StatusCode::CONFLICT)] {
        let response = app
            .clone()
            .oneshot(
                Request::put(format!("/admin/tracing/{output}-filter"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"filter":"off"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}
