#![cfg(feature = "admin-api")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use miden_node_tracing::{OpenTelemetry, TracingConfig, setup_tracing_with_config};
use tower::ServiceExt;

#[tokio::test]
async fn production_setup_exposes_reload_controls_without_an_exporter() {
    let guard = setup_tracing_with_config(TracingConfig {
        open_telemetry: OpenTelemetry::Disabled,
        stdout_filter: "off".to_owned(),
        otel_filter: "off".to_owned(),
    })
    .unwrap();
    assert!(guard.is_none());
    let app = miden_node_tracing::admin::router();
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
