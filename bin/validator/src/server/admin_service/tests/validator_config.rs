use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt;

use super::{commit, test_database};
use crate::server::admin_service::validator_config::router;

const STATUS: &str = "/admin/v1/validator-config";
const PENDING: &str = "/admin/v1/validator-config/pending";

async fn setup(signing_lock: Arc<Mutex<()>>) -> (tempfile::TempDir, Router, Value) {
    let (directory, db, _) = test_database().await;
    commit(&db, 1, &[]).await;
    let header = db.load_chain_tip().await.unwrap().unwrap();
    let signer = header.validator_config().keys()[0].clone();
    let active = json!({"keys": [signer.to_string()], "quorum": 1});
    (directory, router(&db, signer, signing_lock), active)
}

fn add_validator(active: &Value) -> Value {
    let mut keys: Vec<String> = serde_json::from_value(active["keys"].clone()).unwrap();
    keys.push(SigningKey::new().public_key().to_string());
    keys.sort();
    json!({"keys": keys, "quorum": keys.len()})
}

fn change_request(method: Method, active: &Value, pending: &Value) -> Request<Body> {
    let body = json!({"active": active, "pending": pending});
    Request::builder()
        .method(method)
        .uri(PENDING)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn register(app: &Router, active: &Value, pending: &Value) -> StatusCode {
    let request = change_request(Method::PUT, active, pending);
    app.clone().oneshot(request).await.unwrap().status()
}

async fn status(app: &Router) -> Value {
    let request = Request::get(STATUS).body(Body::empty()).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), app.clone().oneshot(request))
        .await
        .expect("configuration status should remain readable during signing")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}

#[tokio::test]
async fn only_one_of_two_competing_changes_can_be_registered() {
    let (_directory, app, active) = setup(Arc::default()).await;
    let first = add_validator(&active);
    let second = add_validator(&active);
    let responses = tokio::join!(register(&app, &active, &first), register(&app, &active, &second));
    let pending = match responses {
        (StatusCode::NO_CONTENT, StatusCode::CONFLICT) => first,
        (StatusCode::CONFLICT, StatusCode::NO_CONTENT) => second,
        _ => panic!("unexpected registration responses: {responses:?}"),
    };
    assert_eq!(register(&app, &active, &pending).await, StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await, json!({"active": active, "pending": pending}));

    let cancel = change_request(Method::DELETE, &active, &pending);
    assert_eq!(app.clone().oneshot(cancel).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await, json!({"active": active, "pending": null}));
}

#[tokio::test]
async fn rejected_changes_leave_no_pending_configuration() {
    let (_directory, app, active) = setup(Arc::default()).await;
    let stale = add_validator(&active);
    let other = json!({"keys": [SigningKey::new().public_key().to_string()], "quorum": 1});
    assert_eq!(register(&app, &stale, &add_validator(&stale)).await, StatusCode::CONFLICT);
    assert_eq!(register(&app, &active, &active).await, StatusCode::BAD_REQUEST);
    assert_eq!(register(&app, &active, &other).await, StatusCode::BAD_REQUEST);
    assert_eq!(register(&app, &stale, &active).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        register(&app, &active, &json!({"keys": [], "quorum": 0})).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(status(&app).await, json!({"active": active, "pending": null}));
}

#[tokio::test]
async fn config_writes_wait_for_signing() {
    let signing_lock = Arc::new(Mutex::new(()));
    let (_directory, app, active) = setup(Arc::clone(&signing_lock)).await;
    let pending = add_validator(&active);

    let signing = signing_lock.lock().await;
    let mut put = std::pin::pin!(register(&app, &active, &pending));
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut put).await.is_err());
    assert_eq!(status(&app).await["pending"], Value::Null);
    drop(signing);
    assert_eq!(put.await, StatusCode::NO_CONTENT);

    let signing = signing_lock.lock().await;
    let request = change_request(Method::DELETE, &active, &pending);
    let mut delete = std::pin::pin!(app.clone().oneshot(request));
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut delete).await.is_err());
    assert_eq!(status(&app).await["pending"], pending);
    drop(signing);
    assert_eq!(delete.await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await["pending"], Value::Null);
}

#[tokio::test]
async fn cancel_rejects_a_different_or_missing_pending_change() {
    let (_directory, app, active) = setup(Arc::default()).await;
    let pending = add_validator(&active);
    let request = change_request(Method::DELETE, &active, &pending);
    assert_eq!(app.clone().oneshot(request).await.unwrap().status(), StatusCode::CONFLICT);

    assert_eq!(register(&app, &active, &pending).await, StatusCode::NO_CONTENT);
    let different = change_request(Method::DELETE, &active, &add_validator(&active));
    assert_eq!(app.clone().oneshot(different).await.unwrap().status(), StatusCode::CONFLICT);
    let missing = Request::delete(PENDING).body(Body::empty()).unwrap();
    assert!(!app.clone().oneshot(missing).await.unwrap().status().is_success());
    assert_eq!(status(&app).await, json!({"active": active, "pending": pending}));
}
