use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
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
    let current = json!({"keys": [signer.to_string()], "quorum": 1});
    (directory, router(&db, signer, signing_lock), current)
}

fn add_validator(current: &Value) -> Value {
    let mut keys: Vec<String> = serde_json::from_value(current["keys"].clone()).unwrap();
    keys.push(SigningKey::new().public_key().to_string());
    keys.sort();
    json!({"keys": keys, "quorum": keys.len()})
}

async fn register(app: &Router, current: &Value, proposed: &Value) -> StatusCode {
    let body = json!({"current": current, "proposed": proposed});
    let request = Request::put(PENDING)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
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
    let (_directory, app, current) = setup(Arc::default()).await;
    let first = add_validator(&current);
    let second = add_validator(&current);
    let responses =
        tokio::join!(register(&app, &current, &first), register(&app, &current, &second));
    let pending = match responses {
        (StatusCode::NO_CONTENT, StatusCode::CONFLICT) => first,
        (StatusCode::CONFLICT, StatusCode::NO_CONTENT) => second,
        _ => panic!("unexpected registration responses: {responses:?}"),
    };
    assert_eq!(register(&app, &current, &pending).await, StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await, json!({"active": current, "pending": pending}));

    let cancel = Request::delete(PENDING).body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(cancel).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await, json!({"active": current, "pending": null}));
}

#[tokio::test]
async fn rejected_changes_leave_no_pending_configuration() {
    let (_directory, app, current) = setup(Arc::default()).await;
    let stale = add_validator(&current);
    let other = json!({"keys": [SigningKey::new().public_key().to_string()], "quorum": 1});
    assert_eq!(register(&app, &stale, &add_validator(&stale)).await, StatusCode::CONFLICT);
    assert_eq!(register(&app, &current, &current).await, StatusCode::BAD_REQUEST);
    assert_eq!(register(&app, &current, &other).await, StatusCode::BAD_REQUEST);
    assert_eq!(register(&app, &stale, &current).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        register(&app, &current, &json!({"keys": [], "quorum": 0})).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(status(&app).await, json!({"active": current, "pending": null}));
}

#[tokio::test]
async fn config_writes_wait_for_signing() {
    let signing_lock = Arc::new(Mutex::new(()));
    let (_directory, app, current) = setup(Arc::clone(&signing_lock)).await;
    let proposed = add_validator(&current);

    let signing = signing_lock.lock().await;
    let mut put = std::pin::pin!(register(&app, &current, &proposed));
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut put).await.is_err());
    assert_eq!(status(&app).await["pending"], Value::Null);
    drop(signing);
    assert_eq!(put.await, StatusCode::NO_CONTENT);

    let signing = signing_lock.lock().await;
    let request = Request::delete(PENDING).body(Body::empty()).unwrap();
    let mut delete = std::pin::pin!(app.clone().oneshot(request));
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut delete).await.is_err());
    assert_eq!(status(&app).await["pending"], proposed);
    drop(signing);
    assert_eq!(delete.await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await["pending"], Value::Null);
}
