use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use miden_protocol::block::{BlockHeader, ValidatorConfig};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::protocol_config::ProtocolConfig;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt;

use super::test_database;
use crate::db::{ValidatorDbWriter, block_with_header};
use crate::server::admin_service::validator_config::router;

const STATUS: &str = "/admin/v1/validator-config";
const PENDING: &str = "/admin/v1/validator-config/pending";

async fn setup(
    signing_lock: Arc<Mutex<()>>,
) -> (tempfile::TempDir, ValidatorDbWriter, Router, u16) {
    let (directory, db, _) = test_database().await;
    let config =
        ValidatorConfig::new((0..3).map(|_| SigningKey::new().public_key()).collect(), 3).unwrap();
    store_config(&db, &BlockHeader::mock(0, None, None, &[]), &config).await;
    let app = router(&db, signing_lock);
    (directory, db, app, 3)
}

fn change_request(method: Method, active: u16, pending: u16) -> Request<Body> {
    let body = json!({"active": active, "pending": pending});
    Request::builder()
        .method(method)
        .uri(PENDING)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn register(app: &Router, active: u16, pending: u16) -> StatusCode {
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
    let (_directory, _db, app, active) = setup(Arc::default()).await;
    let responses = tokio::join!(register(&app, active, 1), register(&app, active, 2));
    let pending = match responses {
        (StatusCode::NO_CONTENT, StatusCode::CONFLICT) => 1,
        (StatusCode::CONFLICT, StatusCode::NO_CONTENT) => 2,
        _ => panic!("unexpected registration responses: {responses:?}"),
    };
    assert_eq!(register(&app, active, pending).await, StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await, json!({"active": active, "pending": pending}));

    let cancel = change_request(Method::DELETE, active, pending);
    assert_eq!(app.clone().oneshot(cancel).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await, json!({"active": active, "pending": null}));
}

#[tokio::test]
async fn rejected_changes_leave_no_pending_quorum() {
    let (_directory, _db, app, active) = setup(Arc::default()).await;
    assert_eq!(register(&app, 2, 1).await, StatusCode::CONFLICT);
    for (active, pending) in [(active, active), (active, 0), (0, 1), (active, 4)] {
        assert_eq!(register(&app, active, pending).await, StatusCode::BAD_REQUEST);
    }
    let keys = Request::put(PENDING)
        .header("Content-Type", "application/json")
        .body(Body::from(json!({"active": active, "pending": 2, "keys": []}).to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(keys).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(status(&app).await, json!({"active": active, "pending": null}));
}

#[tokio::test]
async fn config_writes_wait_for_signing() {
    let signing_lock = Arc::new(Mutex::new(()));
    let (_directory, _db, app, active) = setup(Arc::clone(&signing_lock)).await;
    let pending = 2;

    let signing = signing_lock.lock().await;
    let mut put = std::pin::pin!(register(&app, active, pending));
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut put).await.is_err());
    assert_eq!(status(&app).await["pending"], Value::Null);
    drop(signing);
    assert_eq!(put.await, StatusCode::NO_CONTENT);

    let signing = signing_lock.lock().await;
    let request = change_request(Method::DELETE, active, pending);
    let mut delete = std::pin::pin!(app.clone().oneshot(request));
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut delete).await.is_err());
    assert_eq!(status(&app).await["pending"], pending);
    drop(signing);
    assert_eq!(delete.await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await["pending"], Value::Null);
}

#[tokio::test]
async fn cancel_rejects_a_different_or_missing_pending_change() {
    let (_directory, _db, app, active) = setup(Arc::default()).await;
    let pending = 2;
    let request = change_request(Method::DELETE, active, pending);
    assert_eq!(app.clone().oneshot(request).await.unwrap().status(), StatusCode::CONFLICT);
    assert_eq!(register(&app, active, pending).await, StatusCode::NO_CONTENT);
    let different = change_request(Method::DELETE, active, 1);
    assert_eq!(app.clone().oneshot(different).await.unwrap().status(), StatusCode::CONFLICT);
    let missing = Request::delete(PENDING).body(Body::empty()).unwrap();
    assert!(!app.clone().oneshot(missing).await.unwrap().status().is_success());
    assert_eq!(status(&app).await, json!({"active": active, "pending": pending}));
}

async fn store_config(db: &ValidatorDbWriter, parent: &BlockHeader, config: &ValidatorConfig) {
    let header = BlockHeader::new(
        parent.commitment(),
        parent.block_num().child(),
        parent.chain_commitment(),
        parent.account_root(),
        parent.nullifier_root(),
        parent.note_root(),
        parent.tx_commitment(),
        config.clone(),
        parent.fee_parameters().clone(),
        parent.protocol_config_commitment(),
        parent.next_protocol_config().cloned(),
        parent.timestamp(),
    );
    db.replace_legacy_signed_block(block_with_header(header), ProtocolConfig::mock(), vec![])
        .await
        .unwrap();
}

#[tokio::test]
async fn restored_transition_blocks_cancellation_until_replaced() {
    let (directory, db, app, active) = setup(Arc::default()).await;
    let parent = db.load_chain_tip().await.unwrap().unwrap();
    let pending = 2;
    let config =
        ValidatorConfig::new(parent.validator_config().keys()[..2].to_vec(), pending).unwrap();
    assert_eq!(register(&app, active, pending).await, StatusCode::NO_CONTENT);
    store_config(&db, &parent, &config).await;
    assert_eq!(status(&app).await, json!({"active": active, "pending": pending}));
    assert_eq!(register(&app, active, pending).await, StatusCode::NO_CONTENT);
    assert_eq!(register(&app, active, 1).await, StatusCode::CONFLICT);
    assert_eq!(register(&app, pending, 1).await, StatusCode::CONFLICT);

    let restarted = crate::db::load(directory.path().join("validator.sqlite3")).await.unwrap();
    let app = router(&restarted, Arc::default());
    assert_eq!(status(&app).await, json!({"active": active, "pending": pending}));
    let request = change_request(Method::DELETE, active, pending);
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let message = to_bytes(response.into_body(), 65536).await.unwrap();
    assert!(std::str::from_utf8(&message).unwrap().contains("already signed"));

    store_config(&db, &parent, parent.validator_config()).await;
    let request = change_request(Method::DELETE, active, pending);
    assert_eq!(app.clone().oneshot(request).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(status(&app).await, json!({"active": active, "pending": null}));
}

#[tokio::test]
async fn confirmed_change_is_already_active_when_cancelled() {
    let (_directory, db, app, active) = setup(Arc::default()).await;
    let parent = db.load_chain_tip().await.unwrap().unwrap();
    let pending = 2;
    let config =
        ValidatorConfig::new(parent.validator_config().keys()[..2].to_vec(), pending).unwrap();
    store_config(&db, &parent, &config).await;
    let transition = db.load_chain_tip().await.unwrap().unwrap();
    assert_eq!(register(&app, active, 1).await, StatusCode::CONFLICT);
    store_config(&db, &transition, &config).await;
    assert_eq!(status(&app).await, json!({"active": pending, "pending": null}));
    let request = change_request(Method::DELETE, active, pending);
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let message = to_bytes(response.into_body(), 65536).await.unwrap();
    assert!(std::str::from_utf8(&message).unwrap().contains("already active"));
}
