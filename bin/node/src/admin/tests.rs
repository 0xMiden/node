use axum::body::{Body, to_bytes};
use axum::http::Request;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;

const INVITATION_DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn setup() -> (tempfile::TempDir, Arc<AccountAllowlist>, Router) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("allowlist.sqlite3");
    AccountAllowlist::bootstrap(&path).unwrap();
    let allowlist = Arc::new(AccountAllowlist::load(path).unwrap());
    let app = router(Arc::clone(&allowlist), None);
    (dir, allowlist, app)
}

fn account(index: usize) -> AccountId {
    [ACCOUNT_ID_PRIVATE_SENDER, ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE][index]
        .try_into()
        .unwrap()
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder().method(method).uri(path);
    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8(bytes.to_vec()).unwrap()))
    };
    (status, body)
}

#[tokio::test]
async fn admin_registration_workflow() {
    let (_dir, allowlist, _) = setup();
    let rejected: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
    let funding_api = Router::new().route(
        "/funding/request-funds",
        axum::routing::post(move |Json(body): Json<Value>| {
            let status = if body["account_id"] == rejected.to_hex() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            };
            requests.send(body).unwrap();
            async move { status }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url =
        url::Url::parse(&format!("http://{}/funding", listener.local_addr().unwrap())).unwrap();
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, funding_api)
            .with_graceful_shutdown(server_shutdown.cancelled_owned())
            .await
            .unwrap();
    });
    let funding = FundingClient::new(url, std::num::NonZeroU64::new(42).unwrap()).unwrap();
    let app = router(Arc::clone(&allowlist), Some(funding));
    let path = format!("/admin/allowlist/invitations/{INVITATION_DIGEST}");
    let (status, body) = request(&app, "GET", &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"status": "unknown", "account_id": null, "allowlisted_at": null}));

    assert_eq!(
        request(&app, "PUT", &path, Some(json!({}))).await,
        (StatusCode::CREATED, Value::Null)
    );
    let (_, unused) = request(&app, "GET", &path, None).await;
    assert_eq!(unused["status"], "unused");
    assert!(unused["allowlisted_at"].as_i64().unwrap() > 0);

    let bound = json!({"account_id": account(0).to_string()});
    assert_eq!(request(&app, "PUT", &path, Some(bound.clone())).await.0, StatusCode::NO_CONTENT);
    assert_eq!(request(&app, "PUT", &path, Some(bound)).await.0, StatusCode::NO_CONTENT);
    assert_eq!(request(&app, "PUT", &path, Some(json!({}))).await.0, StatusCode::NO_CONTENT);
    let (_, registered) = request(&app, "GET", &path, None).await;
    assert_eq!(registered["status"], "registered");
    assert_eq!(registered["account_id"], account(0).to_string());
    assert_eq!(registered["allowlisted_at"], unused["allowlisted_at"]);
    assert!(registered.get("invitation_code").is_none());
    assert_eq!(
        allowlist.invitation_status(InvitationCode::new("abc").unwrap()).await.unwrap(),
        miden_node_store::allowlist::InvitationStatus::Registered(account(0))
    );

    let account_path = format!("/admin/allowlist/accounts/{}", account(1));
    assert_eq!(
        request(&app, "PUT", &account_path, None).await,
        (StatusCode::CREATED, Value::Null)
    );
    assert_eq!(
        request(&app, "PUT", &account_path, None).await,
        (StatusCode::NO_CONTENT, Value::Null)
    );
    let (status, info) = request(&app, "GET", &account_path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["account_id"], account(1).to_string());
    assert_eq!(
        info["allowlisted_at"].as_i64(),
        allowlist.allowlisted_at(account(1)).await.unwrap()
    );

    let path = format!("/admin/allowlist/invitations/{}", "00".repeat(32));
    let body = json!({"account_id": rejected.to_hex()});
    let (status, error) = request(&app, "PUT", &path, Some(body.clone())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(error["error"].as_str().unwrap().contains("400 Bad Request"));
    assert!(allowlist.contains_account(rejected).await.unwrap());
    assert_eq!(request(&app, "PUT", &path, Some(body)).await.0, StatusCode::NO_CONTENT);

    for account in [account(0), account(1), rejected] {
        assert_eq!(
            received.try_recv().unwrap(),
            json!({"account_id": account.to_hex(), "amount": 42})
        );
    }
    assert!(matches!(
        received.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    shutdown.cancel();
    server.await.unwrap();
}

#[tokio::test]
async fn database_failures_include_the_cause() {
    let (dir, _allowlist, app) = setup();
    fs_err::remove_file(dir.path().join("allowlist.sqlite3")).unwrap();

    for (path, body) in [
        (format!("/admin/allowlist/accounts/{}", account(0)), None),
        (format!("/admin/allowlist/invitations/{INVITATION_DIGEST}"), Some(json!({}))),
    ] {
        for method in ["GET", "PUT"] {
            let (status, response) = request(&app, method, &path, body.clone()).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            let error = response["error"].as_str().unwrap();
            assert!(error.contains("unable to open database file"), "{error}");
        }
    }
}

#[tokio::test]
async fn invalid_and_conflicting_requests_leave_no_changes() {
    let (_dir, _allowlist, app) = setup();
    for digest in ["abc".to_owned(), "g".repeat(64), "00".repeat(33)] {
        let path = format!("/admin/allowlist/invitations/{digest}");
        assert_eq!(request(&app, "GET", &path, None).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(request(&app, "PUT", &path, Some(json!({}))).await.0, StatusCode::BAD_REQUEST);
    }

    let path = format!("/admin/allowlist/invitations/{INVITATION_DIGEST}");
    assert_eq!(
        request(&app, "PUT", &path, Some(json!({"account_id": "invalid"}))).await,
        (
            StatusCode::BAD_REQUEST,
            json!({"error": "account_id must be a valid hex account ID"})
        )
    );
    assert_eq!(
        request(&app, "PUT", &path, Some(json!({"invitation_code": "abc"}))).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        request(&app, "PUT", "/admin/allowlist/accounts/invalid", None).await.0,
        StatusCode::BAD_REQUEST
    );
    let account_path = format!("/admin/allowlist/accounts/{}", account(0));
    assert_eq!(request(&app, "GET", &account_path, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(request(&app, "PUT", &account_path, None).await.0, StatusCode::CREATED);

    let conflict = json!({"account_id": account(0).to_string()});
    assert_eq!(
        request(&app, "PUT", &path, Some(conflict.clone())).await,
        (
            StatusCode::CONFLICT,
            json!({"error": format!("account {} is already registered", account(0))})
        )
    );
    let (_, unknown) = request(&app, "GET", &path, None).await;
    assert_eq!(
        unknown,
        json!({"status": "unknown", "account_id": null, "allowlisted_at": null})
    );

    assert_eq!(
        request(&app, "PUT", &path, Some(json!({"account_id": account(1).to_string()})))
            .await
            .0,
        StatusCode::CREATED
    );
    let (_, registered) = request(&app, "GET", &path, None).await;
    assert_eq!(request(&app, "PUT", &path, Some(conflict)).await.0, StatusCode::CONFLICT);
    assert_eq!(request(&app, "GET", &path, None).await.1, registered);
    assert_eq!(
        request(&app, "POST", &path, Some(json!({}))).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}
