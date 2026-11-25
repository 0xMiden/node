use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::to_bytes;
use axum::http::{Method, StatusCode};
use axum::{Json, Router};
use miden_node_store::allowlist::InvitationCode;
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::*;

struct TestAdmin {
    url: Url,
    requests: mpsc::UnboundedReceiver<(Method, String, Value)>,
    task: tokio::task::JoinHandle<()>,
}

impl TestAdmin {
    async fn start(fail_at: Option<usize>) -> Self {
        let (sender, requests) = mpsc::unbounded_channel();
        let count = Arc::new(AtomicUsize::new(0));
        let app = Router::new().fallback(move |request: axum::extract::Request| {
            let sender = sender.clone();
            let count = Arc::clone(&count);
            async move {
                let method = request.method().clone();
                let path = request.uri().path_and_query().unwrap().as_str().to_owned();
                let body = to_bytes(request.into_body(), usize::MAX).await.unwrap();
                let body = if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&body).unwrap()
                };
                let quorum_status = method == Method::GET && path.ends_with("/validator-config");
                sender.send((method, path, body)).unwrap();
                if fail_at == Some(count.fetch_add(1, Ordering::Relaxed) + 1) {
                    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "maintenance"})))
                } else if quorum_status {
                    (
                        StatusCode::OK,
                        Json(json!({"active": 3, "pending": null, "activation_height": null})),
                    )
                } else {
                    (StatusCode::CREATED, Json(json!({})))
                }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/proxy", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, requests, task }
    }
}

impl Drop for TestAdmin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn exports_codes_and_uploads_digests() {
    let mut server = TestAdmin::start(None).await;
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("invitations.csv");
    AdminCommand {
        url: server.url.clone(),
        action: AdminAction::CreateInvites(CreateInvitesCommand {
            count: NonZeroUsize::new(10).unwrap(),
            output: output.clone(),
        }),
    }
    .handle()
    .await
    .unwrap();

    let csv = fs_err::read_to_string(&output).unwrap();
    let mut rows = csv.lines();
    assert_eq!(rows.next(), Some("invitation_code"));
    let mut codes = BTreeSet::new();
    for code in rows {
        assert_eq!(code.len(), 12);
        assert!(code.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert!(codes.insert(code.to_owned()));
        let (method, path, body) = server.requests.try_recv().unwrap();
        assert_eq!(method, Method::PUT);
        assert_eq!(
            path,
            format!(
                "/proxy/admin/allowlist/invitations/{}",
                InvitationCode::new(code).unwrap().to_hex_digest()
            )
        );
        assert_eq!(body, json!({}));
    }
    assert_eq!(codes.len(), 10);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs_err::metadata(&output).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(server.requests.try_recv().is_err());
}

#[tokio::test]
async fn directly_allowlists_an_account() {
    let mut server = TestAdmin::start(None).await;
    let account_id: AccountId = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    AdminCommand {
        url: server.url.clone(),
        action: AdminAction::AllowlistAccount { account_id },
    }
    .handle()
    .await
    .unwrap();
    let (method, path, body) = server.requests.try_recv().unwrap();
    assert_eq!(method, Method::PUT);
    assert_eq!(path, format!("/proxy/admin/allowlist/accounts/{}", account_id.to_hex()));
    assert_eq!(body, Value::Null);
    assert!(server.requests.try_recv().is_err());
}

#[tokio::test]
async fn upload_failure_preserves_csv_and_existing_files_are_not_overwritten() {
    let mut server = TestAdmin::start(Some(2)).await;
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("invitations.csv");
    let client = AdminClient::new(server.url.clone()).unwrap();
    let error = CreateInvitesCommand {
        count: NonZeroUsize::new(5).unwrap(),
        output: output.clone(),
    }
    .handle(&client)
    .await
    .unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("invitation 2 of 5"), "{error}");
    assert!(error.contains("503 Service Unavailable"), "{error}");
    assert!(error.contains("maintenance"), "{error}");
    assert_eq!(fs_err::read_to_string(&output).unwrap().lines().skip(1).count(), 5);
    server.requests.try_recv().unwrap();
    server.requests.try_recv().unwrap();
    assert!(server.requests.try_recv().is_err());

    let original = fs_err::read(&output).unwrap();
    assert!(
        CreateInvitesCommand {
            count: NonZeroUsize::new(5).unwrap(),
            output: output.clone(),
        }
        .handle(&client)
        .await
        .is_err()
    );
    assert_eq!(fs_err::read(&output).unwrap(), original);
    assert!(server.requests.try_recv().is_err());
}

#[tokio::test]
async fn quorum_commands_send_the_same_change_file() {
    use clap::Parser;

    let mut server = TestAdmin::start(None).await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("change.json");
    let change = json!({"active":3,"pending":2});
    fs_err::write(&file, change.to_string()).unwrap();
    for (action, expected) in [("register", Method::PUT), ("cancel", Method::DELETE)] {
        let cli = crate::Cli::try_parse_from([
            "miden-node",
            "admin",
            "--url",
            server.url.as_str(),
            "validator-config",
            action,
            file.to_str().unwrap(),
            "--activation-height",
            "1000",
        ])
        .unwrap();
        let crate::commands::Command::Admin(command) = cli.command else {
            panic!("expected admin command")
        };
        command.handle().await.unwrap();
        let (method, path, body) = server.requests.try_recv().unwrap();
        assert_eq!(method, expected);
        assert_eq!(path, "/proxy/admin/v1/validator-config/pending?activation_height=1000");
        assert_eq!(body, change);
    }
    let status = AdminClient::new(server.url.clone())
        .unwrap()
        .validator_config_status()
        .await
        .unwrap();
    assert_eq!(status, json!({"active":3,"pending":null,"activation_height":null}));
    let (method, path, body) = server.requests.try_recv().unwrap();
    assert_eq!(method, Method::GET);
    assert_eq!(path, "/proxy/admin/v1/validator-config");
    assert_eq!(body, Value::Null);
    assert_eq!(fs_err::read_to_string(file).unwrap(), change.to_string());
}

#[tokio::test]
async fn quorum_command_reports_server_errors_and_keeps_the_file() {
    use clap::Parser;

    let server = TestAdmin::start(Some(1)).await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("change.json");
    let original = "{\"active\":3,\"pending\":2}";
    fs_err::write(&file, original).unwrap();
    let cli = crate::Cli::try_parse_from([
        "miden-node",
        "admin",
        "--url",
        server.url.as_str(),
        "validator-config",
        "cancel",
        file.to_str().unwrap(),
        "--activation-height",
        "1000",
    ])
    .unwrap();
    let crate::commands::Command::Admin(command) = cli.command else {
        panic!("expected admin command")
    };
    let error = command.handle().await.unwrap_err().to_string();
    assert!(error.contains("503 Service Unavailable"), "{error}");
    assert!(error.contains("maintenance"), "{error}");
    assert_eq!(fs_err::read_to_string(file).unwrap(), original);
}

#[test]
fn quorum_mutations_require_a_valid_activation_height() {
    use clap::Parser;

    for action in ["register", "cancel"] {
        let args = [
            "miden-node",
            "admin",
            "--url",
            "http://localhost",
            "validator-config",
            action,
            "change.json",
        ];
        assert!(crate::Cli::try_parse_from(args).is_err());
        for height in ["0", "1", "4294967296"] {
            assert!(
                crate::Cli::try_parse_from(args.into_iter().chain(["--activation-height", height]))
                    .is_err()
            );
        }
    }
}
