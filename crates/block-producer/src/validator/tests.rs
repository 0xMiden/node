use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_node_proto::generated::miden::validator::v1::SignBlockRequest;
use miden_node_proto::generated::submission::ProvenTransactionSubmission;
use tracing_subscriber::util::SubscriberInitExt;

use super::{BlockProducerValidatorClient, ValidatorError};

#[tokio::test]
#[serial_test::serial(validator_tracing)]
async fn validator_calls_recover_from_connection_retirement() {
    for cancel_stream in [false, true] {
        for sign_block in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
            let server = tokio::spawn(async move {
                for attempt in 0..2 {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut connection = h2::server::handshake(socket).await.unwrap();
                    let (_, mut response) = connection.accept().await.unwrap().unwrap();
                    if attempt == 0 {
                        // Retire an in-flight connection as an HTTP/2 proxy can.
                        if cancel_stream {
                            response.send_reset(h2::Reason::CANCEL);
                            connection.graceful_shutdown();
                        } else {
                            connection.abrupt_shutdown(h2::Reason::NO_ERROR);
                        }
                    } else {
                        // A terminal application response proves the retry reached the server.
                        let headers = tonic::codegen::http::Response::builder()
                            .header("content-type", "application/grpc")
                            .header("grpc-status", "3")
                            .header("grpc-message", "rejected by validator")
                            .body(())
                            .unwrap();
                        response.send_response(headers, true).unwrap();
                        connection.graceful_shutdown();
                    }
                    while connection.accept().await.is_some() {}
                }
            });
            let client = BlockProducerValidatorClient::new(
                vec![url],
                Duration::from_secs(1),
                miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
            )
            .unwrap();
            let validator = &client.validators[0];
            let error = tokio::time::timeout(Duration::from_secs(5), async {
                if sign_block {
                    match validator.sign_block(SignBlockRequest::default()).await {
                        Err(ValidatorError::Transport(error)) => error,
                        result => panic!("expected application rejection, got {result:?}"),
                    }
                } else {
                    validator
                        .submit_proven_transaction(ProvenTransactionSubmission::default())
                        .await
                        .unwrap_err()
                }
            })
            .await
            .unwrap();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert_eq!(error.message(), "rejected by validator");
            tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
        }
    }
}

#[tokio::test]
#[serial_test::serial(validator_tracing)]
async fn validator_timeouts_are_not_retried() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn({
        let requests = Arc::clone(&requests);
        async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            // Hold every request open without responding, as an unresponsive validator would.
            let mut pending = Vec::new();
            while let Some(Ok(stream)) = connection.accept().await {
                requests.fetch_add(1, Ordering::SeqCst);
                pending.push(stream);
            }
        }
    });
    let client = BlockProducerValidatorClient::new(
        vec![url],
        Duration::from_millis(100),
        miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
    )
    .unwrap();

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.validators[0].submit_proven_transaction(ProvenTransactionSubmission::default()),
    )
    .await
    .unwrap()
    .unwrap_err();

    assert_eq!(error.code(), tonic::Code::Cancelled);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    server.abort();
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
#[serial_test::serial(validator_tracing)]
async fn connection_errors_identify_each_validator_endpoint() {
    // Listeners reserve distinct ports and are closed before use, so connections are refused.
    let listeners = [
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let endpoints: Vec<_> = listeners
        .iter()
        .map(|listener| format!("http://{}/", listener.local_addr().unwrap()))
        .collect();
    drop(listeners);
    let client = BlockProducerValidatorClient::new(
        endpoints.iter().map(|endpoint| endpoint.parse().unwrap()).collect(),
        Duration::from_secs(1),
        miden_node_utils::grpc::DEFAULT_MAX_DECODING_MESSAGE_SIZE,
    )
    .unwrap();
    let capture = Capture::default();
    let writer = capture.clone();
    // The test runtime is single-threaded, so the thread-local subscriber sees every span.
    let _subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish()
        .set_default();

    let results = futures::future::join_all(
        client
            .validators
            .iter()
            .map(|validator| validator.sign_block(SignBlockRequest::default())),
    )
    .await;

    for result in results {
        assert!(matches!(result, Err(ValidatorError::Transport(status))
            if status.code() == tonic::Code::Unavailable));
    }
    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let errors: Vec<_> = output.lines().filter(|line| line.contains("ERROR")).collect();
    assert_eq!(errors.len(), 2, "{output}");
    for endpoint in endpoints {
        let matching: Vec<_> = errors.iter().filter(|line| line.contains(&endpoint)).collect();
        assert_eq!(matching.len(), 1, "{output}");
        assert!(matching[0].contains("validator.client.sign_block"), "{output}");
        assert!(matching[0].contains("dependency.name=\"validator\""), "{output}");
        assert!(matching[0].contains("dependency.endpoint="), "{output}");
        assert!(matching[0].contains("gRPC transport error"), "{output}");
    }
}
