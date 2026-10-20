use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_node_proto::generated::miden::validator::v1::SignBlockRequest;
use tracing_subscriber::util::SubscriberInitExt;

use super::{BlockProducerValidatorClient, ValidatorError};

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
