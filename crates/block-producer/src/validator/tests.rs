use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

extern crate tracing as upstream_tracing;

use miden_node_proto::generated::miden::validator::v1::SignBlockRequest;
use upstream_tracing::instrument::WithSubscriber;

use super::{BlockProducerValidatorClient, ValidatorError, sign_block};

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
    // Bound sockets reserve distinct ports without listening, so connections are refused.
    let sockets = [
        tokio::net::TcpSocket::new_v4().unwrap(),
        tokio::net::TcpSocket::new_v4().unwrap(),
    ];
    for socket in &sockets {
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    }
    let endpoints: Vec<_> = sockets
        .iter()
        .map(|socket| format!("http://{}/", socket.local_addr().unwrap()))
        .collect();
    let client = BlockProducerValidatorClient::new(
        endpoints.iter().map(|endpoint| endpoint.parse().unwrap()).collect(),
        Duration::from_secs(1),
    )
    .unwrap();
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();

    let results = futures::future::join_all(client.clients.iter().map(|(endpoint, client)| {
        sign_block(client.clone(), endpoint, SignBlockRequest::default())
    }))
    .with_subscriber(subscriber)
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
