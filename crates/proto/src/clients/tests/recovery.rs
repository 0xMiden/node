use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use prost::Message;
use prost::bytes::Bytes;

use super::super::{Builder, GrpcClient, RemoteProverProxyStatusClient, WantsConnection};
use crate::generated::miden::remote_prover::v1::{ProxyStatusRequest, ProxyStatusResponse};

#[derive(Clone, Copy, Debug)]
enum Stall {
    Handshake,
    Headers,
    Body,
    Trailers,
    Trickle,
}

/// Stalls the first connection at a selected response stage. Later connections reject requests with
/// an application status, proving that a fresh connection reached the server.
struct Server {
    url: url::Url,
    connections: Arc<AtomicUsize>,
    requests: tokio::sync::mpsc::UnboundedReceiver<usize>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(stall: Stall) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = connections.clone();
        let (events, requests) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let number = count.fetch_add(1, Ordering::SeqCst);
                let events = events.clone();
                tasks.spawn(serve_connection(socket, number, events, stall));
            }
        });
        Self { url, connections, requests, task }
    }

    fn builder(&self) -> Builder<WantsConnection> {
        Builder::new(self.url.clone())
            .without_tls()
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection()
    }

    fn client(&self, timeout: Duration) -> RemoteProverProxyStatusClient {
        self.builder().with_timeout(timeout).connect_lazy()
    }

    async fn request_received(&mut self, connection: usize) {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), self.requests.recv())
                .await
                .unwrap(),
            Some(connection),
        );
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Drives HTTP/2 while withholding application progress on the first connection.
async fn serve_connection(
    socket: tokio::net::TcpStream,
    number: usize,
    events: tokio::sync::mpsc::UnboundedSender<usize>,
    stall: Stall,
) {
    if number == 0 && matches!(stall, Stall::Handshake) {
        let _socket = &socket;
        std::future::pending::<()>().await;
    }
    let mut connection = h2::server::handshake(socket).await.unwrap();
    let mut pending = Vec::new();
    let mut streams = tokio::task::JoinSet::new();
    while let Some(Ok((request, mut response))) = connection.accept().await {
        let _ = events.send(number);
        let headers = http::Response::builder().header("content-type", "application/grpc");
        if request.uri().path() == "/miden.node.v1.NodeService/BlockSubscription" {
            let body = response.send_response(headers.body(()).unwrap(), false).unwrap();
            streams.spawn(subscription(body));
        } else if number == 0 {
            match stall {
                Stall::Body | Stall::Trailers => {
                    let mut body =
                        response.send_response(headers.body(()).unwrap(), false).unwrap();
                    if matches!(stall, Stall::Trailers) {
                        body.send_data(grpc_frame(&ProxyStatusResponse::default()), false).unwrap();
                    }
                    pending.push((request, response, Some(body)));
                    continue;
                },
                Stall::Trickle => {
                    streams.spawn(async move {
                        // Spend part of the budget before headers, then deliver a valid message
                        // slowly enough that a single total deadline must interrupt its body.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let mut body =
                            response.send_response(headers.body(()).unwrap(), false).unwrap();
                        let frame = grpc_frame(&ProxyStatusResponse {
                            version: "a slowly delivered response".to_owned(),
                            ..Default::default()
                        });
                        for byte in frame {
                            if body.send_data(Bytes::from(vec![byte]), false).is_err() {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(30)).await;
                        }
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        let _ = body.send_trailers(trailers);
                    });
                    continue;
                },
                Stall::Handshake | Stall::Headers => {},
            }
            pending.push((request, response, None));
        } else {
            // Even an application Cancelled response must preserve the connection.
            let headers = headers
                .header("grpc-status", "1")
                .header("grpc-message", "application rejection");
            response.send_response(headers.body(()).unwrap(), true).unwrap();
        }
    }
}

fn grpc_frame(message: &impl Message) -> Bytes {
    let payload = message.encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Bytes::from(frame)
}

async fn subscription(mut body: h2::SendStream<Bytes>) {
    use crate::generated::miden::node::v1::BlockSubscriptionResponse;

    for block in [42, 43] {
        let event = BlockSubscriptionResponse {
            committed_chain_tip: block,
            ..Default::default()
        };
        if body.send_data(grpc_frame(&event), false).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    let _ = body.send_trailers(trailers);
}

async fn rejection(client: &mut RemoteProverProxyStatusClient) {
    let error = tokio::time::timeout(Duration::from_secs(5), client.status(ProxyStatusRequest {}))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Cancelled);
    assert_eq!(error.message(), "application rejection");
}

#[tokio::test]
async fn omitted_timeout_bounds_the_complete_response_and_recovers() {
    let server = Server::start(Stall::Body).await;
    let mut client = server.builder().connect_lazy::<RemoteProverProxyStatusClient>();
    let started = tokio::time::Instant::now();
    let error = tokio::time::timeout(Duration::from_secs(15), client.status(ProxyStatusRequest {}))
        .await
        .expect("the default deadline must bound the body")
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    assert!(started.elapsed() >= crate::clients::DEFAULT_REQUEST_TIMEOUT);
    rejection(&mut client).await;
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn timeouts_recover_across_clones_and_connection_modes() {
    for eager in [false, true] {
        for stall in [Stall::Handshake, Stall::Headers, Stall::Body, Stall::Trailers] {
            let server = Server::start(stall).await;
            let mut builder = server.builder().with_timeout(Duration::from_millis(200));
            if !matches!(stall, Stall::Handshake) {
                // PING failures would surface before the RPC deadline. After the handshake, the
                // server keeps acknowledging PINGs while withholding the application response.
                builder.endpoint = builder
                    .endpoint
                    .http2_keep_alive_interval(Duration::from_millis(10))
                    .keep_alive_timeout(Duration::from_millis(50));
            }
            let mut client = if eager {
                builder.connect::<RemoteProverProxyStatusClient>().await.unwrap()
            } else {
                builder.connect_lazy::<RemoteProverProxyStatusClient>()
            };
            let mut cloned = client.clone();
            let error =
                tokio::time::timeout(Duration::from_secs(5), client.status(ProxyStatusRequest {}))
                    .await
                    .unwrap()
                    .unwrap_err();
            assert_eq!(
                error.code(),
                tonic::Code::DeadlineExceeded,
                "{stall:?}, eager={eager}: {error}"
            );
            assert!(!miden_node_utils::retry::is_retryable_grpc_error(&error));
            assert_eq!(server.connections.load(Ordering::SeqCst), 1);
            rejection(&mut cloned).await;
            rejection(&mut client).await;
            assert_eq!(server.connections.load(Ordering::SeqCst), 2);
        }
    }
}

#[tokio::test]
async fn clone_override_and_partial_data_preserve_the_original_deadline() {
    let server = Server::start(Stall::Trickle).await;
    let mut original = server.client(Duration::from_millis(200));
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        original
            .clone()
            .with_timeout(Duration::from_secs(3))
            .status(ProxyStatusRequest {}),
    )
    .await
    .unwrap()
    .unwrap()
    .into_inner();
    assert_eq!(response.version, "a slowly delivered response");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    let error =
        tokio::time::timeout(Duration::from_secs(1), original.status(ProxyStatusRequest {}))
            .await
            .expect("the original budget must remain unchanged")
            .unwrap_err();
    assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    rejection(&mut original).await;
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cancellation_does_not_replace_the_channel() {
    for stall in [Stall::Headers, Stall::Body] {
        let mut server = Server::start(stall).await;
        let mut client = server.client(Duration::from_secs(5));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.status(ProxyStatusRequest {}))
                .await
                .is_err()
        );
        server.request_received(0).await;
        let call = tokio::spawn(async move { client.status(ProxyStatusRequest {}).await });
        server.request_received(0).await;
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn late_timeout_does_not_retire_a_replacement() {
    let mut server = Server::start(Stall::Body).await;
    let mut client = server.client(Duration::from_millis(400));
    let first = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .with_timeout(Duration::from_millis(200))
                .status(ProxyStatusRequest {})
                .await
        }
    });
    server.request_received(0).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = tokio::spawn({
        let mut client = client.clone();
        async move { client.status(ProxyStatusRequest {}).await }
    });
    server.request_received(0).await;
    assert_eq!(first.await.unwrap().unwrap_err().code(), tonic::Code::DeadlineExceeded);
    rejection(&mut client).await;
    assert_eq!(second.await.unwrap().unwrap_err().code(), tonic::Code::DeadlineExceeded);
    rejection(&mut client).await;
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn quiet_subscription_survives_another_calls_timeout() {
    use super::super::RpcClient;
    use crate::generated::miden::node::v1::{BlockSubscriptionRequest, StatusRequest};

    let server = Server::start(Stall::Headers).await;
    let mut client = server
        .builder()
        .with_timeout(Duration::from_millis(100))
        .connect_lazy::<RpcClient>();
    let mut stream = client
        .block_subscription(BlockSubscriptionRequest { block_from: 42 })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(stream.message().await.unwrap().unwrap().committed_chain_tip, 42);
    assert_eq!(
        client.status(StatusRequest {}).await.unwrap_err().code(),
        tonic::Code::DeadlineExceeded
    );
    assert_eq!(
        client.status(StatusRequest {}).await.unwrap_err().message(),
        "application rejection"
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    // The original stream remains usable after the timeout replaces its shared channel.
    let event = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(event.committed_chain_tip, 43);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
}
