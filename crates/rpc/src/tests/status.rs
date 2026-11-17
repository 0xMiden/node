use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::routing::post;
use http::Response;
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::generated::miden::node::v1::node_service_server::NodeService;
use miden_node_proto::generated::miden::node::v1::{
    BlockProducerStatus,
    MempoolStats,
    StatusRequest,
    StatusResponse,
};
use miden_node_proto::prost::Message;
use miden_node_utils::shutdown::CancellationToken;
use tokio::net::TcpListener;
use tonic::{Code, Request};

use super::{TestServerGuard, TestStore, next_block_with_protocol_config};
use crate::server::RpcBackend;
use crate::server::api::RpcService;

#[derive(Clone)]
struct Upstream {
    response: Arc<Mutex<Result<BlockProducerStatus, Code>>>,
    calls: Arc<AtomicUsize>,
}

impl Upstream {
    async fn start(status: BlockProducerStatus) -> (Self, RpcClient, TestServerGuard) {
        let upstream = Self {
            response: Arc::new(Mutex::new(Ok(status))),
            calls: Arc::default(),
        };
        let handler = upstream.clone();
        let router = Router::new().route(
            "/miden.node.v1.NodeService/Status",
            post(move || {
                let handler = handler.clone();
                async move {
                    handler.calls.fetch_add(1, Ordering::SeqCst);
                    let response = handler.response.lock().unwrap().clone();
                    let (code, body) = match response {
                        Ok(status) => {
                            let payload = StatusResponse {
                                block_producer: Some(status),
                                ..Default::default()
                            }
                            .encode_to_vec();
                            let mut body = vec![0];
                            body.extend_from_slice(
                                &u32::try_from(payload.len()).unwrap().to_be_bytes(),
                            );
                            body.extend(payload);
                            (Code::Ok, body)
                        },
                        Err(code) => (code, vec![]),
                    };
                    Response::builder()
                        .header("content-type", "application/grpc")
                        .header("grpc-status", (code as i32).to_string())
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .unwrap();
        });
        let client = Builder::new(url)
            .without_tls()
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection()
            .connect_lazy();
        (upstream, client, TestServerGuard(shutdown))
    }
}

fn upstream_status(chain_tip: u32) -> BlockProducerStatus {
    BlockProducerStatus {
        status: "connected".to_owned(),
        version: "upstream-version".to_owned(),
        chain_tip,
        mempool_stats: Some(MempoolStats::default()),
    }
}

fn full_node(store: &TestStore, source: RpcClient) -> RpcService {
    let mut rpc = RpcService::new(
        store.state.clone(),
        RpcBackend::full_node(source, None),
        None,
        NonZeroUsize::new(100).unwrap(),
        None,
    );
    rpc.set_genesis_commitment(store.genesis_commitment()).unwrap();
    rpc
}

async fn status(rpc: &RpcService) -> StatusResponse {
    rpc.status(Request::new(StatusRequest {})).await.unwrap().into_inner()
}

#[tokio::test]
async fn upstream_status_is_shared_by_concurrent_probes_and_refreshed_after_five_seconds() {
    let expected = upstream_status(10);
    let (upstream, client, _server) = Upstream::start(expected.clone()).await;
    let store = TestStore::start().await;
    let rpc = full_node(&store, client);
    let responses = futures::future::join_all((0..20).map(|_| status(&rpc))).await;
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    for response in responses {
        assert_eq!(response.block_producer.as_ref(), Some(&expected));
    }

    *upstream.response.lock().unwrap() = Ok(upstream_status(11));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;
    assert_eq!(status(&rpc).await.block_producer, Some(expected));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::time::resume();
    assert_eq!(status(&rpc).await.block_producer, Some(upstream_status(11)));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn upstream_failures_replace_stale_status_and_are_cached_until_retry() {
    let (upstream, client, _server) = Upstream::start(upstream_status(10)).await;
    let store = TestStore::start().await;
    let rpc = full_node(&store, client);
    assert_eq!(status(&rpc).await.block_producer, Some(upstream_status(10)));

    *upstream.response.lock().unwrap() = Err(Code::Unavailable);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::resume();
    assert_eq!(status(&rpc).await.block_producer.unwrap().status, "unreachable");
    let responses = futures::future::join_all((0..20).map(|_| status(&rpc))).await;
    assert!(
        responses
            .iter()
            .all(|response| response.block_producer.as_ref().unwrap().status == "unreachable")
    );
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);

    *upstream.response.lock().unwrap() = Ok(upstream_status(12));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::resume();
    assert_eq!(status(&rpc).await.block_producer, Some(upstream_status(12)));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn cached_upstream_status_does_not_cache_the_local_chain_tip() {
    let (upstream, client, _server) = Upstream::start(upstream_status(10)).await;
    let mut store = TestStore::start().await;
    let rpc = full_node(&store, client);
    let before = status(&rpc).await;

    let view = store.state.view();
    let (genesis, _) = view.get_block_header(None, false).await.unwrap();
    let config = view
        .get_protocol_config(genesis.unwrap().protocol_config_commitment())
        .await
        .unwrap()
        .unwrap();
    let block = next_block_with_protocol_config(&store, &config).await;
    store.writer.apply_block(block, Some(config)).await.unwrap();
    let after = status(&rpc).await;

    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert_eq!(after.chain_tip, before.chain_tip + 1);
    assert_eq!(after.block_producer, before.block_producer);
    assert_eq!(after.genesis_commitment, before.genesis_commitment);
    assert_eq!(after.version, before.version);
}
