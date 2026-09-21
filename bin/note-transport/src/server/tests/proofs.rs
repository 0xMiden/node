use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_node_proto::generated::note_transport::SendNoteWithProofRequest;
use miden_node_proto::generated::rpc::{BlockHeaderByNumberRequest, BlockHeaderByNumberResponse};
use miden_node_proto::server::note_transport_api::SendNoteWithProof;
use miden_protocol::block::{BlockHeader, BlockNoteIndex, BlockNoteTree};
use miden_protocol::note::NoteInclusionProof;
use tonic::codegen::{BoxFuture, http};

use super::*;

type HeaderResponses = BTreeMap<u32, VecDeque<Result<BlockHeaderByNumberResponse, tonic::Status>>>;

#[derive(Clone)]
struct NodeRpc {
    responses: Arc<Mutex<HeaderResponses>>,
    delay: Duration,
    requests: Arc<Mutex<Vec<u32>>>,
}

impl tonic::server::NamedService for NodeRpc {
    const NAME: &'static str = "rpc.Api";
}

impl tonic::server::UnaryService<BlockHeaderByNumberRequest> for NodeRpc {
    type Response = BlockHeaderByNumberResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, request: Request<BlockHeaderByNumberRequest>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            // Return no header if the client asks for a different block or extra data.
            let request = request.into_inner();
            if request.include_mmr_proof.unwrap_or(false)
                || request.include_protocol_config.unwrap_or(false)
            {
                return Ok(tonic::Response::new(BlockHeaderByNumberResponse::default()));
            }
            let block_num = request.block_num.unwrap();
            this.requests.lock().unwrap().push(block_num);
            let response = {
                let mut responses = this.responses.lock().unwrap();
                match responses.get_mut(&block_num) {
                    Some(responses) if responses.len() > 1 => responses.pop_front().unwrap(),
                    Some(responses) => responses.front().unwrap().clone(),
                    None => Ok(BlockHeaderByNumberResponse::default()),
                }
            };
            tokio::time::sleep(this.delay).await;
            response.map(tonic::Response::new)
        })
    }
}

impl tower::Service<http::Request<tonic::body::Body>> for NodeRpc {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            if request.uri().path() != "/rpc.Api/GetBlockHeaderByNumber" {
                return Ok(tonic::Status::unimplemented("unknown method").into_http());
            }
            let codec = tonic_prost::ProstCodec::default();
            Ok(tonic::server::Grpc::new(codec).unary(this, request).await)
        })
    }
}

async fn node_rpc(
    response: Result<BlockHeaderByNumberResponse, tonic::Status>,
    delay: Duration,
) -> (url::Url, tokio::task::JoinHandle<()>) {
    node_rpc_at_block(response, delay, 42).await
}

async fn node_rpc_at_block(
    response: Result<BlockHeaderByNumberResponse, tonic::Status>,
    delay: Duration,
    block_num: u32,
) -> (url::Url, tokio::task::JoinHandle<()>) {
    let (url, task, _) = node_rpc_responses(BTreeMap::from([(block_num, response)]), delay).await;
    (url, task)
}

async fn node_rpc_responses(
    responses: BTreeMap<u32, Result<BlockHeaderByNumberResponse, tonic::Status>>,
    delay: Duration,
) -> (url::Url, tokio::task::JoinHandle<()>, Arc<Mutex<Vec<u32>>>) {
    let responses = responses
        .into_iter()
        .map(|(block, response)| (block, VecDeque::from([response])))
        .collect();
    node_rpc_script(responses, delay).await
}

async fn node_rpc_script(
    responses: HeaderResponses,
    delay: Duration,
) -> (url::Url, tokio::task::JoinHandle<()>, Arc<Mutex<Vec<u32>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let rpc = NodeRpc {
        responses: Arc::new(Mutex::new(responses)),
        delay,
        requests: requests.clone(),
    };
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(rpc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (url, task, requests)
}

fn fixture() -> (SendNoteWithProofRequest, BlockHeaderByNumberResponse) {
    fixture_at_block(42)
}

fn fixture_at_block(block_num: u32) -> (SendNoteWithProofRequest, BlockHeaderByNumberResponse) {
    fixture_for_note(block_num, note(1, 7))
}

fn fixture_for_note(
    block_num: u32,
    note: TransportNote,
) -> (SendNoteWithProofRequest, BlockHeaderByNumberResponse) {
    let header = note.header.clone().unwrap().decode_fields().unwrap().verify().unwrap();
    let index = BlockNoteIndex::new(3, 5).unwrap();
    let tree = BlockNoteTree::with_entries([(index, &header)]).unwrap();
    let proof =
        NoteInclusionProof::new(block_num.into(), index.leaf_index_value(), tree.open(index))
            .unwrap();
    let block = BlockHeader::mock(block_num, None, Some(tree.root()), &[]);
    (
        SendNoteWithProofRequest {
            note: Some(note),
            inclusion_proof: Some((&header.id(), &proof).into()),
        },
        BlockHeaderByNumberResponse {
            block_header: Some(block.into()),
            ..Default::default()
        },
    )
}

async fn fetched(server: &Server) -> FetchNotesResponse {
    FetchNotes::full(server, Request::new(FetchNotesRequest { tags: vec![7], cursor: None }))
        .await
        .unwrap()
}

#[tokio::test]
async fn rejects_public_note_without_storage_or_lookup() {
    let (request, response) = fixture_for_note(42, note_with_type(1, 7, NoteType::Public));
    let (url, upstream, requests) =
        node_rpc_responses(BTreeMap::from([(42, Ok(response))]), Duration::ZERO).await;
    let (_dir, server) = server(Config::new(url));
    let before = fetched(&server).await;
    let result = SendNoteWithProof::full(&server, Request::new(request)).await;
    upstream.abort();
    let error = result.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.message(), "only private notes are supported");
    assert_eq!(fetched(&server).await, before);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn verified_submission_stores_inclusion_block_and_preserves_duplicates() {
    let (request, response) = fixture();
    let (url, upstream) = node_rpc(Ok(response), Duration::ZERO).await;
    let (_dir, server) = server(Config::new(url));
    SendNoteWithProof::full(&server, Request::new(request.clone())).await.unwrap();
    let first = fetched(&server).await;
    assert_eq!(first.notes[0].after_block_num, None);
    let mut expected = fetched_note(request.note.clone().unwrap(), None);
    expected.committed_in_block = Some(BlockNumber { block_num: 42 });
    assert_eq!(first.notes, vec![expected]);
    SendNoteWithProof::full(&server, Request::new(request.clone())).await.unwrap();
    SendNote::full(
        &server,
        Request::new(SendNoteRequest {
            note: request.note.clone(),
            after_block_num: Some(BlockNumber { block_num: 10 }),
        }),
    )
    .await
    .unwrap();
    let mut invalid = request;
    invalid.inclusion_proof.as_mut().unwrap().note_index_in_block ^= 1;
    assert_eq!(
        SendNoteWithProof::full(&server, Request::new(invalid))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(fetched(&server).await, first);
    upstream.abort();
}

#[tokio::test]
async fn verified_retry_preserves_unverified_envelope() {
    let (request, response) = fixture();
    let (url, upstream) = node_rpc(Ok(response), Duration::ZERO).await;
    let (_dir, server) = server(Config::new(url));
    SendNote::full(
        &server,
        Request::new(SendNoteRequest {
            note: request.note.clone(),
            after_block_num: Some(BlockNumber { block_num: 10 }),
        }),
    )
    .await
    .unwrap();
    let first = fetched(&server).await;
    assert_eq!(first.notes[0].after_block_num, Some(BlockNumber { block_num: 10 }));
    assert_eq!(first.notes[0].committed_in_block, None);
    SendNoteWithProof::full(&server, Request::new(request)).await.unwrap();
    assert_eq!(fetched(&server).await, first);
    upstream.abort();
}

#[tokio::test]
async fn rejects_invalid_proof_requests_without_storage() {
    let (valid, response) = fixture();
    let (url, upstream) = node_rpc(Ok(response), Duration::ZERO).await;
    let (_dir, server) = server(Config::new(url));
    let mut requests = vec![];
    let mut request = valid.clone();
    request.note = None;
    requests.push(request);
    let mut request = valid.clone();
    request.inclusion_proof = None;
    requests.push(request);
    let mut request = valid.clone();
    request.note.as_mut().unwrap().details = note(2, 7).details;
    requests.push(request);
    let mut request = valid.clone();
    request.note = Some(note(2, 7));
    requests.push(request);
    let mut request = valid.clone();
    request.inclusion_proof.as_mut().unwrap().note_index_in_block = u32::MAX;
    requests.push(request);
    let mut request = valid.clone();
    request.inclusion_proof.as_mut().unwrap().note_index_in_block ^= 1;
    requests.push(request);
    let mut request = valid.clone();
    request.inclusion_proof.as_mut().unwrap().inclusion_path = None;
    requests.push(request);
    let mut request = valid.clone();
    request.inclusion_proof.as_mut().unwrap().note_id = None;
    requests.push(request);
    let mut request = valid.clone();
    let other = note(2, 7);
    let header = other.header.clone().unwrap().decode_fields().unwrap().verify().unwrap();
    request.note = Some(other);
    request.inclusion_proof.as_mut().unwrap().note_id = Some((&header.id()).into());
    requests.push(request);
    for depth in [0, 15, 17] {
        let mut request = valid.clone();
        request.inclusion_proof.as_mut().unwrap().inclusion_path =
            Some(miden_node_proto::generated::primitives::SparseMerklePath {
                empty_nodes_mask: (1_u64 << depth) - 1,
                siblings: vec![],
            });
        requests.push(request);
    }
    let mut request = valid.clone();
    request.inclusion_proof.as_mut().unwrap().inclusion_path = Some(
        miden_protocol::crypto::merkle::SparseMerklePath::from_sized_iter(vec![
            Word::from([
                1_u32, 2, 3, 4
            ]);
            16
        ])
        .unwrap()
        .into(),
    );
    requests.push(request);
    let mut request = valid;
    request.inclusion_proof.as_mut().unwrap().block_num = None;
    requests.push(request);
    for request in requests {
        let error = SendNoteWithProof::full(&server, Request::new(request)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(fetched(&server).await.notes.is_empty());
    }
    upstream.abort();
}

#[tokio::test]
async fn lookup_failures_never_store_notes() {
    let (request, response) = fixture();
    let mut malformed = response.clone();
    malformed.block_header = Some(miden_node_proto::generated::blockchain::BlockHeader::default());
    let mut wrong_block = response.clone();
    wrong_block.block_header = Some(BlockHeader::mock(43, None, None, &[]).into());
    let cases = [
        (
            Ok(BlockHeaderByNumberResponse::default()),
            Duration::ZERO,
            tonic::Code::FailedPrecondition,
        ),
        (
            Err(tonic::Status::not_found("missing")),
            Duration::ZERO,
            tonic::Code::FailedPrecondition,
        ),
        (
            Err(tonic::Status::internal("upstream error")),
            Duration::ZERO,
            tonic::Code::Unavailable,
        ),
        (
            Err(tonic::Status::deadline_exceeded("timeout")),
            Duration::ZERO,
            tonic::Code::DeadlineExceeded,
        ),
        (Ok(malformed), Duration::ZERO, tonic::Code::Unavailable),
        (Ok(wrong_block), Duration::ZERO, tonic::Code::Unavailable),
        (Ok(response), Duration::from_secs(30), tonic::Code::DeadlineExceeded),
    ];
    for (response, delay, code) in cases {
        let (url, upstream) = node_rpc(response, delay).await;
        let mut config = Config::new(url);
        config.grpc.request_timeout = if delay.is_zero() {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(200)
        };
        let (_dir, server) = server(config);
        let error = SendNoteWithProof::full(&server, Request::new(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), code, "{error}");
        assert!(fetched(&server).await.notes.is_empty());
        upstream.abort();
    }
}

#[tokio::test]
async fn proof_submission_roundtrips_over_grpc_and_web() {
    let (request, response) = fixture();
    let (url, upstream) = node_rpc(Ok(response), Duration::ZERO).await;
    let (_dir, server) = server(Config::new(url));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve_on(listener, shutdown.clone()));
    let mut client = miden_node_proto::generated::note_transport::api_client::ApiClient::connect(
        format!("http://{address}"),
    )
    .await
    .unwrap();
    client.send_note_with_proof(request.clone()).await.unwrap();
    let response = grpc_web_request(address, "SendNoteWithProof", request).await;
    let frame = response.bytes().await.unwrap();
    assert_eq!(frame[0], 0);
    let length = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
    assert_eq!(SendNoteResponse::decode(&frame[5..5 + length]).unwrap(), SendNoteResponse {});
    let page = client
        .fetch_notes(FetchNotesRequest { tags: vec![7], cursor: None })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page.notes.len(), 1);
    assert_eq!(page.notes[0].after_block_num, None);
    assert_eq!(page.notes[0].committed_in_block, Some(BlockNumber { block_num: 42 }));
    drop(client);
    shutdown.cancel();
    task.await.unwrap().unwrap();
    upstream.abort();
}

#[tokio::test]
async fn lookup_timeout_returns_deadline_exceeded_over_grpc() {
    let (request, response) = fixture();
    let (url, upstream) = node_rpc(Ok(response), Duration::from_secs(30)).await;
    let mut config = Config::new(url);
    config.grpc.request_timeout = Duration::from_millis(100);
    let (_dir, server) = server(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve_on(listener, shutdown.clone()));
    let mut client = miden_node_proto::generated::note_transport::api_client::ApiClient::connect(
        format!("http://{address}"),
    )
    .await
    .unwrap();
    let error = client.send_note_with_proof(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    assert!(
        client
            .fetch_notes(FetchNotesRequest { tags: vec![7], cursor: None })
            .await
            .unwrap()
            .into_inner()
            .notes
            .is_empty()
    );
    drop(client);
    shutdown.cancel();
    task.await.unwrap().unwrap();
    upstream.abort();
}

#[tokio::test]
async fn verified_submission_obeys_size_and_storage_limits() {
    let (request, response) = fixture();
    let (url, upstream) = node_rpc(Ok(response), Duration::ZERO).await;
    let mut oversized = Config::new("http://127.0.0.1:1".parse().unwrap());
    oversized.max_note_size = NonZeroUsize::new(1).unwrap();
    let mut full = Config::new(url);
    full.max_storage_bytes = NonZeroU64::new(1).unwrap();
    for config in [oversized, full] {
        let (_dir, server) = server(config);
        let error = SendNoteWithProof::full(&server, Request::new(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert!(fetched(&server).await.notes.is_empty());
    }
    upstream.abort();
}

#[tokio::test]
async fn proof_retries_reuse_note_root_and_still_verify_proofs() {
    let (request, response) = fixture();
    let (url, upstream, requests) =
        node_rpc_responses(BTreeMap::from([(42, Ok(response))]), Duration::ZERO).await;
    let (_dir, server) = server(Config::new(url));
    SendNoteWithProof::full(&server, Request::new(request.clone())).await.unwrap();
    SendNoteWithProof::full(&server, Request::new(request.clone())).await.unwrap();
    let mut invalid = request;
    invalid.inclusion_proof.as_mut().unwrap().note_index_in_block ^= 1;
    let error = SendNoteWithProof::full(&server, Request::new(invalid)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(*requests.lock().unwrap(), vec![42]);
    assert_eq!(fetched(&server).await.notes.len(), 1);
    upstream.abort();
}

#[tokio::test]
async fn note_root_cache_evicts_the_least_recently_used_block() {
    let responses = (41..=43)
        .map(|block_num| {
            let root = Word::from([block_num, 0, 0, 0]);
            let header = BlockHeader::mock(block_num, None, Some(root), &[]);
            (
                block_num,
                Ok(BlockHeaderByNumberResponse {
                    block_header: Some(header.into()),
                    ..Default::default()
                }),
            )
        })
        .collect();
    let (url, upstream, requests) = node_rpc_responses(responses, Duration::ZERO).await;
    let (_dir, mut server) = server(Config::new(url));
    server.note_root_cache = LruCache::new(NonZeroUsize::new(2).unwrap());
    for block_num in [41, 42, 41, 43, 41, 42] {
        let root = server.get_note_root(block_num.into()).await.unwrap();
        assert_eq!(root, Word::from([block_num, 0, 0, 0]));
    }
    assert_eq!(*requests.lock().unwrap(), vec![41, 42, 43, 42]);
    upstream.abort();
}

#[tokio::test]
async fn note_root_cache_does_not_cache_failed_or_invalid_headers() {
    let cases = [
        (Ok(BlockHeaderByNumberResponse::default()), tonic::Code::FailedPrecondition),
        (Err(tonic::Status::not_found("missing")), tonic::Code::FailedPrecondition),
        (Err(tonic::Status::internal("upstream error")), tonic::Code::Unavailable),
        (Err(tonic::Status::deadline_exceeded("timeout")), tonic::Code::DeadlineExceeded),
        (
            Ok(BlockHeaderByNumberResponse {
                block_header: Some(miden_node_proto::generated::blockchain::BlockHeader::default()),
                ..Default::default()
            }),
            tonic::Code::Unavailable,
        ),
        (
            Ok(BlockHeaderByNumberResponse {
                block_header: Some(BlockHeader::mock(43, None, None, &[]).into()),
                ..Default::default()
            }),
            tonic::Code::Unavailable,
        ),
    ];
    for (response, code) in cases {
        let expected_requests = if code == tonic::Code::DeadlineExceeded { 6 } else { 2 };
        let (url, upstream, requests) =
            node_rpc_responses(BTreeMap::from([(42, response)]), Duration::ZERO).await;
        let (_dir, server) = server(Config::new(url));
        for _ in 0..2 {
            assert_eq!(server.get_note_root(42.into()).await.unwrap_err().code(), code);
        }
        assert_eq!(*requests.lock().unwrap(), vec![42; expected_requests]);
        upstream.abort();
    }
}

#[tokio::test]
async fn transient_lookup_failures_retry_then_cache_the_root() {
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::DeadlineExceeded,
        tonic::Code::ResourceExhausted,
    ] {
        let (request, response) = fixture();
        let responses = VecDeque::from([
            Err(tonic::Status::new(code, "temporary failure")),
            Err(tonic::Status::new(code, "temporary failure")),
            Ok(response),
        ]);
        let (url, upstream, requests) =
            node_rpc_script(BTreeMap::from([(42, responses)]), Duration::ZERO).await;
        let (_dir, server) = server(Config::new(url));
        SendNoteWithProof::full(&server, Request::new(request.clone())).await.unwrap();
        SendNoteWithProof::full(&server, Request::new(request)).await.unwrap();
        assert_eq!(*requests.lock().unwrap(), vec![42, 42, 42]);
        assert_eq!(fetched(&server).await.notes.len(), 1);
        upstream.abort();
    }
}

#[tokio::test]
async fn transient_lookup_failures_stop_after_three_attempts() {
    let (url, upstream, requests) = node_rpc_responses(
        BTreeMap::from([(42, Err(tonic::Status::unavailable("offline")))]),
        Duration::ZERO,
    )
    .await;
    let (_dir, server) = server(Config::new(url));
    assert_eq!(
        server.get_note_root(42.into()).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert_eq!(*requests.lock().unwrap(), vec![42, 42, 42]);
    upstream.abort();
}

#[tokio::test]
async fn slow_lookup_retries_stay_within_the_shared_budget() {
    let (_, response) = fixture();
    let (url, upstream, requests) =
        node_rpc_responses(BTreeMap::from([(42, Ok(response))]), Duration::from_secs(30)).await;
    let mut config = Config::new(url);
    config.grpc.request_timeout = Duration::from_millis(600);
    let (_dir, server) = server(config);
    let result = tokio::time::timeout(Duration::from_millis(500), server.get_note_root(42.into()))
        .await
        .expect("lookups must finish within the shared budget");
    assert_eq!(result.unwrap_err().code(), tonic::Code::DeadlineExceeded);
    assert_eq!(*requests.lock().unwrap(), vec![42, 42, 42]);
    upstream.abort();
}
