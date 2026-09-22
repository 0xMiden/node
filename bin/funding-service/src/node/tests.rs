use std::convert::Infallible;
use std::future::{Ready, ready};
use std::sync::Mutex as StdMutex;
use std::task::{Context as TaskContext, Poll};

use futures::future::BoxFuture;
use miden_node_proto::generated::{note, rpc, transaction};
use miden_node_proto::prost::Message;
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_standards::note::P2idNote;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic_prost::ProstCodec;
use tower::Service;

use super::*;
use crate::deposit::DepositScanner;

// RPC FIXTURE
// ================================================================================================

pub(crate) struct TestChain {
    pub tip: u32,
    pub notes: Vec<(u32, Note)>,
    pub transactions: Vec<(u32, AccountId, TransactionId)>,
    pub spent: Vec<(u32, Nullifier)>,
    pub unavailable: Option<&'static str>,
    invalid_checked: Option<u32>,
}

impl TestChain {
    pub(crate) fn new(tip: u32) -> Self {
        Self {
            tip,
            notes: vec![],
            transactions: vec![],
            spent: vec![],
            unavailable: None,
            invalid_checked: None,
        }
    }

    fn page(&self, range: BlockRange) -> rpc::PaginationInfo {
        rpc::PaginationInfo {
            chain_tip: self.tip,
            block_num: self.invalid_checked.unwrap_or_else(|| {
                range.block_to.min(self.tip).min(range.block_from.saturating_add(4))
            }),
        }
    }

    fn sync_transactions(
        &self,
        request: &SyncTransactionsRequest,
    ) -> rpc::SyncTransactionsResponse {
        let range = request.block_range.unwrap();
        let page = self.page(range);
        rpc::SyncTransactionsResponse {
            transactions: self
                .transactions
                .iter()
                .filter(|(block, account, _)| {
                    (range.block_from..=page.block_num).contains(block)
                        && request.account_ids.contains(&(*account).into())
                })
                .map(|(block, _, id)| rpc::TransactionRecord {
                    block_num: *block,
                    header: Some(transaction::TransactionHeader {
                        transaction_id: Some((*id).into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .collect(),
            pagination_info: Some(page),
        }
    }

    fn sync_notes(&self, request: &SyncNotesRequest) -> rpc::SyncNotesResponse {
        let range = request.block_range.unwrap();
        let page = self.page(range);
        rpc::SyncNotesResponse {
            blocks: self
                .notes
                .iter()
                .filter(|(block, note)| {
                    (range.block_from..=page.block_num).contains(block)
                        && request.note_tags.contains(&note.metadata().tag().as_u32())
                })
                .map(|(_, note)| rpc::sync_notes_response::NoteSyncBlock {
                    notes: vec![rpc::NoteSyncRecord {
                        inclusion_proof: Some(note::NoteInclusionProof {
                            note_id: Some(note.id().as_word().into()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .collect(),
            pagination_info: Some(page),
        }
    }

    fn notes_by_id(&self, request: &NotesByIdRequest) -> rpc::NotesByIdResponse {
        rpc::NotesByIdResponse {
            notes: request
                .note_ids
                .iter()
                .filter_map(|id| {
                    self.notes
                        .iter()
                        .find(|(_, note)| note::NoteId::from(note.id().as_word()) == *id)
                })
                .map(|(_, note)| rpc::CommittedNote {
                    note: Some(note.clone().into()),
                    inclusion_proof: None,
                })
                .collect(),
        }
    }

    fn sync_nullifiers(&self, request: &SyncNullifiersRequest) -> rpc::SyncNullifiersResponse {
        let range = request.block_range.unwrap();
        let page = self.page(range);
        rpc::SyncNullifiersResponse {
            nullifiers: self
                .spent
                .iter()
                .filter(|(block, nullifier)| {
                    (range.block_from..=page.block_num).contains(block)
                        && request.nullifiers.contains(&u32::from(nullifier.prefix()))
                })
                .map(|(block, nullifier)| rpc::sync_nullifiers_response::NullifierUpdate {
                    nullifier: Some(nullifier.as_word().into()),
                    block_num: *block,
                })
                .collect(),
            pagination_info: Some(page),
        }
    }

    fn account_id() -> AccountId {
        FungibleAsset::mock_issuer()
    }

    fn transaction_id(serial: u32) -> TransactionId {
        TransactionId::from_raw(Word::from([serial; 4]))
    }

    fn deposit(serial: u32) -> Note {
        P2idNote::builder()
            .sender(Self::account_id())
            .target(Self::account_id())
            .asset(FungibleAsset::new(Self::account_id(), 1_000).unwrap())
            .note_type(NoteType::Public)
            .serial_number(Word::from([serial; 4]))
            .build()
            .unwrap()
            .into()
    }
}

type RpcResponse = BoxFuture<'static, Result<http::Response<Body>, Infallible>>;

#[derive(Clone)]
struct RpcFixture(Arc<StdMutex<TestChain>>);

impl RpcFixture {
    fn respond<Req, Resp>(
        &self,
        request: http::Request<Body>,
        respond: fn(&TestChain, &Req) -> Resp,
    ) -> RpcResponse
    where
        Req: Message + Default + Send + 'static,
        Resp: Message + Default + Send + 'static,
    {
        let reply = Reply { chain: self.0.clone(), respond };
        Box::pin(async move {
            Ok(Grpc::new(ProstCodec::<Resp, Req>::default()).unary(reply, request).await)
        })
    }
}

struct Reply<Req, Resp> {
    chain: Arc<StdMutex<TestChain>>,
    respond: fn(&TestChain, &Req) -> Resp,
}

impl<Req, Resp> UnaryService<Req> for Reply<Req, Resp> {
    type Response = Resp;
    type Future = Ready<tonic::Result<tonic::Response<Resp>>>;

    fn call(&mut self, request: tonic::Request<Req>) -> Self::Future {
        ready(Ok(tonic::Response::new((self.respond)(
            &self.chain.lock().unwrap(),
            request.get_ref(),
        ))))
    }
}

impl NamedService for RpcFixture {
    const NAME: &'static str = "rpc.Api";
}

impl Service<http::Request<Body>> for RpcFixture {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = RpcResponse;

    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let method = request.uri().path().rsplit('/').next().unwrap();
        if self.0.lock().unwrap().unavailable == Some(method) {
            return Box::pin(async { Ok(tonic::Status::unavailable("retry").into_http()) });
        }
        match method {
            "Status" => self.respond(request, |chain, _: &()| rpc::RpcStatus {
                chain_tip: chain.tip,
                ..Default::default()
            }),
            "SyncTransactions" => self.respond(request, TestChain::sync_transactions),
            "SyncNotes" => self.respond(request, TestChain::sync_notes),
            "GetNotesById" => self.respond(request, TestChain::notes_by_id),
            "SyncNullifiers" => self.respond(request, TestChain::sync_nullifiers),
            _ => {
                Box::pin(async { Ok(tonic::Status::unimplemented("unused endpoint").into_http()) })
            },
        }
    }
}

pub(crate) struct TestServer {
    pub(crate) node: RpcNodeClient,
    pub(crate) chain: Arc<StdMutex<TestChain>>,
    task: JoinHandle<tonic::Result<()>>,
}

impl TestServer {
    pub(crate) async fn start(chain: TestChain) -> Self {
        let chain = Arc::new(StdMutex::new(chain));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let incoming = futures::stream::unfold(listener, |listener| async move {
            Some((listener.accept().await.map(|(stream, _)| stream), listener))
        });
        let service = RpcFixture(chain.clone());
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming)
                .await
                .map_err(|err| tonic::Status::internal(err.to_string()))
        });
        let rpc_client = Builder::new(url)
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .without_otel_context_injection()
            .connect::<RpcClient>()
            .await
            .unwrap();
        let node = RpcNodeClient {
            rpc_client,
            genesis_commitment: Word::empty(),
            protocol_config: ProtocolConfig::current(
                AssetId::new_fungible(TestChain::account_id()),
            )
            .unwrap(),
            trusted_validator_signing_keys: Arc::from([]),
            sealer: Arc::new(Mutex::new(None)),
        };
        Self { node, chain, task }
    }

    async fn status(&self) -> Result<TransactionStatus> {
        self.node
            .transaction_status(
                TestChain::account_id(),
                TestChain::transaction_id(1),
                10.into(),
                20.into(),
            )
            .await
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// TRANSACTION RESOLUTION
// ================================================================================================

#[rstest::rstest]
#[case::state_conflict(tonic::Status::with_details(
    tonic::Code::InvalidArgument, "conflict", vec![2].into()
))]
#[case::node_error(tonic::Status::with_details(
    tonic::Code::Internal, "node error", vec![0].into()
))]
#[case::encryption_key(tonic::Status::failed_precondition("refresh the encryption key"))]
#[case::validator_busy(tonic::Status::resource_exhausted("validator busy"))]
fn submission_errors_from_the_node_are_rejected(#[case] status: tonic::Status) {
    assert!(matches!(SubmissionOutcome::from_status(status), SubmissionOutcome::Rejected(_)));
}

#[rstest::rstest]
#[case::connection_lost(tonic::Status::unavailable("connection lost"))]
#[case::timeout(tonic::Status::deadline_exceeded("response timed out"))]
#[case::broken_response(tonic::Status::internal("broken response"))]
#[case::connection_reset(tonic::Status::from_error(Box::new(std::io::Error::from(
    std::io::ErrorKind::ConnectionReset,
))))]
fn submission_errors_from_transport_leave_the_outcome_unknown(#[case] status: tonic::Status) {
    assert!(matches!(SubmissionOutcome::from_status(status), SubmissionOutcome::Unknown(_)));
}

#[tokio::test]
async fn commitment_on_a_later_page_takes_precedence_over_expiration() {
    let mut chain = TestChain::new(30);
    chain.transactions = vec![
        (12, TestChain::account_id(), TestChain::transaction_id(2)),
        (19, TestChain::account_id(), TestChain::transaction_id(1)),
    ];
    let server = TestServer::start(chain).await;

    assert_eq!(server.status().await.unwrap(), TransactionStatus::Committed);
}

#[tokio::test]
async fn an_absent_transaction_is_pending_until_expiration() {
    let server = TestServer::start(TestChain::new(19)).await;

    assert_eq!(server.status().await.unwrap(), TransactionStatus::Pending);
    server.chain.lock().unwrap().tip = 20;
    assert_eq!(server.status().await.unwrap(), TransactionStatus::Expired);
}

#[tokio::test]
async fn a_failed_scan_leaves_the_outcome_unknown_and_can_be_retried() {
    let mut chain = TestChain::new(30);
    chain.transactions = vec![(19, TestChain::account_id(), TestChain::transaction_id(1))];
    chain.unavailable = Some("SyncTransactions");
    let server = TestServer::start(chain).await;

    assert!(server.status().await.is_err());
    server.chain.lock().unwrap().unavailable = None;
    assert_eq!(server.status().await.unwrap(), TransactionStatus::Committed);
}

#[tokio::test]
async fn invalid_pagination_does_not_establish_expiration() {
    for checked in [10, 21] {
        let mut chain = TestChain::new(30);
        chain.invalid_checked = Some(checked);
        let server = TestServer::start(chain).await;
        assert!(server.status().await.is_err());
    }
}

// DEPOSIT DISCOVERY
// ================================================================================================

#[tokio::test]
async fn discovery_recovers_historical_deposits_and_continues_with_new_blocks() {
    let first = TestChain::deposit(1);
    let second = TestChain::deposit(2);
    let third = TestChain::deposit(3);
    let mut chain = TestChain::new(12);
    chain.notes = vec![(3, first.clone()), (10, second.clone())];
    chain.unavailable = Some("GetNotesById");
    let server = TestServer::start(chain).await;
    let mut scanner = DepositScanner::new(TestChain::account_id(), TestChain::account_id());

    assert!(scanner.scan(&server.node, 12.into()).await.is_err());
    server.chain.lock().unwrap().unavailable = None;
    let mut recovered = HashMap::new();
    while !scanner.is_caught_up(12.into()) {
        recovered.extend(
            scanner
                .scan(&server.node, 12.into())
                .await
                .unwrap()
                .into_iter()
                .map(|note| (note.id(), note)),
        );
    }
    assert_eq!(recovered, HashMap::from([(first.id(), first), (second.id(), second)]));
    assert!(scanner.scan(&server.node, 12.into()).await.unwrap().is_empty());

    {
        let mut chain = server.chain.lock().unwrap();
        chain.tip = 15;
        chain.notes.push((14, third.clone()));
    }
    assert_eq!(scanner.scan(&server.node, 15.into()).await.unwrap(), vec![third]);
}

#[tokio::test]
async fn a_prefix_collision_does_not_mark_an_unspent_deposit_as_spent() {
    let deposit = TestChain::deposit(1);
    let mut word = deposit.nullifier().as_word();
    word[0] += miden_protocol::Felt::ONE;
    let other = Nullifier::from_raw(word);
    let mut chain = TestChain::new(12);
    chain.spent = vec![(10, other)];
    let server = TestServer::start(chain).await;

    assert!(
        server
            .node
            .spent_nullifiers(&[deposit.nullifier()], 12.into())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn invalid_nullifier_pagination_does_not_report_notes_as_unspent() {
    let nullifier = TestChain::deposit(1).nullifier();
    for checked in [0, 21] {
        let mut chain = TestChain::new(20);
        chain.invalid_checked = Some(checked);
        let server = TestServer::start(chain).await;
        assert!(server.node.spent_nullifiers(&[nullifier], 20.into()).await.is_err());
    }
}

#[tokio::test]
async fn invalid_note_pagination_does_not_skip_deposits() {
    let deposit = TestChain::deposit(1);
    let mut chain = TestChain::new(12);
    chain.notes = vec![(3, deposit.clone())];
    chain.invalid_checked = Some(13);
    let server = TestServer::start(chain).await;
    let mut scanner = DepositScanner::new(TestChain::account_id(), TestChain::account_id());

    assert!(scanner.scan(&server.node, 12.into()).await.is_err());
    server.chain.lock().unwrap().invalid_checked = None;
    assert_eq!(scanner.scan(&server.node, 12.into()).await.unwrap(), vec![deposit]);
}

#[tokio::test]
async fn nullifier_checks_find_spent_notes_in_a_large_set() {
    let mut requested: Vec<_> = (0..1_500u32)
        .map(|prefix| {
            Nullifier::from_raw(Word::new([
                miden_protocol::Felt::ZERO,
                miden_protocol::Felt::ZERO,
                miden_protocol::Felt::ZERO,
                miden_protocol::Felt::new(u64::from(prefix) << 48).unwrap(),
            ]))
        })
        .collect();
    let first = requested[0];
    let last = *requested.last().unwrap();
    let mut chain = TestChain::new(20);
    chain.spent = vec![(3, first), (19, last)];
    let server = TestServer::start(chain).await;
    requested.push(first);

    assert_eq!(
        server.node.spent_nullifiers(&requested, 20.into()).await.unwrap(),
        HashSet::from([first, last])
    );
}
