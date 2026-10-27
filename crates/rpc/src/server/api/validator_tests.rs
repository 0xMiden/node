use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::generated::miden::validator::v1::validator_service_server::ValidatorService;
use miden_node_proto::generated::miden::validator::v1::*;
use miden_node_proto::generated::submission::{
    ProvenTransactionSubmission,
    SealedTransactionInputs,
};
use miden_node_proto::prost::Message;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::AccountUpdateDetails;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockHeader;
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_protocol::testing::dummy_execution_proof;
use miden_protocol::transaction::{
    InputNoteCommitment,
    OutputNote,
    PartialBlockchain,
    ProvenTransaction,
    TxAccountUpdate,
};
use tonic::{Code, Request, Response, Status};

use super::{submit_batch_to_validators, submit_tx_to_validators};

#[derive(Clone, Default)]
struct Service {
    calls: Arc<Mutex<Vec<Vec<u8>>>>,
    responses: Arc<Mutex<VecDeque<Code>>>,
}

#[tonic::async_trait]
impl ValidatorService for Service {
    type BlockSubscriptionStream = tokio_stream::Empty<Result<BlockSubscriptionResponse, Status>>;

    async fn submit_proven_transaction(
        &self,
        request: Request<SubmitProvenTransactionRequest>,
    ) -> Result<Response<SubmitProvenTransactionResponse>, Status> {
        self.calls.lock().unwrap().push(request.into_inner().encode_to_vec());
        let code = self.responses.lock().unwrap().pop_front().unwrap_or(Code::Ok);
        if code != Code::Ok {
            return Err(Status::new(code, "connection closed"));
        }
        Ok(Response::new(SubmitProvenTransactionResponse {}))
    }

    async fn status(&self, _: Request<StatusRequest>) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_transaction_encryption_key(
        &self,
        _: Request<GetTransactionEncryptionKeyRequest>,
    ) -> Result<Response<GetTransactionEncryptionKeyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn sign_block(
        &self,
        _: Request<SignBlockRequest>,
    ) -> Result<Response<SignBlockResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn block_subscription(
        &self,
        _: Request<BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

struct Server {
    client: ValidatorClient,
    service: Service,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    #[expect(deprecated, reason = "Transport tests use a raw tonic service.")]
    async fn new(responses: Vec<Code>, retirement: Option<h2::Reason>) -> Self {
        let service = Service::default();
        *service.responses.lock().unwrap() = responses.into();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let handler = service.clone();
        let task = tokio::spawn(async move {
            if let Some(reason) = retirement {
                let (socket, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(socket).await.unwrap();
                let (_, mut response) = connection.accept().await.unwrap().unwrap();
                if reason == h2::Reason::CANCEL {
                    response.send_reset(reason);
                    connection.graceful_shutdown();
                } else {
                    connection.abrupt_shutdown(reason);
                }
                while connection.accept().await.is_some() {}
            }
            tonic::transport::Server::builder()
                .add_service(validator_service_server::ValidatorServiceServer::new(handler))
                .serve_with_incoming_shutdown(
                    miden_node_utils::grpc::tcp_incoming(listener),
                    stop.cancelled_owned(),
                )
                .await
                .unwrap();
        });
        let client = Builder::new(url)
            .without_tls()
            .with_timeout(Duration::from_secs(2))
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .without_otel_context_injection()
            .connect_lazy();
        Self { client, service, shutdown, task }
    }

    fn calls(&self) -> Vec<Vec<u8>> {
        self.service.calls.lock().unwrap().clone()
    }

    async fn stop(self) {
        self.shutdown.cancel();
        self.task.await.unwrap();
    }
}

/// Two consecutive private transactions with distinct sealed inputs.
struct Submission {
    batch: ProposedBatch,
    sealed: Vec<SealedTransactionInputs>,
}

impl Submission {
    fn new() -> Self {
        let chain = PartialBlockchain::default();
        let header = BlockHeader::mock(0_u32, Some(chain.peaks().hash_peaks()), None, &[]);
        let transactions = (1_u32..=2)
            .map(|i| {
                let update = TxAccountUpdate::new(
                    ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
                    Word::from([i; 4]),
                    Word::from([i + 1; 4]),
                    Word::empty(),
                    AccountUpdateDetails::Private,
                )
                .unwrap();
                Arc::new(
                    ProvenTransaction::new(
                        update,
                        std::iter::empty::<InputNoteCommitment>(),
                        std::iter::empty::<OutputNote>(),
                        header.block_num(),
                        header.commitment(),
                        100.into(),
                        dummy_execution_proof(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let batch =
            ProposedBatch::new_unverified(transactions, header, chain, BTreeMap::new()).unwrap();
        let sealed = (1..=2)
            .map(|i| SealedTransactionInputs { key_id: vec![i], ciphertext: vec![i; 16] })
            .collect();
        Self { batch, sealed }
    }

    fn transaction(&self, index: usize) -> ProvenTransactionSubmission {
        ProvenTransactionSubmission {
            transaction: Some(self.batch.transactions()[index].as_ref().into()),
            sealed_transaction_inputs: Some(self.sealed[index].clone()),
        }
    }

    fn encoded(&self, index: usize) -> Vec<u8> {
        SubmitProvenTransactionRequest {
            submission: Some(self.transaction(index)),
        }
        .encode_to_vec()
    }

    async fn submit(&self, clients: &[ValidatorClient], batch: bool) -> Result<(), Status> {
        if batch {
            submit_batch_to_validators(clients, &self.batch, &self.sealed).await
        } else {
            submit_tx_to_validators(clients, &self.transaction(0)).await
        }
    }
}

#[tokio::test]
async fn validator_submission_recovers_from_connection_retirement() {
    let submission = Submission::new();
    for reason in [h2::Reason::NO_ERROR, h2::Reason::CANCEL] {
        for batch in [false, true] {
            let server = Server::new(vec![], Some(reason)).await;
            tokio::time::timeout(
                Duration::from_secs(5),
                submission.submit(std::slice::from_ref(&server.client), batch),
            )
            .await
            .unwrap()
            .unwrap();
            let expected = (0..if batch { 2 } else { 1 })
                .map(|i| submission.encoded(i))
                .collect::<Vec<_>>();
            assert_eq!(server.calls(), expected);
            server.stop().await;
        }
    }
}

#[tokio::test]
async fn validator_submission_retries_only_failed_transactions() {
    let submission = Submission::new();
    for batch in [false, true] {
        let healthy = Server::new(vec![], None).await;
        let responses = if batch {
            vec![Code::Ok, Code::Unavailable]
        } else {
            vec![Code::Unavailable]
        };
        let failing = Server::new(responses, None).await;
        submission
            .submit(&[healthy.client.clone(), failing.client.clone()], batch)
            .await
            .unwrap();
        let expected = (0..if batch { 2 } else { 1 })
            .map(|i| submission.encoded(i))
            .collect::<Vec<_>>();
        assert_eq!(healthy.calls(), expected);
        let mut retried = expected.clone();
        retried.push(expected.last().unwrap().clone());
        assert_eq!(failing.calls(), retried);
        healthy.stop().await;
        failing.stop().await;
    }
}

#[tokio::test]
async fn validator_submission_preserves_application_errors() {
    let submission = Submission::new();
    for code in [Code::Cancelled, Code::Internal, Code::Unknown, Code::InvalidArgument] {
        for batch in [false, true] {
            let server = Server::new(vec![code], None).await;
            let error = submission
                .submit(std::slice::from_ref(&server.client), batch)
                .await
                .unwrap_err();
            assert_eq!(error.code(), code);
            assert_eq!(error.message(), "connection closed");
            assert_eq!(server.calls(), vec![submission.encoded(0)]);
            server.stop().await;
        }
    }
}

#[tokio::test]
async fn validator_submission_retries_are_bounded() {
    let submission = Submission::new();
    let server = Server::new(vec![Code::Unavailable; 20], None).await;
    let error = submission
        .submit(std::slice::from_ref(&server.client), false)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(server.calls(), vec![submission.encoded(0); 11]);
    server.stop().await;
}
