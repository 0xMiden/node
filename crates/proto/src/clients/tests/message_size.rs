use miden_node_utils::shutdown::CancellationToken;
use prost::Message;
use tonic::{Request, Response, Status};

use super::super::{Builder, RemoteProverProxyStatusClient};
use crate::generated::miden::remote_prover::v1::proxy_status_service_server::ProxyStatusService;
use crate::generated::miden::remote_prover::v1::{ProxyStatusRequest, ProxyStatusResponse};

struct StatusService(usize);

#[tonic::async_trait]
impl ProxyStatusService for StatusService {
    async fn status(
        &self,
        _: Request<ProxyStatusRequest>,
    ) -> Result<Response<ProxyStatusResponse>, Status> {
        Ok(Response::new(ProxyStatusResponse {
            version: "x".repeat(self.0),
            ..Default::default()
        }))
    }
}

#[expect(
    deprecated,
    reason = "Transport fixtures use raw tonic services without domain decoding."
)]
pub(super) async fn server(
    payload_bytes: usize,
) -> (url::Url, CancellationToken, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(crate::generated::miden::remote_prover::v1::proxy_status_service_server::ProxyStatusServiceServer::new(StatusService(payload_bytes)))
            .add_service(crate::generated::miden::validator::v1::validator_service_server::ValidatorServiceServer::new(StatusService(payload_bytes)))
            .serve_with_incoming_shutdown(
                miden_node_utils::grpc::tcp_incoming(listener),
                stop.cancelled_owned(),
            )
            .await
            .unwrap();
    });
    (url, shutdown, task)
}

#[tokio::test]
async fn message_size_override_survives_states_clones_and_connection_modes() {
    let (url, shutdown, task) = server(4 * 1024 * 1024 + 1).await;
    let builder = Builder::new(url.clone())
        .max_decoding_message_size(16 * 1024 * 1024)
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_auth_header()
        .without_otel_context_injection();
    let mut lazy = builder.clone().connect_lazy::<RemoteProverProxyStatusClient>();
    let mut eager = builder.clone().connect::<RemoteProverProxyStatusClient>().await.unwrap();
    assert_eq!(
        lazy.status(ProxyStatusRequest {}).await.unwrap().into_inner().version.len(),
        4 * 1024 * 1024 + 1
    );
    assert_eq!(
        eager.status(ProxyStatusRequest {}).await.unwrap().into_inner().version.len(),
        4 * 1024 * 1024 + 1
    );
    let mut default = Builder::new(url)
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_auth_header()
        .without_otel_context_injection()
        .connect_lazy::<RemoteProverProxyStatusClient>();
    assert_eq!(
        default.status(ProxyStatusRequest {}).await.unwrap_err().code(),
        tonic::Code::OutOfRange
    );
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn message_size_counts_encoded_bytes_at_the_boundary() {
    let response = ProxyStatusResponse {
        version: "x".repeat(126),
        ..Default::default()
    };
    assert_eq!(response.encoded_len(), 128);
    let (url, shutdown, task) = server(126).await;
    let builder = Builder::new(url)
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_auth_header()
        .without_otel_context_injection();
    let mut at_limit = builder
        .clone()
        .max_decoding_message_size(128)
        .connect_lazy::<RemoteProverProxyStatusClient>();
    assert_eq!(at_limit.status(ProxyStatusRequest {}).await.unwrap().into_inner(), response);
    let mut over_limit = builder
        .max_decoding_message_size(127)
        .connect_lazy::<RemoteProverProxyStatusClient>();
    assert_eq!(
        over_limit.status(ProxyStatusRequest {}).await.unwrap_err().code(),
        tonic::Code::OutOfRange
    );
    shutdown.cancel();
    task.await.unwrap();
}

#[tonic::async_trait]
impl crate::generated::miden::validator::v1::validator_service_server::ValidatorService
    for StatusService
{
    type BlockSubscriptionStream = tokio_stream::Iter<
        std::vec::IntoIter<
            Result<crate::generated::miden::validator::v1::BlockSubscriptionResponse, Status>,
        >,
    >;

    async fn status(
        &self,
        _: Request<crate::generated::miden::validator::v1::StatusRequest>,
    ) -> Result<Response<crate::generated::miden::validator::v1::StatusResponse>, Status> {
        Ok(Response::new(crate::generated::miden::validator::v1::StatusResponse {
            version: "x".repeat(self.0),
            ..Default::default()
        }))
    }

    async fn block_subscription(
        &self,
        _: Request<crate::generated::miden::validator::v1::BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        let items = (1..=3)
            .map(|tip| {
                Ok(crate::generated::miden::validator::v1::BlockSubscriptionResponse {
                    committed_chain_tip: tip,
                    protocol_config: (tip == 3 && self.0 > 0).then(Default::default),
                    ..Default::default()
                })
            })
            .collect::<Vec<_>>();
        Ok(Response::new(tokio_stream::iter(items)))
    }

    async fn sign_block(
        &self,
        _: Request<crate::generated::miden::validator::v1::SignBlockRequest>,
    ) -> Result<Response<crate::generated::miden::validator::v1::SignBlockResponse>, Status> {
        Err(Status::unimplemented("unused test method"))
    }

    async fn submit_proven_transaction(
        &self,
        _: Request<crate::generated::miden::validator::v1::SubmitProvenTransactionRequest>,
    ) -> Result<
        Response<crate::generated::miden::validator::v1::SubmitProvenTransactionResponse>,
        Status,
    > {
        Err(Status::unimplemented("unused test method"))
    }

    async fn get_transaction_encryption_key(
        &self,
        _: Request<crate::generated::miden::validator::v1::GetTransactionEncryptionKeyRequest>,
    ) -> Result<
        Response<crate::generated::miden::validator::v1::GetTransactionEncryptionKeyResponse>,
        Status,
    > {
        Err(Status::unimplemented("unused test method"))
    }
}

#[tokio::test]
async fn message_size_validator_uses_four_mib_default_and_accepts_override() {
    use crate::clients::ValidatorClient;
    use crate::generated::miden::validator::v1::StatusRequest;
    let (url, shutdown, task) = server(4 * 1024 * 1024 + 1).await;
    let builder = Builder::new(url)
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_auth_header()
        .without_otel_context_injection();
    let mut default = builder.clone().connect_lazy::<ValidatorClient>();
    assert_eq!(
        default.status(StatusRequest {}).await.unwrap_err().code(),
        tonic::Code::OutOfRange
    );
    let mut larger = builder
        .max_decoding_message_size(16 * 1024 * 1024)
        .connect_lazy::<ValidatorClient>();
    assert_eq!(
        larger.status(StatusRequest {}).await.unwrap().into_inner().version.len(),
        4 * 1024 * 1024 + 1
    );
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn message_size_limits_stream_items_individually() {
    use crate::clients::ValidatorClient;
    use crate::generated::miden::validator::v1::BlockSubscriptionRequest;
    for oversized_last in [false, true] {
        let (url, shutdown, task) = server(usize::from(oversized_last)).await;
        let mut client = Builder::new(url)
            .max_decoding_message_size(5)
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .without_otel_context_injection()
            .connect_lazy::<ValidatorClient>();
        let mut stream = client
            .block_subscription(BlockSubscriptionRequest { block_from: 0 })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stream.message().await.unwrap().unwrap().committed_chain_tip, 1);
        assert_eq!(stream.message().await.unwrap().unwrap().committed_chain_tip, 2);
        if oversized_last {
            assert_eq!(stream.message().await.unwrap_err().code(), tonic::Code::OutOfRange);
        } else {
            assert_eq!(stream.message().await.unwrap().unwrap().committed_chain_tip, 3);
            assert!(stream.message().await.unwrap().is_none());
        }
        shutdown.cancel();
        task.await.unwrap();
    }
}
