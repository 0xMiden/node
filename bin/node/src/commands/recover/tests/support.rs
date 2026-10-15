use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use miden_node_proto::clients::{Builder, ValidatorClient};
use miden_node_proto::generated::miden::validator::v1 as wire;
use miden_node_proto::server::miden_validator_v1_validator_service as api;
use miden_node_store::{BlockWriter, ProofWriter, State, WriterTask};
use miden_node_utils::clap::{GrpcOptions, StorageOptions};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::block::SignedBlock;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::utils::serde::Deserializable;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_stream::Stream;
use url::Url;

pub struct RunningValidator {
    pub url: Url,
    pub shutdown: CancellationToken,
    pub task: JoinHandle<anyhow::Result<()>>,
    pub directory: TempDir,
}

impl RunningValidator {
    pub fn client(&self) -> ValidatorClient {
        Builder::new(self.url.clone())
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection()
            .connect_lazy()
    }

    pub async fn stop(self) -> anyhow::Result<TempDir> {
        self.shutdown.cancel();
        join_server(self.task).await??;
        Ok(self.directory)
    }
}

pub async fn start_validator(
    key: SigningKey,
    genesis: SignedBlock,
    config: ProtocolConfig,
) -> anyhow::Result<RunningValidator> {
    let directory = tempfile::tempdir()?;
    miden_validator::db::bootstrap(
        directory.path().join("validator.sqlite3"),
        miden_node_store::default_sqlite_connection_pool_size(),
        genesis,
        config,
    )
    .await?;
    reopen_validator(key, directory).await
}

pub async fn reopen_validator(
    key: SigningKey,
    directory: TempDir,
) -> anyhow::Result<RunningValidator> {
    let db = miden_validator::db::load(directory.path().join("validator.sqlite3")).await?;
    let operator = miden_validator::EncodedGoldenOperatorKey::from_bytes(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/testdata/insecure-storage-key/validator-1/storage-key.bundle",
    )))?
    .decode()?;
    let key_exchange =
        miden_protocol::crypto::dsa::eddsa_25519_sha512::KeyExchangeKey::read_from_bytes(
            &[3u8; 32],
        )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = miden_validator::ValidatorServer {
        address,
        grpc_options: GrpcOptions::default(),
        signer: miden_validator::ValidatorSigner::new_local(key),
        decrypter: Arc::new(miden_validator::LocalX25519TransactionInputDecrypter::new(
            key_exchange,
        )),
        private_record_sealer: miden_validator::PrivateRecordSealer::from_operator_key(&operator),
        db,
    };
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve_on(listener, shutdown.clone()));
    Ok(RunningValidator {
        url: Url::parse(&format!("http://{address}"))?,
        shutdown,
        task,
        directory,
    })
}

pub async fn load_store(
    path: &std::path::Path,
) -> anyhow::Result<(Arc<State>, BlockWriter, ProofWriter, WriterTask)> {
    Ok(State::load(path, StorageOptions::default())
        .await?
        .start(CancellationToken::new()))
}

/// A transport fault forwards genuine backup events while exposing stream lifetime to the test.
#[derive(Clone)]
pub enum Fault {
    InterruptAfterFirst(Arc<Notify>),
    Hold(Arc<Notify>),
    Refuse(Arc<Notify>),
}

#[derive(Clone)]
struct BackupProxy {
    upstream: ValidatorClient,
    fault: Fault,
    opened: Arc<Notify>,
    dropped: Arc<Notify>,
}

struct ObservedStream {
    inner: Pin<Box<dyn Stream<Item = tonic::Result<wire::BlockSubscriptionResponse>> + Send>>,
    dropped: Arc<Notify>,
}

impl Stream for ObservedStream {
    type Item = tonic::Result<wire::BlockSubscriptionResponse>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(cx)
    }
}
impl Drop for ObservedStream {
    fn drop(&mut self) {
        self.dropped.notify_one();
    }
}

struct GatedStream {
    upstream: tonic::Streaming<wire::BlockSubscriptionResponse>,
    gate: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    interrupt: bool,
    emitted: bool,
}
impl Stream for GatedStream {
    type Item = tonic::Result<wire::BlockSubscriptionResponse>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.interrupt && !this.emitted {
            let item = Pin::new(&mut this.upstream).poll_next(cx);
            if item.is_ready() {
                this.emitted = true;
            }
            return item;
        }
        if this.gate.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        if this.interrupt {
            Poll::Ready(Some(Err(tonic::Status::unavailable("injected interrupted backup"))))
        } else {
            Pin::new(&mut this.upstream).poll_next(cx)
        }
    }
}

#[tonic::async_trait]
impl api::Status for BackupProxy {
    type Input = wire::StatusRequest;
    type Output = wire::StatusResponse;
    fn decode(input: Self::Input) -> tonic::Result<Self::Input> {
        Ok(input)
    }
    fn encode(output: Self::Output) -> tonic::Result<Self::Output> {
        Ok(output)
    }
    async fn handle(
        &self,
        input: Self::Input,
        _: &tonic::metadata::MetadataMap,
        _: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        Ok(self.upstream.clone().status(input).await?.into_inner())
    }
}

#[tonic::async_trait]
impl api::BlockSubscription for BackupProxy {
    type Input = wire::BlockSubscriptionRequest;
    type Item = wire::BlockSubscriptionResponse;
    type ItemStream = ObservedStream;
    fn decode(input: Self::Input) -> tonic::Result<Self::Input> {
        Ok(input)
    }
    fn encode(output: Self::Item) -> tonic::Result<Self::Item> {
        Ok(output)
    }
    async fn handle(
        &self,
        input: Self::Input,
        _: &tonic::metadata::MetadataMap,
        _: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        if let Fault::Refuse(release) = &self.fault {
            release.notified().await;
            return Err(tonic::Status::unavailable("injected setup refusal"));
        }
        let upstream = self.upstream.clone().block_subscription(input).await?.into_inner();
        self.opened.notify_one();
        let (release, interrupt) = match &self.fault {
            Fault::Hold(release) => (release.clone(), false),
            Fault::InterruptAfterFirst(release) => (release.clone(), true),
            Fault::Refuse(_) => unreachable!(),
        };
        let inner = Box::pin(GatedStream {
            upstream,
            gate: Box::pin(async move { release.notified().await }),
            interrupt,
            emitted: false,
        });
        Ok(ObservedStream { inner, dropped: self.dropped.clone() })
    }
}

macro_rules! unsupported {
    ($method:ident, $request:ident, $response:ident) => {
        #[tonic::async_trait]
        impl api::$method for BackupProxy {
            type Input = wire::$request;
            type Output = wire::$response;
            fn decode(input: Self::Input) -> tonic::Result<Self::Input> {
                Ok(input)
            }
            fn encode(output: Self::Output) -> tonic::Result<Self::Output> {
                Ok(output)
            }
            async fn handle(
                &self,
                _: Self::Input,
                _: &tonic::metadata::MetadataMap,
                _: &tonic::codegen::http::Extensions,
            ) -> tonic::Result<Self::Output> {
                Err(tonic::Status::unimplemented("backup-only test proxy"))
            }
        }
    };
}
unsupported!(SignBlock, SignBlockRequest, SignBlockResponse);
unsupported!(
    SubmitProvenTransaction,
    SubmitProvenTransactionRequest,
    SubmitProvenTransactionResponse
);
unsupported!(
    GetTransactionEncryptionKey,
    GetTransactionEncryptionKeyRequest,
    GetTransactionEncryptionKeyResponse
);

pub struct RunningProxy {
    pub url: Url,
    pub opened: Arc<Notify>,
    pub dropped: Arc<Notify>,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}
impl RunningProxy {
    pub fn client(&self) -> ValidatorClient {
        Builder::new(self.url.clone())
            .without_tls()
            .with_timeout(Duration::from_secs(5))
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection()
            .connect_lazy()
    }
    pub async fn stop(self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        join_server(self.task).await??;
        Ok(())
    }
}

pub async fn start_proxy(upstream: ValidatorClient, fault: Fault) -> anyhow::Result<RunningProxy> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = Url::parse(&format!("http://{}", listener.local_addr()?))?;
    let opened = Arc::new(Notify::new());
    let dropped = Arc::new(Notify::new());
    let shutdown = CancellationToken::new();
    let service = BackupProxy {
        upstream,
        fault,
        opened: opened.clone(),
        dropped: dropped.clone(),
    };
    let child = shutdown.clone();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(api::service(service))
            .serve_with_incoming_shutdown(
                miden_node_utils::grpc::tcp_incoming(listener),
                child.cancelled_owned(),
            )
            .await
    });
    Ok(RunningProxy { url, opened, dropped, shutdown, task })
}

/// Retain ownership through timeout so stalled servers are aborted and drained.
pub async fn join_server<T>(mut task: JoinHandle<T>) -> anyhow::Result<T> {
    match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
        Ok(result) => Ok(result?),
        Err(error) => {
            task.abort();
            let _ = task.await;
            Err(error.into())
        },
    }
}
