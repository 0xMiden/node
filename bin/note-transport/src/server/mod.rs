use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};

use miden_node_db::sqlite::{DbReader, DbWriter};
use miden_node_proto::Verify;
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::errors::conversion_error_to_status;
use miden_node_proto::generated::note_transport::DecodedTransportNote;
use miden_node_tracing::grpc::grpc_trace_fn;
use miden_node_tracing::panic::catch_panic_layer_fn;
use miden_node_tracing::{error, info};
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::Serializable;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use url::Url;

use crate::{COMPONENT, LOG_TARGET, db};

mod fetch_notes;
mod note_root;
mod send_note;
mod send_note_with_proof;

const NOTE_ROOT_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

#[derive(Clone, Debug)]
pub struct Config {
    pub rpc_url: Url,
    pub max_note_size: NonZeroUsize,
    pub max_connections: NonZeroUsize,
    pub max_storage_bytes: NonZeroU64,
    pub retention_days: NonZeroU32,
    pub grpc: GrpcOptions,
}

impl Config {
    /// Creates a configuration with default limits and a trusted node endpoint.
    pub fn new(rpc_url: Url) -> Self {
        Self {
            rpc_url,
            max_note_size: NonZeroUsize::new(512_000).unwrap(),
            max_connections: NonZeroUsize::new(4096).unwrap(),
            max_storage_bytes: NonZeroU64::new(1024 * 1024 * 1024).unwrap(),
            retention_days: NonZeroU32::new(30).unwrap(),
            grpc: GrpcOptions::default(),
        }
    }
}

pub struct Server {
    config: Config,
    writer: DbWriter,
    reader: DbReader,
    rpc: RpcClient,
    note_root_cache: LruCache<BlockNumber, Word>,
}

impl Server {
    pub fn new(config: Config, writer: DbWriter, reader: DbReader) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.max_note_size.get() <= db::FETCH_NOTES_MAX_BYTES,
            "max-note-size must be between 1 and {} bytes",
            db::FETCH_NOTES_MAX_BYTES
        );
        anyhow::ensure!(!config.grpc.request_timeout.is_zero(), "grpc.timeout must be positive");
        parse_rpc_url(config.rpc_url.as_str()).map_err(anyhow::Error::msg)?;
        let rpc = Builder::new(config.rpc_url.clone())
            .with_tls()?
            // The lookup timeout covers connection setup and the complete response.
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect_lazy();
        Ok(Self {
            config,
            writer,
            reader,
            rpc,
            note_root_cache: LruCache::new(NOTE_ROOT_CACHE_CAPACITY),
        })
    }

    /// Serves requests until cancellation and waits for active requests to finish.
    pub async fn serve_on(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        use anyhow::Context;
        use miden_node_proto::server::note_transport_api;
        db::record_retained_bytes(&self.reader).await?;
        let (health, health_service) = tonic_health::server::health_reporter();
        health
            .set_service_status(
                note_transport_api::service_name(),
                tonic_health::ServingStatus::Serving,
            )
            .await;
        let reflection = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(miden_node_proto_build::note_transport_api_descriptor())
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .build_v1()
            .context("failed to build note transport reflection service")?;
        info!(target: LOG_TARGET, "Note transport ready",
            service.name = COMPONENT,
            service.version = env!("CARGO_PKG_VERSION"),
            rpc.listen = listener.local_addr()?.to_string());
        tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(CatchPanicLayer::custom(catch_panic_layer_fn))
            .layer(TraceLayer::new_for_grpc().make_span_with(grpc_trace_fn))
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_headers(Any)
                    .allow_methods(Any)
                    .expose_headers(Any),
            )
            .layer(tonic_web::GrpcWebLayer::new())
            .layer(GlobalConcurrencyLimitLayer::new(self.config.max_connections.get()))
            .timeout(self.config.grpc.request_timeout)
            .add_service(health_service)
            .add_service(reflection)
            .add_service(note_transport_api::service(self))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                shutdown.cancelled().await;
                health
                    .set_service_status(
                        note_transport_api::service_name(),
                        tonic_health::ServingStatus::NotServing,
                    )
                    .await;
            })
            .await
            .context("note transport server failed")
    }
}

impl Server {
    fn check_note_size(&self, note: &db::NewNote) -> tonic::Result<usize> {
        let size = note.header.to_bytes().len() + note.details.to_bytes().len();
        if size > self.config.max_note_size.get() {
            return Err(tonic::Status::resource_exhausted("note exceeds max-note-size"));
        }
        Ok(size)
    }

    async fn store_note(&self, note: db::NewNote) -> tonic::Result<()> {
        let size = self.check_note_size(&note)?;
        let id = note.header.id();
        let result = db::store_note(
            &self.writer,
            note,
            self.config.max_storage_bytes,
            self.config.retention_days,
        )
        .await
        .map_err(storage_status)?;
        info!(target: LOG_TARGET, "Note accepted",
            note.id = id,
            note_transport.payload_bytes = size,
            note_transport.inserted = result == db::StoreResult::Inserted);
        Ok(())
    }
}

/// Parses the trusted node URL. Only HTTP and HTTPS endpoints are supported.
pub fn parse_rpc_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|error| error.to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("rpc-url must be an HTTP or HTTPS URL with a host".into());
    }
    Ok(url)
}

fn decode_note(request: DecodedTransportNote) -> tonic::Result<db::NewNote> {
    use miden_node_proto::errors::ConversionResultExt;

    let header = request
        .header
        .verify()
        .context("note.header")
        .map_err(conversion_error_to_status)?;
    let details = request
        .details
        .verify()
        .context("note.details")
        .map_err(conversion_error_to_status)?;
    if details.commitment() != header.details_commitment() {
        return Err(tonic::Status::invalid_argument("note details do not match the header"));
    }
    Ok(db::NewNote {
        header,
        details,
        after_block_num: None,
        included_in_block: None,
    })
}

fn storage_status(error: db::StorageError) -> tonic::Status {
    match error {
        db::StorageError::Capacity(message) => tonic::Status::resource_exhausted(message),
        db::StorageError::StaleCursor => tonic::Status::failed_precondition(
            "cursor belongs to another database generation; clear the cursor and retry",
        ),
        db::StorageError::InvalidCursor => tonic::Status::invalid_argument("invalid cursor"),
        error => {
            error!(error, target: LOG_TARGET, "Note storage operation failed");
            tonic::Status::internal("note storage operation failed")
        },
    }
}

#[cfg(test)]
mod tests;
