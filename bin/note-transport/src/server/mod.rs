use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use miden_node_db::sqlite::{DbReader, DbWriter};
use miden_node_proto::decode::GrpcDecodeExt;
use miden_node_proto::generated::note_transport::{
    FetchNotesRequest,
    FetchNotesResponse,
    TransportNote,
};
use miden_node_proto::server::note_transport_api::{FetchNotes, SendNote};
use miden_node_tracing::grpc::grpc_trace_fn;
use miden_node_tracing::panic::catch_panic_layer_fn;
use miden_node_tracing::{error, info, miden_instrument};
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::note::{NoteDetails, NoteHeader};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use prost::Message;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::{COMPONENT, LOG_TARGET, db};

// Keep responses within the default gRPC client decoding limit.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    pub max_note_size: usize,
    pub max_connections: usize,
    pub max_storage_bytes: u64,
    pub retention_days: u32,
    pub grpc: GrpcOptions,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_note_size: 512_000,
            max_connections: 4096,
            max_storage_bytes: 1024 * 1024 * 1024,
            retention_days: 30,
            grpc: GrpcOptions::default(),
        }
    }
}

pub struct Server {
    config: Config,
    writer: DbWriter,
    reader: DbReader,
}

impl Server {
    pub fn new(config: Config, writer: DbWriter, reader: DbReader) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=db::FETCH_NOTES_MAX_BYTES).contains(&config.max_note_size),
            "max-note-size must be between 1 and {} bytes",
            db::FETCH_NOTES_MAX_BYTES
        );
        anyhow::ensure!(config.max_connections > 0, "max-connections must be positive");
        anyhow::ensure!(!config.grpc.request_timeout.is_zero(), "grpc.timeout must be positive");
        Ok(Self { config, writer, reader })
    }

    /// Serves requests until cancellation and waits for active requests to finish.
    pub async fn serve_on(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
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
            .layer(GlobalConcurrencyLimitLayer::new(self.config.max_connections))
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

#[tonic::async_trait]
impl SendNote for Server {
    type Input = db::StoredNote;
    type Output = ();

    fn decode(request: TransportNote) -> tonic::Result<Self::Input> {
        let decoder = request.decoder();
        let header: NoteHeader = decoder.decode_field("header", request.header)?;
        let details: NoteDetails = decoder.decode_field("details", request.details)?;
        if details.commitment() != header.details_commitment() {
            return Err(tonic::Status::invalid_argument("note details do not match the header"));
        }
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_micros()).ok())
            .ok_or_else(|| tonic::Status::internal("system time is outside the supported range"))?;
        Ok(db::StoredNote {
            header,
            details: details.to_bytes(),
            created_at,
            seq: 0,
            after_block_num: request.after_block_num.map(|block| block.block_num),
        })
    }

    fn encode(_: ()) -> tonic::Result<()> {
        Ok(())
    }

    #[miden_instrument(target = COMPONENT, err)]
    async fn handle(
        &self,
        note: Self::Input,
        _: &MetadataMap,
        _: &Extensions,
    ) -> tonic::Result<()> {
        let size = note.header.to_bytes().len() + note.details.len();
        if size > self.config.max_note_size {
            return Err(tonic::Status::resource_exhausted("note exceeds max-note-size"));
        }
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

#[tonic::async_trait]
impl FetchNotes for Server {
    type Input = FetchNotesRequest;
    type Output = FetchNotesResponse;

    fn decode(mut request: FetchNotesRequest) -> tonic::Result<Self::Input> {
        if request.tags.len() > 128 {
            return Err(tonic::Status::invalid_argument("at most 128 tags are allowed"));
        }
        if request.cursor > i64::MAX as u64 {
            return Err(tonic::Status::invalid_argument("cursor exceeds SQLite range"));
        }
        request.tags.sort_unstable();
        request.tags.dedup();
        Ok(request)
    }

    fn encode(response: Self::Output) -> tonic::Result<FetchNotesResponse> {
        Ok(response)
    }

    #[miden_instrument(target = COMPONENT, err)]
    async fn handle(
        &self,
        request: Self::Input,
        _: &MetadataMap,
        _: &Extensions,
    ) -> tonic::Result<Self::Output> {
        let page = db::fetch_notes(&self.reader, request.tags, request.cursor)
            .await
            .map_err(storage_status)?;
        let mut cursor = request.cursor;
        let mut notes = Vec::with_capacity(page.notes.len());
        let mut has_more = page.has_more;
        // Reserve the fixed64 cursor and the boolean continuation field.
        let mut response_bytes = 11;
        for note in page.notes {
            let next_cursor = u64::try_from(note.seq)
                .map_err(|_| tonic::Status::internal("invalid stored cursor"))?;
            let details = NoteDetails::read_from_bytes(&note.details).map_err(|error| {
                error!(error, target: LOG_TARGET, "Failed to decode stored note details");
                tonic::Status::internal("invalid stored note details")
            })?;
            let note = TransportNote {
                header: Some(note.header.into()),
                details: Some(details.into()),
                after_block_num: note.after_block_num.map(|block_num| {
                    miden_node_proto::generated::blockchain::BlockNumber { block_num }
                }),
            };
            let note_bytes = note.encoded_len();
            let field_bytes =
                1 + prost::encoding::encoded_len_varint(note_bytes as u64) + note_bytes;
            if response_bytes + field_bytes > MAX_RESPONSE_BYTES {
                if notes.is_empty() {
                    return Err(tonic::Status::resource_exhausted(
                        "stored note exceeds the response limit",
                    ));
                }
                has_more = true;
                break;
            }
            response_bytes += field_bytes;
            cursor = next_cursor;
            notes.push(note);
        }
        info!(target: LOG_TARGET, "Notes fetched",
            note_transport.returned = notes.len(), note_transport.cursor = cursor,
            note_transport.has_more = has_more);
        Ok(FetchNotesResponse { notes, cursor, has_more })
    }
}

fn storage_status(error: db::StorageError) -> tonic::Status {
    match error {
        db::StorageError::Capacity(message) => tonic::Status::resource_exhausted(message),
        db::StorageError::InvalidCursor => {
            tonic::Status::invalid_argument("cursor exceeds SQLite range")
        },
        error => {
            error!(error, target: LOG_TARGET, "Note storage operation failed");
            tonic::Status::internal("note storage operation failed")
        },
    }
}

#[cfg(test)]
mod tests;
