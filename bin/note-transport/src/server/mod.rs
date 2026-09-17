use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};

use miden_node_db::sqlite::{DbReader, DbWriter};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::errors::ConversionError;
use miden_node_proto::generated::note_transport::{
    DecodedTransportNote,
    FetchNotesCursor,
    FetchNotesRequest,
    FetchNotesResponse,
    SendNoteRequest,
    SendNoteResponse,
    SendNoteWithProofRequest,
    TransportNote,
};
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_node_proto::server::note_transport_api::{FetchNotes, SendNote, SendNoteWithProof};
use miden_node_proto::{BuildUnchecked, DecodeMessage, Verify};
use miden_node_tracing::grpc::grpc_trace_fn;
use miden_node_tracing::panic::catch_panic_layer_fn;
use miden_node_tracing::{error, info, miden_instrument};
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::BLOCK_NOTE_TREE_DEPTH;
use miden_protocol::note::NoteInclusionProof;
use miden_protocol::utils::serde::Serializable;
use prost::Message;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use url::Url;

use crate::{COMPONENT, LOG_TARGET, db};

// Keep responses within the default gRPC client decoding limit.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

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
        Ok(Self { config, writer, reader, rpc })
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

#[tonic::async_trait]
impl SendNote for Server {
    type Input = db::NewNote;
    type Output = ();

    fn decode(request: SendNoteRequest) -> tonic::Result<Self::Input> {
        decode_note(request.decode_fields().map_err(ConversionError::into_status)?.note)
    }

    fn encode(_: ()) -> tonic::Result<SendNoteResponse> {
        Ok(SendNoteResponse {})
    }

    #[miden_instrument(target = COMPONENT, err)]
    async fn handle(
        &self,
        note: Self::Input,
        _: &MetadataMap,
        _: &Extensions,
    ) -> tonic::Result<()> {
        self.store_note(note).await
    }
}

#[tonic::async_trait]
impl SendNoteWithProof for Server {
    type Input = (db::NewNote, NoteInclusionProof);
    type Output = ();

    fn decode(request: SendNoteWithProofRequest) -> tonic::Result<Self::Input> {
        use miden_node_proto::errors::ConversionResultExt;

        let request = request.decode_fields().map_err(ConversionError::into_status)?;
        let mut note = decode_note(request.note)?;
        let (note_id, proof) = request
            .inclusion_proof
            .verify()
            .context("inclusion_proof")
            .map_err(ConversionError::into_status)?;
        if note_id != note.header.id() {
            return Err(tonic::Status::invalid_argument("proof note ID does not match the note"));
        }
        if proof.note_path().depth() != BLOCK_NOTE_TREE_DEPTH {
            return Err(tonic::Status::invalid_argument("invalid note proof depth"));
        }
        let block_num = proof.location().block_num();
        if note.after_block_num.is_some_and(|hint| hint != block_num) {
            return Err(tonic::Status::invalid_argument("block hint does not match the proof"));
        }
        note.after_block_num = Some(block_num);
        Ok((note, proof))
    }

    fn encode(_: ()) -> tonic::Result<SendNoteResponse> {
        Ok(SendNoteResponse {})
    }

    #[miden_instrument(target = COMPONENT, err)]
    async fn handle(
        &self,
        (note, proof): Self::Input,
        _: &MetadataMap,
        _: &Extensions,
    ) -> tonic::Result<()> {
        use miden_node_proto::errors::ConversionResultExt;

        self.check_note_size(&note)?;
        let mut rpc = self.rpc.clone();
        let response = tokio::time::timeout(
            // Reserve half of the request budget for note validation and storage.
            self.config.grpc.request_timeout / 2,
            rpc.get_block_header_by_number(BlockHeaderByNumberRequest {
                block_num: Some(proof.location().block_num().as_u32()),
                include_mmr_proof: Some(false),
                include_protocol_config: Some(false),
            }),
        )
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("block header lookup timed out"))?
        .map_err(|error| lookup_status(&error))?
        .into_inner();
        let header = response
            .block_header
            .ok_or_else(|| tonic::Status::failed_precondition("proof block is not available"))?
            .decode_fields()
            // The configured node supplies the canonical header. No parent check is required.
            .and_then(|header| header.build_unchecked().context("block_header"))
            .map_err(|error| {
                error!(error, target: LOG_TARGET, "Invalid node block header");
                tonic::Status::unavailable("node returned an invalid block header")
            })?;
        if header.block_num() != proof.location().block_num() {
            return Err(tonic::Status::unavailable("node returned a different block"));
        }
        proof
            .note_path()
            .verify(
                proof.location().block_note_tree_index().into(),
                note.header.id().as_word(),
                &header.note_root(),
            )
            .map_err(|_| tonic::Status::invalid_argument("note inclusion proof is invalid"))?;
        self.store_note(note).await
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

#[tonic::async_trait]
impl FetchNotes for Server {
    type Input = FetchNotesRequest;
    type Output = FetchNotesResponse;

    fn decode(mut request: FetchNotesRequest) -> tonic::Result<Self::Input> {
        if request.tags.len() > 128 {
            return Err(tonic::Status::invalid_argument("at most 128 tags are allowed"));
        }
        if request.cursor.is_some_and(|cursor| cursor.sequence > i64::MAX as u64) {
            return Err(tonic::Status::invalid_argument("invalid cursor"));
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
        let cursor = request.cursor.map(|cursor| db::Cursor {
            nonce: cursor.nonce,
            sequence: cursor.sequence,
        });
        let page = db::fetch_notes(&self.reader, request.tags, cursor)
            .await
            .map_err(storage_status)?;

        let mut cursor = FetchNotesCursor {
            nonce: page.cursor.nonce,
            sequence: cursor.map_or(0, |cursor| cursor.sequence),
        };
        let mut notes = Vec::with_capacity(page.notes.len());
        let mut has_more = page.has_more;
        // Reserve space for a nonzero sequence and a continuation flag.
        let mut response_bytes = FetchNotesResponse {
            notes: vec![],
            cursor: Some(FetchNotesCursor { sequence: u64::MAX, ..cursor }),
            has_more: true,
        }
        .encoded_len();
        for note in page.notes {
            let next_cursor = u64::try_from(note.seq).map_err(|error| {
                error!(error, target: LOG_TARGET, "Invalid stored note cursor");
                tonic::Status::internal("note storage operation failed")
            })?;
            let note = TransportNote {
                header: Some(note.header.into()),
                details: Some(note.details.into()),
                after_block_num: note.after_block_num.map(|block_num| {
                    miden_node_proto::generated::blockchain::BlockNumber {
                        block_num: block_num.as_u32(),
                    }
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
            cursor.sequence = next_cursor;
            notes.push(note);
        }
        info!(target: LOG_TARGET, "Notes fetched",
            note_transport.returned = notes.len(), note_transport.cursor = cursor.sequence,
            note_transport.has_more = has_more);
        Ok(FetchNotesResponse { notes, cursor: Some(cursor), has_more })
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

fn lookup_status(error: &tonic::Status) -> tonic::Status {
    match error.code() {
        tonic::Code::NotFound => tonic::Status::failed_precondition("proof block is not available"),
        tonic::Code::DeadlineExceeded => {
            tonic::Status::deadline_exceeded("block header lookup timed out")
        },
        _ => {
            error!(error, target: LOG_TARGET, "Block header lookup failed");
            tonic::Status::unavailable("block header lookup failed")
        },
    }
}

fn decode_note(request: DecodedTransportNote) -> tonic::Result<db::NewNote> {
    use miden_node_proto::errors::ConversionResultExt;

    let header = request
        .header
        .verify()
        .context("note.header")
        .map_err(ConversionError::into_status)?;
    let details = request
        .details
        .verify()
        .context("note.details")
        .map_err(ConversionError::into_status)?;
    let after_block_num = request
        .after_block_num
        .map(Verify::verify)
        .transpose()
        .context("note.after_block_num")
        .map_err(ConversionError::into_status)?;
    if details.commitment() != header.details_commitment() {
        return Err(tonic::Status::invalid_argument("note details do not match the header"));
    }
    Ok(db::NewNote { header, details, after_block_num })
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
