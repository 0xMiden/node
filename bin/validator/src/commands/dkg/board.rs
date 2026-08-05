use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use futures::StreamExt;
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_blobs::api::downloader::{DownloadProgressItem, Downloader};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, Hash};
use iroh_docs::DocTicket;
use iroh_docs::api::Doc;
use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
use iroh_docs::engine::LiveEvent;
use iroh_docs::protocol::Docs;
use iroh_docs::store::{DownloadPolicy, Query};
use iroh_gossip::net::Gossip;

use super::{decode_fixed_hex, write_new_file};

const ENDPOINT_SECRET_FILE: &str = "endpoint-secret.hex";
const DOCUMENT_ID_FILE: &str = "document-id.hex";
const BOARD_FORMAT_FILE: &str = "board-format";
const BOARD_FORMAT: &[u8] = b"bounded-upload-v1\n";
const UPLOAD_SECRET_FILE: &str = "upload-secret.hex";
const BOARD_TICKET_PREFIX: &str = "miden-storage-key-dkg-board-v1";
const UPLOAD_ALPN: &[u8] = b"/miden/storage-key-dkg-board-upload/1";
const UPLOAD_HEADER_BYTES: usize = 32 + 1 + 4 + 8;
const UPLOAD_RESPONSE_BYTES: usize = 1 + 32;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONCURRENT_UPLOADS: usize = 3;
const MAX_UPLOAD_ERROR_BYTES: usize = 1024;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(30);
const PEER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const COMMON_ARTIFACT_COUNT: usize = 3;
const ARTIFACTS_PER_PARTICIPANT: usize = 6;
const MAX_VALUES_PER_SLOT: usize = 2;

/// A read-only document ticket paired with permission to submit bounded artifacts to its board.
#[derive(Clone, Debug)]
pub(super) struct BoardTicket {
    document: DocTicket,
    upload_secret: [u8; 32],
}

impl fmt::Display for BoardTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{BOARD_TICKET_PREFIX}:{}:{}",
            hex::encode(self.upload_secret),
            self.document
        )
    }
}

impl FromStr for BoardTicket {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.splitn(3, ':');
        ensure!(parts.next() == Some(BOARD_TICKET_PREFIX), "invalid DKG board ticket prefix");
        let secret = parts.next().context("DKG board ticket is missing its upload secret")?;
        let document = parts.next().context("DKG board ticket is missing its document ticket")?;
        let upload_secret = decode_fixed_hex::<32>(secret, "DKG board upload secret")?;
        let document = DocTicket::from_str(document).context("invalid Iroh document ticket")?;
        ensure!(
            matches!(document.capability, iroh_docs::Capability::Read(_)),
            "DKG board document ticket must be read-only"
        );
        Ok(Self { document, upload_secret })
    }
}

/// One immutable location in a DKG ceremony document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ArtifactSlot {
    Registration(u32),
    Manifest,
    DecryptionConfig,
    ContextConfig,
    DecryptionDealing(u32),
    ContextDealing(u32),
    Transcript(u32),
    TranscriptAcceptance(u32),
    FinalConfirmation(u32),
}

impl ArtifactSlot {
    fn prefix(&self) -> String {
        match self {
            Self::Registration(participant) => format!("registration/{participant}/"),
            Self::Manifest => "common/manifest/".to_owned(),
            Self::DecryptionConfig => "common/decryption-config/".to_owned(),
            Self::ContextConfig => "common/context-config/".to_owned(),
            Self::DecryptionDealing(participant) => {
                format!("dealing/{participant}/decryption/")
            },
            Self::ContextDealing(participant) => format!("dealing/{participant}/context/"),
            Self::Transcript(participant) => format!("acceptance/{participant}/transcript/"),
            Self::TranscriptAcceptance(participant) => {
                format!("acceptance/{participant}/signature/")
            },
            Self::FinalConfirmation(participant) => {
                format!("final/{participant}/confirmation/")
            },
        }
    }

    fn key(&self, hash: Hash) -> String {
        format!("{}{}", self.prefix(), hash.to_hex())
    }

    fn upload_fields(&self) -> anyhow::Result<(u8, u32)> {
        let fields = match self {
            Self::Registration(participant) => (1, *participant),
            Self::DecryptionDealing(participant) => (2, *participant),
            Self::ContextDealing(participant) => (3, *participant),
            Self::Transcript(participant) => (4, *participant),
            Self::TranscriptAcceptance(participant) => (5, *participant),
            Self::FinalConfirmation(participant) => (6, *participant),
            Self::Manifest | Self::DecryptionConfig | Self::ContextConfig => {
                anyhow::bail!("only the DKG board may publish common ceremony artifacts")
            },
        };
        Ok(fields)
    }

    fn from_upload_fields(kind: u8, participant: u32) -> anyhow::Result<Self> {
        ensure!(participant > 0, "DKG board participant index must be nonzero");
        match kind {
            1 => Ok(Self::Registration(participant)),
            2 => Ok(Self::DecryptionDealing(participant)),
            3 => Ok(Self::ContextDealing(participant)),
            4 => Ok(Self::Transcript(participant)),
            5 => Ok(Self::TranscriptAcceptance(participant)),
            6 => Ok(Self::FinalConfirmation(participant)),
            _ => anyhow::bail!("DKG board upload contains an unknown artifact kind"),
        }
    }
}

#[derive(Clone, Debug)]
struct BoardWriter {
    author: iroh_docs::AuthorId,
    document: Doc,
    allowed_prefixes: Arc<Vec<String>>,
    lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug)]
enum Publisher {
    Local(BoardWriter),
    Remote {
        endpoint: Endpoint,
        target: EndpointAddr,
        upload_secret: [u8; 32],
    },
}

#[derive(Clone, Debug)]
struct UploadProtocol {
    permits: Arc<tokio::sync::Semaphore>,
    upload_secret: [u8; 32],
    writer: BoardWriter,
}

/// A persistent Iroh node joined to one ceremony document.
pub(super) struct BoardNode {
    blobs: FsStore,
    document: Doc,
    downloader: Downloader,
    event_error: tokio::sync::watch::Receiver<Option<String>>,
    event_task: tokio::task::JoinHandle<()>,
    allowed_prefixes: Arc<Vec<String>>,
    max_document_entries: usize,
    peer_ready: tokio::sync::watch::Receiver<bool>,
    publisher: Publisher,
    remote_providers: std::sync::Arc<tokio::sync::RwLock<BTreeMap<Hash, Vec<EndpointId>>>>,
    router: Router,
    sync_generation: tokio::sync::watch::Receiver<u64>,
    sync_targets: Vec<iroh::EndpointAddr>,
}

struct BoardRuntime {
    author: iroh_docs::AuthorId,
    blobs: FsStore,
    docs: Docs,
    downloader: Downloader,
    endpoint: Endpoint,
    gossip: Gossip,
}

struct BoardEvents {
    error: tokio::sync::watch::Receiver<Option<String>>,
    peer_ready: tokio::sync::watch::Receiver<bool>,
    remote_providers: Arc<tokio::sync::RwLock<BTreeMap<Hash, Vec<EndpointId>>>>,
    sync_generation: tokio::sync::watch::Receiver<u64>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BoardNode {
    fn drop(&mut self) {
        self.event_task.abort();
    }
}

impl BoardNode {
    /// Creates a new ceremony document and returns its read and upload ticket.
    pub(super) async fn create(
        data_directory: &Path,
        participant_count: usize,
    ) -> anyhow::Result<(Self, BoardTicket)> {
        Self::create_with_network(data_directory, participant_count, true).await
    }

    pub(super) async fn create_with_network(
        data_directory: &Path,
        participant_count: usize,
        use_network_services: bool,
    ) -> anyhow::Result<(Self, BoardTicket)> {
        let runtime = BoardRuntime::start(data_directory, use_network_services).await?;
        let document_id_path = data_directory.join(DOCUMENT_ID_FILE);
        let existing_document = document_id_path.exists();
        let document = if existing_document {
            require_current_board_format(data_directory)?;
            let id = fs_err::read_to_string(&document_id_path).with_context(|| {
                format!("failed to read Iroh document ID {}", document_id_path.display())
            })?;
            let id = decode_fixed_hex::<32>(id.trim(), "Iroh document ID")?;
            runtime
                .docs
                .open(iroh_docs::NamespaceId::from(&id))
                .await
                .context("failed to open Iroh document")?
                .context("persisted Iroh document is missing")?
        } else {
            let document = runtime.docs.create().await.context("failed to create Iroh document")?;
            write_new_file(
                &document_id_path,
                hex::encode(document.id().to_bytes()).as_bytes(),
                true,
            )?;
            write_new_file(&data_directory.join(BOARD_FORMAT_FILE), BOARD_FORMAT, true)?;
            document
        };
        let upload_secret = load_or_create_upload_secret(data_directory, !existing_document)?;
        document
            .set_download_policy(DownloadPolicy::NothingExcept(Vec::new()))
            .await
            .context("failed to restrict DKG board downloads")?;
        let mut document_ticket = document
            .share(
                ShareMode::Read,
                if use_network_services {
                    AddrInfoOptions::RelayAndAddresses
                } else {
                    AddrInfoOptions::Id
                },
            )
            .await
            .context("failed to create Iroh document ticket")?;
        if !use_network_services {
            let mut socket = runtime
                .endpoint
                .bound_sockets()
                .into_iter()
                .find(std::net::SocketAddr::is_ipv4)
                .context("Iroh test endpoint has no IPv4 socket")?;
            socket.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            document_ticket.nodes = vec![iroh::EndpointAddr::from_parts(
                runtime.endpoint.id(),
                [iroh::TransportAddr::Ip(socket)],
            )];
        }
        let ticket = BoardTicket { document: document_ticket, upload_secret };
        let board = runtime
            .attach(document, participant_count, Vec::new(), Some(upload_secret), None)
            .await?;
        board
            .document
            .start_sync(Vec::new())
            .await
            .context("failed to start DKG board synchronization")?;
        Ok((board, ticket))
    }

    /// Joins an existing ceremony document through its read and upload ticket.
    pub(super) async fn join(
        data_directory: &Path,
        ticket: &str,
        participant_count: usize,
    ) -> anyhow::Result<Self> {
        Self::join_with_network(data_directory, ticket, participant_count, true).await
    }

    pub(super) async fn join_with_network(
        data_directory: &Path,
        ticket: &str,
        participant_count: usize,
        use_network_services: bool,
    ) -> anyhow::Result<Self> {
        let ticket = BoardTicket::from_str(ticket)?;
        let runtime = BoardRuntime::start(data_directory, use_network_services).await?;
        let BoardTicket { document, upload_secret } = ticket;
        let DocTicket { capability, nodes } = document;
        let target = nodes.first().cloned().context("DKG board ticket has no endpoint")?;
        let document = runtime
            .docs
            .import_namespace(capability)
            .await
            .context("failed to join Iroh ceremony document")?;
        document
            .set_download_policy(DownloadPolicy::NothingExcept(Vec::new()))
            .await
            .context("failed to restrict DKG board downloads")?;
        let mut board = runtime
            .attach(document, participant_count, nodes.clone(), None, Some((target, upload_secret)))
            .await?;
        board
            .document
            .start_sync(nodes)
            .await
            .context("failed to start DKG board synchronization")?;
        board.wait_for_peer().await?;
        Ok(board)
    }

    /// Publishes one artifact without replacing another value in the same slot.
    pub(super) async fn publish(&self, slot: &ArtifactSlot, value: &[u8]) -> anyhow::Result<Hash> {
        self.ensure_admitted()?;
        validate_artifact_length(value.len())?;
        let expected_hash = Hash::new(value);
        let sync_generation = *self.sync_generation.borrow();
        let stored_hash = match &self.publisher {
            Publisher::Local(writer) => writer.store(slot, value).await?,
            Publisher::Remote { endpoint, target, upload_secret } => {
                upload_artifact(endpoint, target, upload_secret, slot, value).await?
            },
        };
        ensure!(stored_hash == expected_hash, "Iroh stored artifact under an unexpected hash");
        self.document
            .start_sync(self.sync_targets.clone())
            .await
            .context("failed to synchronize DKG board artifact")?;
        if !self.sync_targets.is_empty() || *self.peer_ready.borrow() {
            let mut completed = self.sync_generation.clone();
            tokio::time::timeout(
                PEER_READY_TIMEOUT,
                completed.wait_for(|generation| *generation > sync_generation),
            )
            .await
            .context("timed out synchronizing DKG board artifact")?
            .context("DKG board synchronization monitor stopped")?;
        }
        Ok(stored_hash)
    }

    /// Reads the unique content value published for one artifact slot.
    pub(super) async fn read_unique(&self, slot: &ArtifactSlot) -> anyhow::Result<Option<Vec<u8>>> {
        self.validate_document_metadata().await?;
        let prefix = slot.prefix();
        let entries = self
            .document
            .get_many(Query::key_prefix(prefix.as_bytes()))
            .await
            .context("failed to query DKG board artifacts")?;
        futures::pin_mut!(entries);
        let mut values = BTreeMap::new();
        while let Some(entry) = entries.next().await {
            let entry = entry.context("failed to read DKG board entry")?;
            ensure!(
                entry.content_len() > 0 && entry.content_len() <= MAX_ARTIFACT_BYTES,
                "DKG board artifact exceeds {MAX_ARTIFACT_BYTES} bytes",
            );
            let expected_key = slot.key(entry.content_hash());
            ensure!(
                entry.key() == expected_key.as_bytes(),
                "DKG board key does not match its content hash"
            );
            let hash = entry.content_hash();
            if self.blobs.blobs().get_bytes(hash).await.is_err() {
                let mut providers =
                    self.remote_providers.read().await.get(&hash).cloned().unwrap_or_default();
                let sync_peers = self
                    .document
                    .get_sync_peers()
                    .await
                    .context("failed to list DKG board peers")?
                    .unwrap_or_default()
                    .into_iter()
                    .map(|id| EndpointId::from_bytes(&id).context("invalid DKG board peer ID"))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                for peer in sync_peers {
                    if !providers.contains(&peer) {
                        providers.push(peer);
                    }
                }
                if providers.is_empty() {
                    return Ok(None);
                }
                let Ok(mut progress) = self.downloader.download(hash, providers).stream().await
                else {
                    return Ok(None);
                };
                while let Some(item) = progress.next().await {
                    match item {
                        DownloadProgressItem::Progress(downloaded) => ensure!(
                            downloaded <= MAX_ARTIFACT_BYTES,
                            "DKG board artifact exceeds {MAX_ARTIFACT_BYTES} bytes",
                        ),
                        DownloadProgressItem::Error(_) | DownloadProgressItem::DownloadError => {
                            return Ok(None);
                        },
                        DownloadProgressItem::TryProvider { .. }
                        | DownloadProgressItem::ProviderFailed { .. }
                        | DownloadProgressItem::PartComplete { .. } => {},
                    }
                }
            }
            let bytes = self
                .blobs
                .blobs()
                .get_bytes(hash)
                .await
                .context("downloaded DKG board artifact is missing")?;
            ensure!(
                u64::try_from(bytes.len()).context("artifact length does not fit u64")?
                    == entry.content_len(),
                "DKG board artifact length does not match its entry"
            );
            values.entry(hash).or_insert_with(|| bytes.to_vec());
        }
        ensure!(values.len() <= 1, "DKG board contains conflicting artifacts for {prefix}");
        Ok(values.into_values().next())
    }

    async fn validate_document_metadata(&self) -> anyhow::Result<()> {
        self.ensure_admitted()?;
        inspect_document_metadata(&self.document, &self.allowed_prefixes, self.max_document_entries)
            .await
    }

    fn ensure_admitted(&self) -> anyhow::Result<()> {
        if let Some(error) = self.event_error.borrow().as_ref() {
            anyhow::bail!("DKG board synchronization stopped: {error}");
        }
        Ok(())
    }

    async fn wait_for_peer(&mut self) -> anyhow::Result<()> {
        if *self.peer_ready.borrow() {
            return Ok(());
        }
        tokio::time::timeout(PEER_READY_TIMEOUT, self.peer_ready.wait_for(|ready| *ready))
            .await
            .context("timed out waiting for the DKG board peer")?
            .context("DKG board peer monitor stopped")?;
        Ok(())
    }

    /// Waits until one unique artifact has synchronized locally.
    pub(super) async fn wait_unique(
        &self,
        slot: &ArtifactSlot,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let mut events = self
            .document
            .subscribe()
            .await
            .context("failed to subscribe to DKG board updates")?;
        tokio::time::timeout(timeout, async {
            loop {
                if let Some(value) = self.read_unique(slot).await? {
                    return Ok(value);
                }
                tokio::select! {
                    event = events.next() => {
                        event.transpose()?.context("DKG board update stream ended")?;
                    },
                    () = tokio::time::sleep(Duration::from_millis(250)) => {},
                }
            }
        })
        .await
        .with_context(|| format!("timed out waiting for DKG board slot {}", slot.prefix()))?
    }

    /// Stops the board node and flushes its persistent stores.
    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        self.event_task.abort();
        self.router.shutdown().await.context("failed to stop Iroh board node")?;
        Ok(())
    }
}

fn validate_artifact_length(length: usize) -> anyhow::Result<()> {
    ensure!(length > 0, "DKG board artifact must not be empty");
    ensure!(
        u64::try_from(length).context("artifact length does not fit u64")? <= MAX_ARTIFACT_BYTES,
        "DKG board artifact exceeds {MAX_ARTIFACT_BYTES} bytes",
    );
    Ok(())
}

impl BoardWriter {
    fn validate_slot(&self, slot: &ArtifactSlot) -> anyhow::Result<()> {
        ensure!(
            self.allowed_prefixes.contains(&slot.prefix()),
            "DKG board upload targets an unknown participant or artifact slot"
        );
        Ok(())
    }

    async fn store(&self, slot: &ArtifactSlot, value: &[u8]) -> anyhow::Result<Hash> {
        validate_artifact_length(value.len())?;
        self.validate_slot(slot)?;
        let prefix = slot.prefix();
        let expected_hash = Hash::new(value);
        let _guard = self.lock.lock().await;
        let entries = self
            .document
            .get_many(Query::key_prefix(prefix.as_bytes()))
            .await
            .context("failed to inspect DKG board artifact slot")?;
        futures::pin_mut!(entries);
        let mut hashes = Vec::new();
        while let Some(entry) = entries.next().await {
            let entry = entry.context("failed to read DKG board artifact slot")?;
            if entry.content_hash() == expected_hash {
                return Ok(expected_hash);
            }
            hashes.push(entry.content_hash());
            ensure!(
                hashes.len() < MAX_VALUES_PER_SLOT,
                "DKG board artifact slot already contains conflicting values"
            );
        }

        let stored_hash = self
            .document
            .set_bytes(self.author, slot.key(expected_hash), value.to_vec())
            .await
            .context("failed to publish DKG board artifact")?;
        ensure!(stored_hash == expected_hash, "Iroh stored artifact under an unexpected hash");
        Ok(stored_hash)
    }
}

impl UploadProtocol {
    async fn receive(&self, recv: &mut iroh::endpoint::RecvStream) -> anyhow::Result<Hash> {
        let mut header = [0u8; UPLOAD_HEADER_BYTES];
        recv.read_exact(&mut header)
            .await
            .context("failed to read DKG board upload header")?;
        ensure!(
            secrets_match(&header[..32], &self.upload_secret),
            "invalid DKG board upload secret"
        );
        let kind = header[32];
        let participant = u32::from_be_bytes(header[33..37].try_into().expect("fixed slice"));
        let length = u64::from_be_bytes(header[37..45].try_into().expect("fixed slice"));
        ensure!(
            length > 0 && length <= MAX_ARTIFACT_BYTES,
            "DKG board artifact exceeds {MAX_ARTIFACT_BYTES} bytes"
        );
        let slot = ArtifactSlot::from_upload_fields(kind, participant)?;
        self.writer.validate_slot(&slot)?;
        let length = usize::try_from(length).context("DKG board artifact length is too large")?;
        let mut value = vec![0u8; length];
        recv.read_exact(&mut value)
            .await
            .context("failed to read DKG board upload body")?;
        recv.read_to_end(0).await.context("DKG board upload has trailing bytes")?;
        self.writer.store(&slot, &value).await
    }
}

impl ProtocolHandler for UploadProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        if let Ok(result) =
            tokio::time::timeout(UPLOAD_TIMEOUT, self.serve_connection(&connection)).await
        {
            result
        } else {
            connection.close(1u32.into(), b"DKG board upload timed out");
            Ok(())
        }
    }
}

impl UploadProtocol {
    async fn serve_connection(&self, connection: &Connection) -> Result<(), AcceptError> {
        let _permit = self.permits.acquire().await.map_err(AcceptError::from_err)?;
        let (mut send, mut recv) = connection.accept_bi().await?;
        let response = match self.receive(&mut recv).await {
            Ok(hash) => {
                let mut response = Vec::with_capacity(UPLOAD_RESPONSE_BYTES);
                response.push(0);
                response.extend_from_slice(hash.as_bytes());
                response
            },
            Err(error) => upload_error_response(&error),
        };
        send.write_all(&response).await.map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

async fn upload_artifact(
    endpoint: &Endpoint,
    target: &EndpointAddr,
    upload_secret: &[u8; 32],
    slot: &ArtifactSlot,
    value: &[u8],
) -> anyhow::Result<Hash> {
    validate_artifact_length(value.len())?;
    let (kind, participant) = slot.upload_fields()?;
    upload_artifact_request(
        endpoint,
        target,
        upload_secret,
        kind,
        participant,
        u64::try_from(value.len()).context("artifact length does not fit u64")?,
        value,
    )
    .await
}

async fn upload_artifact_request(
    endpoint: &Endpoint,
    target: &EndpointAddr,
    upload_secret: &[u8; 32],
    kind: u8,
    participant: u32,
    declared_length: u64,
    value: &[u8],
) -> anyhow::Result<Hash> {
    let connection = endpoint
        .connect(target.clone(), UPLOAD_ALPN)
        .await
        .context("failed to connect to the DKG board upload service")?;
    let (mut send, mut recv) =
        connection.open_bi().await.context("failed to open a DKG board upload stream")?;
    let mut header = [0u8; UPLOAD_HEADER_BYTES];
    header[..32].copy_from_slice(upload_secret);
    header[32] = kind;
    header[33..37].copy_from_slice(&participant.to_be_bytes());
    header[37..45].copy_from_slice(&declared_length.to_be_bytes());
    send.write_all(&header)
        .await
        .context("failed to write DKG board upload header")?;
    send.write_all(value).await.context("failed to write DKG board upload body")?;
    send.finish().context("failed to finish DKG board upload")?;
    let response = tokio::time::timeout(
        UPLOAD_TIMEOUT,
        recv.read_to_end(UPLOAD_RESPONSE_BYTES + MAX_UPLOAD_ERROR_BYTES),
    )
    .await
    .context("timed out waiting for the DKG board upload response")?
    .context("failed to read DKG board upload response")?;
    connection.close(0u32.into(), b"upload complete");
    ensure!(!response.is_empty(), "DKG board returned an empty upload response");
    if response[0] != 0 {
        let message = std::str::from_utf8(&response[1..])
            .context("DKG board returned a non-UTF-8 upload error")?;
        anyhow::bail!("DKG board rejected the artifact: {message}");
    }
    ensure!(
        response.len() == UPLOAD_RESPONSE_BYTES,
        "DKG board returned an invalid upload response"
    );
    Ok(Hash::from_bytes(response[1..].try_into().expect("validated response length")))
}

fn upload_error_response(error: &anyhow::Error) -> Vec<u8> {
    let mut message = format!("{error:#}");
    if message.len() > MAX_UPLOAD_ERROR_BYTES {
        let mut end = MAX_UPLOAD_ERROR_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    let mut response = Vec::with_capacity(1 + message.len());
    response.push(1);
    response.extend_from_slice(message.as_bytes());
    response
}

fn secrets_match(candidate: &[u8], expected: &[u8; 32]) -> bool {
    candidate
        .iter()
        .zip(expected)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

impl BoardRuntime {
    async fn start(data_directory: &Path, use_network_services: bool) -> anyhow::Result<Self> {
        fs_err::create_dir_all(data_directory).with_context(|| {
            format!("failed to create Iroh data directory {}", data_directory.display())
        })?;
        let secret = load_or_create_endpoint_secret(data_directory)?;
        let builder = if use_network_services {
            Endpoint::builder(presets::N0)
        } else {
            Endpoint::builder(presets::Minimal)
        };
        let endpoint = builder
            .secret_key(secret)
            .bind()
            .await
            .context("failed to bind Iroh endpoint")?;
        let blobs_directory = data_directory.join("blobs");
        let docs_directory = data_directory.join("docs");
        fs_err::create_dir_all(&blobs_directory).context("failed to create Iroh blob directory")?;
        fs_err::create_dir_all(&docs_directory)
            .context("failed to create Iroh document directory")?;
        let blobs =
            FsStore::load(blobs_directory).await.context("failed to load Iroh blob store")?;
        let downloader = blobs.downloader(&endpoint);
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(docs_directory)
            .spawn(endpoint.clone(), blobs.as_ref().clone(), gossip.clone())
            .await
            .context("failed to load Iroh document store")?;
        let author = docs.author_default().await.context("failed to load Iroh author")?;
        Ok(Self {
            author,
            blobs,
            docs,
            downloader,
            endpoint,
            gossip,
        })
    }

    async fn attach(
        self,
        document: Doc,
        participant_count: usize,
        sync_targets: Vec<iroh::EndpointAddr>,
        served_upload_secret: Option<[u8; 32]>,
        remote_upload: Option<(EndpointAddr, [u8; 32])>,
    ) -> anyhow::Result<BoardNode> {
        ensure!(participant_count > 0, "DKG board requires at least one participant");
        ensure!(
            served_upload_secret.is_some() ^ remote_upload.is_some(),
            "DKG board must either serve or submit uploads"
        );
        let artifact_slot_count = participant_count
            .checked_mul(ARTIFACTS_PER_PARTICIPANT)
            .and_then(|count| count.checked_add(COMMON_ARTIFACT_COUNT))
            .context("DKG board participant count is too large")?;
        let max_document_entries = artifact_slot_count
            .checked_mul(MAX_VALUES_PER_SLOT)
            .context("DKG board participant count is too large")?;
        let allowed_prefixes = Arc::new(allowed_slot_prefixes(participant_count)?);
        inspect_document_metadata(&document, &allowed_prefixes, max_document_entries).await?;
        let writer = BoardWriter {
            author: self.author,
            document: document.clone(),
            allowed_prefixes: allowed_prefixes.clone(),
            lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        let publisher = match remote_upload {
            Some((target, upload_secret)) => Publisher::Remote {
                endpoint: self.endpoint.clone(),
                target,
                upload_secret,
            },
            None => Publisher::Local(writer.clone()),
        };
        let mut router = Router::builder(self.endpoint)
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(self.blobs.as_ref(), None))
            .accept(iroh_gossip::ALPN, self.gossip)
            .accept(iroh_docs::ALPN, self.docs.clone());
        if let Some(upload_secret) = served_upload_secret {
            router = router.accept(
                UPLOAD_ALPN,
                UploadProtocol {
                    permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS)),
                    upload_secret,
                    writer,
                },
            );
        }
        let router = router.spawn();
        let events = BoardEvents::start(&document).await?;
        Ok(BoardNode {
            blobs: self.blobs,
            document,
            downloader: self.downloader,
            event_error: events.error,
            event_task: events.task,
            allowed_prefixes,
            max_document_entries,
            peer_ready: events.peer_ready,
            publisher,
            remote_providers: events.remote_providers,
            router,
            sync_generation: events.sync_generation,
            sync_targets,
        })
    }
}

impl BoardEvents {
    async fn start(document: &Doc) -> anyhow::Result<Self> {
        let mut events =
            document.subscribe().await.context("failed to start DKG board event monitor")?;
        let (event_tx, error) = tokio::sync::watch::channel(None);
        let (peer_ready_tx, peer_ready) = tokio::sync::watch::channel(false);
        let (sync_generation_tx, sync_generation) = tokio::sync::watch::channel(0u64);
        let remote_providers =
            Arc::new(tokio::sync::RwLock::<BTreeMap<Hash, Vec<EndpointId>>>::default());
        let monitored_providers = remote_providers.clone();
        let task = tokio::spawn(async move {
            let mut neighbor_ready = false;
            let mut sync_ready = false;
            while let Some(event) = events.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        event_tx.send_replace(Some(error.to_string()));
                        break;
                    },
                };
                match &event {
                    LiveEvent::NeighborUp(_) => {
                        neighbor_ready = true;
                        if sync_ready {
                            peer_ready_tx.send_replace(true);
                        }
                    },
                    LiveEvent::NeighborDown(_) => {
                        neighbor_ready = false;
                        sync_ready = false;
                        peer_ready_tx.send_replace(false);
                    },
                    LiveEvent::SyncFinished(sync) if sync.result.is_ok() => {
                        sync_ready = true;
                        sync_generation_tx.send_modify(|generation| *generation += 1);
                        if neighbor_ready {
                            peer_ready_tx.send_replace(true);
                        }
                    },
                    _ => {},
                }
                if let LiveEvent::InsertRemote { from, entry, .. } = &event {
                    let mut providers = monitored_providers.write().await;
                    let providers = providers.entry(entry.content_hash()).or_default();
                    if !providers.contains(from) {
                        providers.push(*from);
                    }
                }
            }
        });
        Ok(Self {
            error,
            peer_ready,
            remote_providers,
            sync_generation,
            task,
        })
    }
}

fn allowed_slot_prefixes(participant_count: usize) -> anyhow::Result<Vec<String>> {
    let mut prefixes = vec![
        ArtifactSlot::Manifest.prefix(),
        ArtifactSlot::DecryptionConfig.prefix(),
        ArtifactSlot::ContextConfig.prefix(),
    ];
    for position in 0..participant_count {
        let participant = u32::try_from(position + 1).context("too many DKG participants")?;
        prefixes.extend([
            ArtifactSlot::Registration(participant).prefix(),
            ArtifactSlot::DecryptionDealing(participant).prefix(),
            ArtifactSlot::ContextDealing(participant).prefix(),
            ArtifactSlot::Transcript(participant).prefix(),
            ArtifactSlot::TranscriptAcceptance(participant).prefix(),
            ArtifactSlot::FinalConfirmation(participant).prefix(),
        ]);
    }
    Ok(prefixes)
}

async fn inspect_document_metadata(
    document: &Doc,
    allowed_prefixes: &[String],
    max_document_entries: usize,
) -> anyhow::Result<()> {
    let entries = document.get_many(Query::all()).await.context("failed to inspect DKG board")?;
    futures::pin_mut!(entries);
    let mut slots = BTreeMap::new();
    let mut count = 0usize;
    while let Some(entry) = entries.next().await {
        let entry = entry.context("failed to read DKG board entry")?;
        count += 1;
        ensure!(count <= max_document_entries, "DKG board contains too many entries");
        ensure!(
            entry.content_len() > 0 && entry.content_len() <= MAX_ARTIFACT_BYTES,
            "DKG board artifact exceeds {MAX_ARTIFACT_BYTES} bytes",
        );
        let key = std::str::from_utf8(entry.key()).context("DKG board key is not UTF-8")?;
        let (prefix, hash) = allowed_prefixes
            .iter()
            .find_map(|prefix| key.strip_prefix(prefix).map(|hash| (prefix, hash)))
            .context("DKG board contains an unrecognized artifact slot")?;
        ensure!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "DKG board key has an invalid content hash"
        );
        if let Some(previous) = slots.insert(prefix.clone(), hash.to_owned()) {
            ensure!(previous == hash, "DKG board contains conflicting artifacts for {prefix}");
        }
    }
    Ok(())
}

fn load_or_create_endpoint_secret(data_directory: &Path) -> anyhow::Result<SecretKey> {
    let path = data_directory.join(ENDPOINT_SECRET_FILE);
    if path.exists() {
        let bytes = fs_err::read_to_string(&path)
            .with_context(|| format!("failed to read Iroh endpoint secret {}", path.display()))?;
        let bytes = decode_fixed_hex::<32>(bytes.trim(), "Iroh endpoint secret")?;
        return Ok(SecretKey::from_bytes(&bytes));
    }

    let secret = SecretKey::generate();
    write_new_file(&path, hex::encode(secret.to_bytes()).as_bytes(), true)?;
    Ok(secret)
}

fn load_or_create_upload_secret(
    data_directory: &Path,
    allow_create: bool,
) -> anyhow::Result<[u8; 32]> {
    let path = data_directory.join(UPLOAD_SECRET_FILE);
    if path.exists() {
        let bytes = fs_err::read_to_string(&path).with_context(|| {
            format!("failed to read DKG board upload secret {}", path.display())
        })?;
        return decode_fixed_hex::<32>(bytes.trim(), "DKG board upload secret");
    }
    ensure!(
        allow_create,
        "this DKG board predates bounded uploads; start a new ceremony in a new data directory"
    );

    let secret = SecretKey::generate().to_bytes();
    write_new_file(&path, hex::encode(secret).as_bytes(), true)?;
    Ok(secret)
}

fn require_current_board_format(data_directory: &Path) -> anyhow::Result<()> {
    let path = data_directory.join(BOARD_FORMAT_FILE);
    let format = fs_err::read(&path).with_context(|| {
        format!(
            "this DKG board predates bounded uploads; start a new ceremony in a new data directory ({})",
            path.display()
        )
    })?;
    ensure!(
        format == BOARD_FORMAT,
        "unsupported DKG board format; start a new ceremony in a new data directory"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
