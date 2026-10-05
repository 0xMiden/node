//! This module connects the storage key DKG board to Iroh.
//!
//! The board process is the only writer to the Iroh document. Validators receive a read-only
//! document ticket. A separate secret lets each validator upload to its own slots. Each
//! [`ArtifactSlot`] can hold only one distinct value. A different second value stops the ceremony.
//! The runner controls the ceremony phases.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use futures::StreamExt;
use iroh::endpoint::{Connection, presets};
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_blobs::api::remote::GetProgressItem;
use iroh_blobs::get::{GetError, StreamPair};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, Hash};
use iroh_docs::DocTicket;
use iroh_docs::api::Doc;
use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
use iroh_docs::engine::LiveEvent;
use iroh_docs::protocol::Docs;
use iroh_docs::store::{DownloadPolicy, Query};
use iroh_gossip::net::Gossip;
use iroh_tickets::{ParseError, Ticket};
use miden_node_utils::shutdown::CancellationToken;
use serde::{Deserialize, Serialize};

mod persistence;
mod upload;

#[cfg(test)]
use persistence::{BOARD_FORMAT_FILE, ENDPOINT_SECRET_FILE, UPLOAD_SECRETS_DIRECTORY};
use persistence::{
    BOARD_METADATA_DIRECTORY,
    DOCUMENT_ID_FILE,
    load_or_create_endpoint_secret,
    load_upload_secrets,
    publish_board_metadata,
    require_current_board_format,
};
#[cfg(test)]
use upload::upload_artifact_request;
use upload::{UPLOAD_ALPN, UploadProtocol, upload_artifact};

use super::super::{
    decode_fixed_hex,
    durably_create_directory_all,
    sync_directory,
    sync_directory_tree,
};
use super::core::{
    ArtifactSlot,
    BoardCore,
    MAX_ARTIFACT_BYTES,
    SlotValues,
    validate_artifact_length,
};
use super::{BoardPolicy, JoinCancelled};

const PEER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const PROVIDER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER_TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

/// This ticket gives its holder read access to the board and upload permission for one participant.
///
/// The ticket contains no private DKG material. Its holder can read public ceremony artifacts and
/// upload only to the named participant's slots.
#[derive(Clone, Deserialize, Serialize)]
pub(in crate::commands::dkg) struct BoardTicket {
    document: DocTicket,
    participant: u32,
    upload_secret: [u8; 32],
}

impl BoardTicket {
    pub(in crate::commands::dkg) fn participant(&self) -> u32 {
        self.participant
    }

    pub(in crate::commands::dkg) fn document_id(&self) -> [u8; 32] {
        self.document.capability.id().to_bytes()
    }
}

impl fmt::Debug for BoardTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoardTicket")
            .field("participant", &self.participant)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, Serialize)]
enum BoardTicketWireFormat {
    Variant0(BoardTicket),
}

impl Ticket for BoardTicket {
    const KIND: &'static str = "miden-storage-key-dkg-board";

    fn encode_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&BoardTicketWireFormat::Variant0(self.clone()))
            .expect("postcard serialization failed")
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let BoardTicketWireFormat::Variant0(ticket) = postcard::from_bytes(bytes)?;
        if ticket.participant == 0 {
            return Err(ParseError::verification_failed(
                "DKG board participant index must be nonzero",
            ));
        }
        if !matches!(ticket.document.capability, iroh_docs::Capability::Read(_)) {
            return Err(ParseError::verification_failed(
                "DKG board document ticket must be read-only",
            ));
        }
        if ticket.document.nodes.is_empty() {
            return Err(ParseError::verification_failed(
                "DKG board document addressing info cannot be empty",
            ));
        }
        if ticket.encode_bytes() != bytes {
            return Err(ParseError::verification_failed(
                "DKG board ticket must use canonical bytes",
            ));
        }
        Ok(ticket)
    }
}

impl fmt::Display for BoardTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&Ticket::encode_string(self))
    }
}

impl FromStr for BoardTicket {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let ticket: Self = Ticket::decode_string(value)?;
        if ticket.to_string() != value {
            return Err(ParseError::verification_failed(
                "DKG board ticket must use canonical text",
            ));
        }
        Ok(ticket)
    }
}

impl ArtifactSlot {
    fn key(&self, hash: Hash) -> String {
        format!("{}{}", self.prefix(), hash.to_hex())
    }
}

#[derive(Clone, Debug)]
struct BoardWriter {
    author: iroh_docs::AuthorId,
    core: Arc<BoardCore>,
    document: Doc,
    lock: Arc<tokio::sync::Mutex<()>>,
}

enum Publisher {
    Local(BoardWriter),
    Remote {
        endpoint: Endpoint,
        participant: u32,
        target: EndpointAddr,
        upload_secret: [u8; 32],
    },
}

/// A persistent Iroh node joined to one ceremony document.
pub(super) struct BoardNode {
    blobs: FsStore,
    core: Arc<BoardCore>,
    document: Doc,
    event_error: tokio::sync::watch::Receiver<Option<String>>,
    event_task: tokio::task::JoinHandle<()>,
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
    pub(super) async fn create_with_network(
        data_directory: &Path,
        participant_count: usize,
        policy: &BoardPolicy,
        use_network_services: bool,
    ) -> anyhow::Result<(Self, Vec<BoardTicket>)> {
        let metadata_directory = data_directory.join(BOARD_METADATA_DIRECTORY);
        let reopen = metadata_directory.exists();
        if reopen {
            require_current_board_format(&metadata_directory, policy)?;
        }
        let runtime = BoardRuntime::start(data_directory, use_network_services).await?;
        let (document, upload_secrets) = if reopen {
            let document_id_path = metadata_directory.join(DOCUMENT_ID_FILE);
            let id = fs_err::read_to_string(&document_id_path).with_context(|| {
                format!("failed to read Iroh document ID {}", document_id_path.display())
            })?;
            let id = decode_fixed_hex::<32>(id.trim(), "Iroh document ID")?;
            let document = runtime
                .docs
                .open(iroh_docs::NamespaceId::from(&id))
                .await
                .context("failed to open Iroh document")?
                .context("persisted Iroh document is missing")?;
            let upload_secrets = load_upload_secrets(&metadata_directory, participant_count)?;
            (document, upload_secrets)
        } else {
            let document = runtime.docs.create().await.context("failed to create Iroh document")?;
            persist_new_document(&document, data_directory).await?;
            let upload_secrets = (0..participant_count)
                .map(|_| SecretKey::generate().to_bytes())
                .collect::<Vec<_>>();
            publish_board_metadata(&metadata_directory, &document, &upload_secrets, policy)?;
            (document, upload_secrets)
        };
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
        let tickets = upload_secrets
            .iter()
            .enumerate()
            .map(|(position, upload_secret)| {
                Ok(BoardTicket {
                    document: document_ticket.clone(),
                    participant: u32::try_from(position + 1)
                        .context("too many DKG participants")?,
                    upload_secret: *upload_secret,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let board = runtime
            .attach(document, participant_count, Vec::new(), Some(upload_secrets), None)
            .await?;
        board
            .document
            .start_sync(Vec::new())
            .await
            .context("failed to start DKG board synchronization")?;
        Ok((board, tickets))
    }

    pub(super) async fn join_with_network(
        data_directory: &Path,
        ticket: BoardTicket,
        participant_count: usize,
        use_network_services: bool,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        let runtime = BoardRuntime::start(data_directory, use_network_services).await?;
        let BoardTicket { document, participant, upload_secret } = ticket;
        ensure!(
            usize::try_from(participant).context("participant index does not fit usize")?
                <= participant_count,
            "DKG board ticket names an unknown participant"
        );
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
            .attach(
                document,
                participant_count,
                nodes.clone(),
                None,
                Some((target, participant, upload_secret)),
            )
            .await?;
        board
            .document
            .start_sync(nodes)
            .await
            .context("failed to start DKG board synchronization")?;
        let admission = tokio::select! {
            result = board.wait_for_peer() => result,
            _ = shutdown.cancelled() => Err(JoinCancelled.into()),
        };
        match admission {
            Ok(()) => Ok(board),
            Err(error) => {
                board.shutdown().await?;
                Err(error)
            },
        }
    }

    /// Publishes one artifact without replacing another value in the same slot.
    pub(super) async fn publish(&self, slot: &ArtifactSlot, value: &[u8]) -> anyhow::Result<Hash> {
        self.ensure_admitted()?;
        validate_artifact_length(value.len())?;
        let expected_hash = Hash::new(value);
        let sync_generation = *self.sync_generation.borrow();
        let stored_hash = match &self.publisher {
            Publisher::Local(writer) => writer.store(slot, value).await?,
            Publisher::Remote {
                endpoint,
                participant,
                target,
                upload_secret,
            } => {
                upload_artifact(endpoint, target, *participant, upload_secret, slot, value).await?
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
        self.core.validate_slot(slot)?;
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
            if !self.blobs.blobs().has(hash).await.with_context(|| {
                format!("failed to check DKG board blob {hash} for {}", slot.prefix())
            })? {
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
                if !self.download_blob(hash, slot, providers, PROVIDER_TRANSFER_TIMEOUT).await? {
                    return Ok(None);
                }
            }
            let bytes = self.blobs.blobs().get_bytes(hash).await.with_context(|| {
                format!("failed to read DKG board blob {hash} for {}", slot.prefix())
            })?;
            ensure!(
                u64::try_from(bytes.len()).context("artifact length does not fit u64")?
                    == entry.content_len(),
                "DKG board artifact length does not match its entry"
            );
            values.entry(hash).or_insert_with(|| bytes.to_vec());
        }
        SlotValues::from_values(values.into_values()).into_unique(slot)
    }

    async fn download_blob(
        &self,
        hash: Hash,
        slot: &ArtifactSlot,
        providers: Vec<EndpointId>,
        transfer_timeout: Duration,
    ) -> anyhow::Result<bool> {
        let mut timed_out_provider = None;
        for provider in providers {
            let Ok(Ok(connection)) = tokio::time::timeout(
                PROVIDER_CONNECT_TIMEOUT,
                self.router.endpoint().connect(provider, iroh_blobs::ALPN),
            )
            .await
            else {
                continue;
            };
            let Ok(fetched) =
                tokio::time::timeout(transfer_timeout, self.fetch_blob(connection, hash, slot))
                    .await
            else {
                timed_out_provider = Some(provider);
                continue;
            };
            if fetched? {
                return Ok(true);
            }
        }
        if let Some(provider) = timed_out_provider {
            anyhow::bail!(
                "timed out after {} ms downloading DKG board blob {hash} for {} from provider {provider}",
                transfer_timeout.as_millis(),
                slot.prefix()
            );
        }
        Ok(false)
    }

    async fn fetch_blob(
        &self,
        connection: Connection,
        hash: Hash,
        slot: &ArtifactSlot,
    ) -> anyhow::Result<bool> {
        let Ok(Ok((send, recv))) =
            tokio::time::timeout(PROVIDER_CONNECT_TIMEOUT, connection.open_bi()).await
        else {
            return Ok(false);
        };
        let streams = StreamPair::new(connection.stable_id() as u64, recv, send);
        Self::read_fetch_progress(self.blobs.remote().fetch(streams, hash).stream(), hash, slot)
            .await
    }

    async fn read_fetch_progress(
        stream: impl futures::Stream<Item = GetProgressItem>,
        hash: Hash,
        slot: &ArtifactSlot,
    ) -> anyhow::Result<bool> {
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            match item {
                GetProgressItem::Progress(size) => ensure!(
                    size <= MAX_ARTIFACT_BYTES,
                    "DKG board artifact exceeds {MAX_ARTIFACT_BYTES} bytes",
                ),
                GetProgressItem::Done(_) => return Ok(true),
                GetProgressItem::Error(
                    error @ (GetError::LocalFailure { .. }
                    | GetError::IrpcSend { .. }
                    | GetError::BadRequest { .. }),
                ) => anyhow::bail!(
                    "failed to download DKG board blob {hash} for {}: {error:#}",
                    slot.prefix()
                ),
                GetProgressItem::Error(_) => return Ok(false),
            }
        }
        anyhow::bail!("DKG board blob download ended without a result")
    }

    async fn validate_document_metadata(&self) -> anyhow::Result<()> {
        self.ensure_admitted()?;
        inspect_document_metadata(
            &self.document,
            self.core.allowed_prefixes(),
            self.core.max_document_entries(),
        )
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

    /// Stops the board node and flushes the authoritative stores.
    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        self.event_task.abort();
        let writer_guard = match &self.publisher {
            Publisher::Local(writer) => Some(writer.lock.lock().await),
            Publisher::Remote { .. } => None,
        };
        let mut failures = Vec::new();
        if writer_guard.is_some() {
            if let Err(error) =
                self.blobs.sync_db().await.context("failed to flush Iroh blob store")
            {
                failures.push(format!("{error:#}"));
            }
            if let Err(error) = flush_document(&self.document).await {
                failures.push(format!("{error:#}"));
            }
        }
        if let Err(error) = self.router.shutdown().await.context("failed to stop Iroh board node") {
            failures.push(format!("{error:#}"));
        }
        ensure!(failures.is_empty(), "DKG board shutdown failed: {}", failures.join("; "));
        Ok(())
    }
}

async fn flush_document(document: &Doc) -> anyhow::Result<()> {
    let entries = document
        .get_many(Query::all())
        .await
        .context("failed to flush Iroh document store")?;
    futures::pin_mut!(entries);
    entries
        .next()
        .await
        .transpose()
        .context("failed to flush Iroh document store")?;
    Ok(())
}

async fn persist_new_document(document: &Doc, data_directory: &Path) -> anyhow::Result<()> {
    flush_document(document).await.context("failed to commit new Iroh document")?;
    sync_directory_tree(&data_directory.join("docs"))?;
    sync_directory(data_directory)
}

impl BoardWriter {
    fn validate_slot(&self, slot: &ArtifactSlot) -> anyhow::Result<()> {
        self.core.validate_slot(slot)
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
        let key = slot.key(expected_hash);
        let expected_len = u64::try_from(value.len())?;
        while let Some(entry) = entries.next().await {
            let entry = entry.context("failed to read DKG board artifact slot")?;
            let hash = entry.content_hash();
            let actual_key =
                std::str::from_utf8(entry.key()).context("DKG board key is not UTF-8")?;
            let expected_key = slot.key(hash);
            ensure!(
                actual_key == expected_key,
                "DKG board artifact key {actual_key} does not match expected {expected_key}"
            );
            ensure!(
                (1..=MAX_ARTIFACT_BYTES).contains(&entry.content_len()),
                "DKG board artifact length {} is outside 1..={MAX_ARTIFACT_BYTES}",
                entry.content_len()
            );
            if hash == expected_hash {
                ensure!(
                    entry.content_len() == expected_len,
                    "DKG board artifact length {} does not match expected {expected_len}",
                    entry.content_len()
                );
            }
            hashes.push(hash);
        }
        SlotValues::from_values(hashes).publish(&expected_hash)?;

        let stored_hash = self
            .document
            .set_bytes(self.author, key, value.to_vec())
            .await
            .context("failed to publish DKG board artifact")?;
        ensure!(stored_hash == expected_hash, "Iroh stored artifact under an unexpected hash");
        flush_document(&self.document).await?;
        Ok(stored_hash)
    }
}

impl BoardRuntime {
    async fn start(data_directory: &Path, use_network_services: bool) -> anyhow::Result<Self> {
        ensure!(cfg!(unix), "Iroh board stores require Unix private directory permissions");
        let data_directory = data_directory.components().collect::<PathBuf>();
        let data_directory = data_directory.as_path();
        let parent = data_directory
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        durably_create_directory_all(parent)
            .with_context(|| format!("failed to create Iroh data parent {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};

            match std::fs::DirBuilder::new().mode(0o700).create(data_directory) {
                Ok(()) => sync_directory(parent)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => return Err(error).context("failed to create Iroh data directory"),
            }
            let metadata = fs_err::symlink_metadata(data_directory)
                .context("failed to inspect Iroh data directory")?;
            let file_type = metadata.file_type();
            let kind = if file_type.is_dir() {
                "directory"
            } else if file_type.is_file() {
                "file"
            } else if file_type.is_symlink() {
                "symlink"
            } else if file_type.is_socket() {
                "socket"
            } else if file_type.is_fifo() {
                "FIFO"
            } else if file_type.is_char_device() {
                "character device"
            } else if file_type.is_block_device() {
                "block device"
            } else {
                "unknown"
            };
            // Group and other users must not have access to the board store.
            ensure!(
                file_type.is_dir() && metadata.permissions().mode().trailing_zeros() >= 6,
                "Iroh data directory {} must be a private directory (type: {}, mode: {:o})",
                data_directory.display(),
                kind,
                metadata.permissions().mode() & 0o777
            );
        }
        #[cfg(not(unix))]
        durably_create_directory_all(data_directory)
            .context("failed to create Iroh data directory")?;
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
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(docs_directory)
            .spawn(endpoint.clone(), blobs.as_ref().clone(), gossip.clone())
            .await
            .context("failed to load Iroh document store")?;
        let author = docs.author_default().await.context("failed to load Iroh author")?;
        Ok(Self { author, blobs, docs, endpoint, gossip })
    }

    async fn attach(
        self,
        document: Doc,
        participant_count: usize,
        sync_targets: Vec<iroh::EndpointAddr>,
        served_upload_secrets: Option<Vec<[u8; 32]>>,
        remote_upload: Option<(EndpointAddr, u32, [u8; 32])>,
    ) -> anyhow::Result<BoardNode> {
        ensure!(
            served_upload_secrets.is_some() ^ remote_upload.is_some(),
            "DKG board must either serve or submit uploads"
        );
        let core = Arc::new(BoardCore::new(participant_count)?);
        inspect_document_metadata(&document, core.allowed_prefixes(), core.max_document_entries())
            .await?;
        let writer = BoardWriter {
            author: self.author,
            core: core.clone(),
            document: document.clone(),
            lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        let board_peer = remote_upload.as_ref().map(|(target, ..)| target.id);
        let publisher = match remote_upload {
            Some((target, participant, upload_secret)) => Publisher::Remote {
                endpoint: self.endpoint.clone(),
                participant,
                target,
                upload_secret,
            },
            None => Publisher::Local(writer.clone()),
        };
        let mut router = Router::builder(self.endpoint)
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(self.blobs.as_ref(), None))
            .accept(iroh_gossip::ALPN, self.gossip)
            .accept(iroh_docs::ALPN, self.docs.clone());
        if let Some(upload_secrets) = served_upload_secrets {
            ensure!(
                upload_secrets.len() == participant_count,
                "DKG board requires one upload secret per participant"
            );
            router = router.accept(UPLOAD_ALPN, UploadProtocol::new(upload_secrets, writer));
        }
        let router = router.spawn();
        let events = BoardEvents::start(&document, board_peer).await?;
        Ok(BoardNode {
            blobs: self.blobs,
            core,
            document,
            event_error: events.error,
            event_task: events.task,
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
    async fn start(document: &Doc, board_peer: Option<EndpointId>) -> anyhow::Result<Self> {
        let mut events =
            document.subscribe().await.context("failed to start DKG board event monitor")?;
        let (event_tx, error) = tokio::sync::watch::channel(None);
        let (peer_ready_tx, peer_ready) = tokio::sync::watch::channel(false);
        let (sync_generation_tx, sync_generation) = tokio::sync::watch::channel(0u64);
        let remote_providers =
            Arc::new(tokio::sync::RwLock::<BTreeMap<Hash, Vec<EndpointId>>>::default());
        let monitored_providers = remote_providers.clone();
        let task = tokio::spawn(async move {
            while let Some(event) = events.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        event_tx.send_replace(Some(error.to_string()));
                        break;
                    },
                };
                if let Some(ready) = board_peer_status(&event, board_peer) {
                    peer_ready_tx.send_replace(ready);
                    if ready {
                        sync_generation_tx.send_modify(|generation| *generation += 1);
                    }
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

fn board_peer_status(event: &LiveEvent, board_peer: Option<EndpointId>) -> Option<bool> {
    match event {
        LiveEvent::NeighborDown(peer) if Some(*peer) == board_peer => Some(false),
        LiveEvent::SyncFinished(sync) if sync.result.is_ok() && Some(sync.peer) == board_peer => {
            Some(true)
        },
        _ => None,
    }
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

#[cfg(test)]
mod tests;
