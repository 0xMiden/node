//! The Iroh adapter for the storage key DKG bulletin board.
//!
//! The board process is the only writer to the Iroh document. Validators receive a read-only
//! document ticket plus a participant-scoped secret for the board's bounded upload protocol. Each
//! [`ArtifactSlot`] is valid only while it holds at most one content-addressed value. A second
//! distinct value poisons that slot and stops the ceremony. This module only moves and stores
//! artifacts. The ceremony phases that use those artifacts are ordered in `runner`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use futures::StreamExt;
use iroh::endpoint::presets;
use iroh::protocol::Router;
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
use iroh_tickets::{ParseError, Ticket};
use serde::{Deserialize, Serialize};

mod persistence;
mod upload;

#[cfg(test)]
use persistence::ENDPOINT_SECRET_FILE;
use persistence::{
    BOARD_FORMAT_FILE,
    BOARD_METADATA_DIRECTORY,
    DOCUMENT_ID_FILE,
    UPLOAD_SECRETS_DIRECTORY,
    load_or_create_endpoint_secret,
    load_upload_secrets,
    publish_board_metadata,
    require_current_board_format,
};
#[cfg(test)]
use upload::upload_artifact_request;
use upload::{UPLOAD_ALPN, UploadProtocol, upload_artifact};

use super::super::{decode_fixed_hex, durably_create_directory_all};
use super::core::{
    ArtifactSlot,
    BoardCore,
    MAX_ARTIFACT_BYTES,
    PublishAction,
    SlotValues,
    validate_artifact_length,
};

const PEER_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// The board address and read capability, paired with one participant's upload permission.
///
/// This credential contains no DKG private material. Its holder can read public ceremony artifacts
/// and upload only to the named participant's slots.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct BoardTicket {
    document: DocTicket,
    participant: u32,
    upload_secret: [u8; 32],
}

impl BoardTicket {
    pub(super) fn participant(&self) -> u32 {
        self.participant
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
        Ticket::decode_string(value)
    }
}

pub(super) fn validate_ticket(value: &str) -> anyhow::Result<u32> {
    Ok(BoardTicket::from_str(value)?.participant())
}

pub(super) async fn create(
    data_directory: &Path,
    participant_count: usize,
    use_network_services: bool,
) -> anyhow::Result<(BoardNode, Vec<(String, u32)>)> {
    let (node, tickets) =
        BoardNode::create_with_network(data_directory, participant_count, use_network_services)
            .await?;
    let tickets = tickets
        .into_iter()
        .map(|ticket| {
            let participant = ticket.participant();
            (ticket.to_string(), participant)
        })
        .collect();
    Ok((node, tickets))
}

pub(super) async fn join(
    data_directory: &Path,
    encoded_ticket: &str,
    participant_count: usize,
    use_network_services: bool,
) -> anyhow::Result<BoardNode> {
    let ticket = BoardTicket::from_str(encoded_ticket)?;
    BoardNode::join_with_network(data_directory, ticket, participant_count, use_network_services)
        .await
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

#[derive(Debug)]
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
    downloader: Downloader,
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
    pub(super) async fn create_with_network(
        data_directory: &Path,
        participant_count: usize,
        use_network_services: bool,
    ) -> anyhow::Result<(Self, Vec<BoardTicket>)> {
        let runtime = BoardRuntime::start(data_directory, use_network_services).await?;
        let metadata_directory = data_directory.join(BOARD_METADATA_DIRECTORY);
        let (document, upload_secrets) = if metadata_directory.exists() {
            require_current_board_format(&metadata_directory)?;
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
            ensure!(
                !data_directory.join(DOCUMENT_ID_FILE).exists()
                    && !data_directory.join(BOARD_FORMAT_FILE).exists()
                    && !data_directory.join(UPLOAD_SECRETS_DIRECTORY).exists(),
                "unsupported DKG board format; start a new ceremony in a new data directory"
            );
            let document = runtime.docs.create().await.context("failed to create Iroh document")?;
            let upload_secrets = (0..participant_count)
                .map(|_| SecretKey::generate().to_bytes())
                .collect::<Vec<_>>();
            publish_board_metadata(&metadata_directory, &document, &upload_secrets)?;
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
        SlotValues::from_values(values.into_values()).into_unique(slot)
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

    /// Stops the board node and flushes its persistent stores.
    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        self.event_task.abort();
        self.router.shutdown().await.context("failed to stop Iroh board node")?;
        Ok(())
    }
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
        while let Some(entry) = entries.next().await {
            let entry = entry.context("failed to read DKG board artifact slot")?;
            hashes.push(entry.content_hash());
        }
        match SlotValues::from_values(hashes).publish(&expected_hash)? {
            PublishAction::AlreadyPresent => return Ok(expected_hash),
            PublishAction::Insert => {},
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

impl BoardRuntime {
    async fn start(data_directory: &Path, use_network_services: bool) -> anyhow::Result<Self> {
        durably_create_directory_all(data_directory).with_context(|| {
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
        let events = BoardEvents::start(&document).await?;
        Ok(BoardNode {
            blobs: self.blobs,
            core,
            document,
            downloader: self.downloader,
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
