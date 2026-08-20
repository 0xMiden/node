use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::Hash;

use super::super::core::{ArtifactSlot, MAX_ARTIFACT_BYTES, validate_artifact_length};
use super::BoardWriter;

pub(super) const UPLOAD_ALPN: &[u8] = b"/miden/storage-key-dkg-board-upload/3";
const UPLOAD_HEADER_BYTES: usize = 32 + 1 + 4 + 8;
const UPLOAD_RESPONSE_BYTES: usize = 1 + 32;
const MAX_CONCURRENT_UPLOADS: usize = 3;
const MAX_UPLOAD_ERROR_BYTES: usize = 1024;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub(super) struct UploadProtocol {
    permits: Arc<tokio::sync::Semaphore>,
    upload_secrets: Arc<Vec<[u8; 32]>>,
    writer: BoardWriter,
}

impl UploadProtocol {
    pub(super) fn new(upload_secrets: Vec<[u8; 32]>, writer: BoardWriter) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS)),
            upload_secrets: Arc::new(upload_secrets),
            writer,
        }
    }

    async fn receive(&self, recv: &mut iroh::endpoint::RecvStream) -> anyhow::Result<Hash> {
        let mut header = [0u8; UPLOAD_HEADER_BYTES];
        recv.read_exact(&mut header)
            .await
            .context("failed to read DKG board upload header")?;
        let kind = header[32];
        let participant = u32::from_be_bytes(header[33..37].try_into().expect("fixed slice"));
        let secret_position = usize::try_from(participant)
            .context("participant index does not fit usize")?
            .checked_sub(1)
            .context("DKG board participant index must be nonzero")?;
        let expected_secret = self
            .upload_secrets
            .get(secret_position)
            .context("DKG board upload targets an unknown participant")?;
        ensure!(
            secrets_match(&header[..32], expected_secret),
            "DKG board ticket does not authorize this participant"
        );
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

impl ArtifactSlot {
    fn upload_fields(&self) -> anyhow::Result<(u8, u32)> {
        let fields = match self {
            Self::Registration(participant) => (1, *participant),
            Self::DecryptionDealing(participant) => (2, *participant),
            Self::ContextDealing(participant) => (3, *participant),
            Self::TranscriptAcceptance(participant) => (4, *participant),
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
            4 => Ok(Self::TranscriptAcceptance(participant)),
            _ => anyhow::bail!("DKG board upload contains an unknown artifact kind"),
        }
    }
}

pub(super) async fn upload_artifact(
    endpoint: &Endpoint,
    target: &EndpointAddr,
    authorized_participant: u32,
    upload_secret: &[u8; 32],
    slot: &ArtifactSlot,
    value: &[u8],
) -> anyhow::Result<Hash> {
    validate_artifact_length(value.len())?;
    let (kind, participant) = slot.upload_fields()?;
    ensure!(
        participant == authorized_participant,
        "DKG board ticket does not authorize participant {participant}"
    );
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

pub(super) async fn upload_artifact_request(
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
