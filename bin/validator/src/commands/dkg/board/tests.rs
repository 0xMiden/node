use super::*;

impl BoardNode {
    async fn create_for_test(data_directory: &Path) -> anyhow::Result<(Self, Vec<BoardTicket>)> {
        Self::create_with_network(data_directory, 3, false).await
    }

    async fn join_for_test(data_directory: &Path, ticket: BoardTicket) -> anyhow::Result<Self> {
        Self::join_with_network(data_directory, ticket, 3, false).await
    }

    fn local_writer_for_test(&self) -> &BoardWriter {
        match &self.publisher {
            Publisher::Local(writer) => writer,
            Publisher::Remote { .. } => panic!("expected local DKG board writer"),
        }
    }

    async fn upload_raw_for_test(
        &self,
        kind: u8,
        participant: u32,
        declared_length: u64,
        value: &[u8],
    ) -> anyhow::Result<Hash> {
        match &self.publisher {
            Publisher::Remote { endpoint, target, upload_secret, .. } => {
                upload_artifact_request(
                    endpoint,
                    target,
                    upload_secret,
                    kind,
                    participant,
                    declared_length,
                    value,
                )
                .await
            },
            Publisher::Local(_) => anyhow::bail!("expected remote DKG board publisher"),
        }
    }

    async fn publish_hash_for_test(
        &self,
        slot: &ArtifactSlot,
        hash: Hash,
        size: u64,
    ) -> anyhow::Result<()> {
        let writer = self.local_writer_for_test();
        self.document
            .set_hash(writer.author, slot.key(hash), hash, size)
            .await
            .context("failed to publish raw test hash")
    }
}

fn ticket_for(tickets: &[BoardTicket], participant: u32) -> BoardTicket {
    tickets
        .iter()
        .find(|ticket| ticket.participant == participant)
        .expect("participant ticket must exist")
        .clone()
}

#[test]
fn endpoint_secret_is_persisted_privately() -> anyhow::Result<()> {
    let data_directory = tempfile::tempdir()?;
    let first = load_or_create_endpoint_secret(data_directory.path())?;
    let second = load_or_create_endpoint_secret(data_directory.path())?;
    assert_eq!(first.to_bytes(), second.to_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs_err::metadata(data_directory.path().join(ENDPOINT_SECRET_FILE))?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    Ok(())
}

#[tokio::test]
async fn artifact_syncs_between_board_nodes() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let ticket = ticket_for(&tickets, 1);
    assert!(matches!(ticket.document.capability, iroh_docs::Capability::Read(_)));
    let client = BoardNode::join_for_test(&root.path().join("client"), ticket).await?;
    let slot = ArtifactSlot::Registration(1);
    let value = b"signed registration";

    client.publish(&slot, value).await?;
    assert_eq!(host.wait_unique(&slot, Duration::from_secs(10)).await?, value,);

    client.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn conflicting_artifacts_are_rejected() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, _) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let slot = ArtifactSlot::Manifest;

    host.publish(&slot, b"first").await?;
    host.publish(&slot, b"second").await?;
    let error = host.read_unique(&slot).await.unwrap_err();
    assert!(error.to_string().contains("conflicting artifacts"));

    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn board_reopens_the_same_document_after_restart() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let data_directory = root.path().join("host");
    let (host, first_tickets) = BoardNode::create_for_test(&data_directory).await?;
    host.publish(&ArtifactSlot::Manifest, b"manifest").await?;
    host.shutdown().await?;

    let (host, second_tickets) = BoardNode::create_for_test(&data_directory).await?;
    assert_eq!(first_tickets.len(), second_tickets.len());
    for (first, second) in first_tickets.iter().zip(&second_tickets) {
        assert_eq!(first.participant, second.participant);
        assert_eq!(first.document.capability.id(), second.document.capability.id());
        assert_eq!(first.upload_secret, second.upload_secret);
    }
    assert_eq!(host.read_unique(&ArtifactSlot::Manifest).await?, Some(b"manifest".to_vec()));

    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn board_metadata_is_published_as_one_directory() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let data_directory = root.path().join("host");
    let (host, _) = BoardNode::create_for_test(&data_directory).await?;

    let metadata_directory = data_directory.join(BOARD_METADATA_DIRECTORY);
    assert!(metadata_directory.join(DOCUMENT_ID_FILE).is_file());
    assert!(metadata_directory.join(BOARD_FORMAT_FILE).is_file());
    assert!(metadata_directory.join(UPLOAD_SECRETS_DIRECTORY).is_dir());
    assert!(!data_directory.join(DOCUMENT_ID_FILE).exists());
    assert!(!data_directory.join(BOARD_FORMAT_FILE).exists());
    assert!(!data_directory.join(UPLOAD_SECRETS_DIRECTORY).exists());

    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn incomplete_board_metadata_is_rejected() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let data_directory = root.path().join("host");
    let (host, _) = BoardNode::create_for_test(&data_directory).await?;
    host.shutdown().await?;
    fs_err::remove_file(data_directory.join(BOARD_METADATA_DIRECTORY).join(BOARD_FORMAT_FILE))?;

    let error = BoardNode::create_for_test(&data_directory)
        .await
        .err()
        .context("incomplete board metadata unexpectedly reopened")?;
    assert!(error.to_string().contains("failed to read DKG board format"));
    Ok(())
}

#[tokio::test]
async fn legacy_board_metadata_is_rejected() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let data_directory = root.path().join("host");
    let upload_secrets_directory = data_directory.join(UPLOAD_SECRETS_DIRECTORY);
    fs_err::create_dir_all(&upload_secrets_directory)?;
    fs_err::write(data_directory.join(DOCUMENT_ID_FILE), hex::encode([0; 32]))?;
    fs_err::write(data_directory.join(BOARD_FORMAT_FILE), b"participant-upload-v3\n")?;
    for participant in 1..=3 {
        fs_err::write(
            upload_secrets_directory.join(format!("participant-{participant}.hex")),
            hex::encode([0; 32]),
        )?;
    }

    let error = BoardNode::create_for_test(&data_directory)
        .await
        .err()
        .context("legacy board metadata unexpectedly reopened")?;
    assert!(error.to_string().contains("unsupported DKG board format"));
    assert!(!data_directory.join(BOARD_METADATA_DIRECTORY).exists());
    Ok(())
}

#[tokio::test]
async fn previous_board_format_is_not_reopened() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let data_directory = root.path().join("host");
    let (host, _) = BoardNode::create_for_test(&data_directory).await?;
    host.shutdown().await?;
    fs_err::write(
        data_directory.join(BOARD_METADATA_DIRECTORY).join(BOARD_FORMAT_FILE),
        b"participant-upload-v3\n",
    )?;

    let error = BoardNode::create_for_test(&data_directory)
        .await
        .err()
        .context("old board format unexpectedly reopened")?;
    assert!(error.to_string().contains("unsupported DKG board format"));
    Ok(())
}

#[test]
fn legacy_board_ticket_is_rejected() {
    BoardTicket::from_str("miden-storage-key-dkg-board-v3:1:00:invalid")
        .expect_err("old board ticket unexpectedly parsed");
}

#[tokio::test]
async fn board_ticket_round_trips_and_validates_fields() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, mut tickets) = BoardNode::create_for_test(root.path()).await?;
    let ticket = tickets.remove(0);
    let encoded = ticket.to_string();
    let decoded = BoardTicket::from_str(&encoded)?;
    assert_eq!(decoded.to_string(), encoded);

    let mut invalid = ticket.clone();
    invalid.participant = 0;
    let error = BoardTicket::from_str(&invalid.to_string())
        .expect_err("zero participant ticket unexpectedly parsed");
    assert!(error.to_string().contains("must be nonzero"));

    invalid = ticket;
    invalid.document.nodes.clear();
    let error = BoardTicket::from_str(&invalid.to_string())
        .expect_err("ticket without addressing info unexpectedly parsed");
    assert!(error.to_string().contains("addressing info cannot be empty"));

    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unknown_participants_and_artifact_kinds_are_rejected_before_body_allocation()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let ticket = ticket_for(&tickets, 1);
    let client = BoardNode::join_for_test(&root.path().join("client"), ticket).await?;

    let error = client.upload_raw_for_test(1, 99, MAX_ARTIFACT_BYTES, &[]).await.unwrap_err();
    assert!(error.to_string().contains("unknown participant"));
    let error = client.upload_raw_for_test(255, 1, 16, b"private artifact").await.unwrap_err();
    assert!(error.to_string().contains("unknown artifact kind"));
    assert!(host.read_unique(&ArtifactSlot::Registration(1)).await?.is_none());

    client.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[test]
fn oversized_artifacts_are_rejected_before_allocation() {
    let oversized = usize::try_from(MAX_ARTIFACT_BYTES).unwrap() + 1;
    assert!(validate_artifact_length(oversized).is_err());
}

#[tokio::test]
async fn oversized_upload_is_rejected_before_body_allocation() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let ticket = ticket_for(&tickets, 1);
    let client = BoardNode::join_for_test(&root.path().join("client"), ticket).await?;
    let error = client.upload_raw_for_test(1, 1, MAX_ARTIFACT_BYTES + 1, &[]).await.unwrap_err();
    assert!(error.to_string().contains("exceeds"));
    assert!(host.read_unique(&ArtifactSlot::Registration(1)).await?.is_none());

    client.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn invalid_upload_secret_is_rejected_before_storage() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let mut ticket = ticket_for(&tickets, 1);
    ticket.upload_secret[0] ^= 1;
    let client = BoardNode::join_for_test(&root.path().join("client"), ticket).await?;

    let error = client
        .publish(&ArtifactSlot::Registration(1), b"signed registration")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not authorize this participant"));
    assert!(host.read_unique(&ArtifactSlot::Registration(1)).await?.is_none());

    client.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn participant_ticket_cannot_publish_another_participants_slot() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let first =
        BoardNode::join_for_test(&root.path().join("first"), ticket_for(&tickets, 1)).await?;

    let error = first
        .upload_raw_for_test(
            1,
            2,
            u64::try_from(b"wrong registration".len())?,
            b"wrong registration",
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not authorize this participant"));
    assert!(host.read_unique(&ArtifactSlot::Registration(2)).await?.is_none());

    let second =
        BoardNode::join_for_test(&root.path().join("second"), ticket_for(&tickets, 2)).await?;
    second.publish(&ArtifactSlot::Registration(2), b"signed registration").await?;
    assert_eq!(
        host.wait_unique(&ArtifactSlot::Registration(2), Duration::from_secs(10))
            .await?,
        b"signed registration"
    );

    first.shutdown().await?;
    second.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn invalid_download_metadata_is_rejected() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, _) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let slot = ArtifactSlot::Manifest;
    let value = b"manifest";
    let hash = host.publish(&slot, value).await?;

    host.publish_hash_for_test(&slot, hash, 1).await?;
    let error = host.read_unique(&slot).await.unwrap_err();
    assert!(error.to_string().contains("length does not match"));

    host.shutdown().await?;
    Ok(())
}
