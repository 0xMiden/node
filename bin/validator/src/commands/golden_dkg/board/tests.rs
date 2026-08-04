use super::*;

impl BoardNode {
    async fn create_for_test(data_directory: &Path) -> anyhow::Result<(Self, BoardTicket)> {
        Self::create_with_network(data_directory, 3, false).await
    }

    async fn join_for_test(data_directory: &Path, ticket: BoardTicket) -> anyhow::Result<Self> {
        Self::join_with_network(data_directory, &ticket.to_string(), 3, false).await
    }

    fn local_writer_for_test(&self) -> &BoardWriter {
        match &self.publisher {
            Publisher::Local(writer) => writer,
            Publisher::Remote { .. } => panic!("expected local Golden board writer"),
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
            Publisher::Remote { endpoint, target, upload_secret } => {
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
            Publisher::Local(_) => anyhow::bail!("expected remote Golden board publisher"),
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

#[tokio::test]
async fn artifact_syncs_between_board_nodes() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, ticket) = BoardNode::create_for_test(&root.path().join("host")).await?;
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
    let (host, first_ticket) = BoardNode::create_for_test(&data_directory).await?;
    host.publish(&ArtifactSlot::Manifest, b"manifest").await?;
    host.shutdown().await?;

    let (host, second_ticket) = BoardNode::create_for_test(&data_directory).await?;
    assert_eq!(first_ticket.document.capability.id(), second_ticket.document.capability.id());
    assert_eq!(first_ticket.upload_secret, second_ticket.upload_secret);
    assert_eq!(host.read_unique(&ArtifactSlot::Manifest).await?, Some(b"manifest".to_vec()));

    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unmarked_board_is_not_reopened_even_with_an_upload_secret() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let data_directory = root.path().join("host");
    let (host, _) = BoardNode::create_for_test(&data_directory).await?;
    host.shutdown().await?;
    fs_err::remove_file(data_directory.join(BOARD_FORMAT_FILE))?;

    let error = BoardNode::create_for_test(&data_directory)
        .await
        .err()
        .context("legacy board unexpectedly reopened")?;
    assert!(error.to_string().contains("predates bounded uploads"));
    Ok(())
}

#[tokio::test]
async fn unknown_participants_and_artifact_kinds_are_rejected_before_body_allocation()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, ticket) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let client = BoardNode::join_for_test(&root.path().join("client"), ticket).await?;

    let error = client.upload_raw_for_test(1, 99, MAX_ARTIFACT_BYTES, &[]).await.unwrap_err();
    assert!(error.to_string().contains("unknown participant or artifact slot"));
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
    let (host, ticket) = BoardNode::create_for_test(&root.path().join("host")).await?;
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
    let (host, mut ticket) = BoardNode::create_for_test(&root.path().join("host")).await?;
    ticket.upload_secret[0] ^= 1;
    let client = BoardNode::join_for_test(&root.path().join("client"), ticket).await?;

    let error = client
        .publish(&ArtifactSlot::Registration(1), b"signed registration")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("invalid Golden board upload secret"));
    assert!(host.read_unique(&ArtifactSlot::Registration(1)).await?.is_none());

    client.shutdown().await?;
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
