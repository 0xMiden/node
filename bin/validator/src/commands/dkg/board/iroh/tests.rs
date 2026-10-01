use super::*;

#[test]
fn unrelated_neighbor_does_not_change_board_admission() {
    let board_peer = SecretKey::from_bytes(&[1; 32]).public();
    let other_peer = SecretKey::from_bytes(&[2; 32]).public();
    assert_eq!(board_peer_status(&LiveEvent::NeighborDown(other_peer), Some(board_peer)), None);
    assert_eq!(
        board_peer_status(&LiveEvent::NeighborDown(board_peer), Some(board_peer)),
        Some(false)
    );
}

impl BoardNode {
    async fn create_for_test(data_directory: &Path) -> anyhow::Result<(Self, Vec<BoardTicket>)> {
        Self::create_with_network(data_directory, 3, false).await
    }

    async fn join_for_test(data_directory: &Path, ticket: BoardTicket) -> anyhow::Result<Self> {
        Self::join_with_network(data_directory, ticket, 3, false, CancellationToken::new()).await
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

fn blob_provider_address(provider: &BoardNode) -> anyhow::Result<EndpointAddr> {
    let mut socket = provider
        .router
        .endpoint()
        .bound_sockets()
        .into_iter()
        .find(std::net::SocketAddr::is_ipv4)
        .context("Iroh test endpoint has no IPv4 socket")?;
    socket.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    Ok(EndpointAddr::from_parts(
        provider.router.endpoint().id(),
        [iroh::TransportAddr::Ip(socket)],
    ))
}

fn assert_upload_close_reason(error: iroh::endpoint::ConnectionError, expected: &[u8]) {
    match error {
        iroh::endpoint::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.reason.as_ref(), expected);
        },
        other => panic!("unexpected upload close reason: {other}"),
    }
}

async fn connect_blob_provider(host: &BoardNode, provider: &BoardNode) -> anyhow::Result<()> {
    host.router
        .endpoint()
        .connect(blob_provider_address(provider)?, iroh_blobs::ALPN)
        .await?;
    Ok(())
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

#[cfg(unix)]
#[tokio::test]
async fn board_data_directory_is_private_under_public_parent() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir()?;
    fs_err::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))?;
    let data_directory = root.path().join("board");
    let runtime = BoardRuntime::start(&data_directory, false).await?;
    assert_eq!(fs_err::metadata(&data_directory)?.permissions().mode() & 0o777, 0o700);
    drop(runtime);

    fs_err::set_permissions(&data_directory, std::fs::Permissions::from_mode(0o755))?;
    let error = BoardRuntime::start(&data_directory, false)
        .await
        .err()
        .context("public board data directory was accepted")?;
    assert!(error.to_string().contains("must be a private directory"));

    fs_err::set_permissions(&data_directory, std::fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::symlink(&data_directory, root.path().join("link"))?;
    let error = BoardRuntime::start(&root.path().join("link/"), false)
        .await
        .err()
        .context("symlinked board data directory was accepted")?;
    assert!(error.to_string().contains("must be a private directory"));
    assert!(error.to_string().contains("link"));
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
async fn board_metadata_points_to_a_committed_document() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let data_directory = root.path().join("host");
    let runtime = BoardRuntime::start(&data_directory, false).await?;
    let document = runtime.docs.create().await?;
    persist_new_document(&document, &data_directory).await?;
    let metadata_directory = data_directory.join(BOARD_METADATA_DIRECTORY);
    assert!(!metadata_directory.exists());
    publish_board_metadata(&metadata_directory, &document, &[[1; 32]; 3])?;

    let snapshot_path = root.path().join("snapshot.redb");
    fs_err::copy(data_directory.join("docs/docs.redb"), &snapshot_path)?;
    let mut snapshot = iroh_docs::store::fs::Store::persistent(&snapshot_path)?;
    snapshot.open_replica(&document.id())?;

    drop(runtime);
    Ok(())
}

#[tokio::test]
async fn joining_an_unavailable_board_can_be_cancelled() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let ticket = ticket_for(&tickets, 1);
    host.shutdown().await?;
    let work_directory = root.path().join("participant");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let work_directory = work_directory.clone();
        let shutdown = shutdown.clone();
        async move {
            match BoardNode::join_with_network(&work_directory, ticket, 3, false, shutdown).await {
                Ok(board) => {
                    board.shutdown().await?;
                    anyhow::bail!("joined an unavailable board")
                },
                Err(error) => Ok(error),
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while !work_directory.join("docs/docs.redb").is_file() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(!task.is_finished());
    shutdown.cancel();
    let error = tokio::time::timeout(Duration::from_secs(10), task).await???;
    assert_eq!(error.to_string(), "DKG board join cancelled");
    let store = FsStore::load(work_directory.join("blobs")).await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn only_the_ticket_endpoint_can_admit_a_participant() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let host_directory = root.path().join("host");
    let (host, tickets) = BoardNode::create_for_test(&host_directory).await?;
    let ticket = ticket_for(&tickets, 1);
    let other =
        BoardNode::join_for_test(&root.path().join("other"), ticket_for(&tickets, 2)).await?;
    let other_addr = blob_provider_address(&other)?;
    let other_id = other_addr.id;
    let host_addr = ticket.document.nodes[0].clone();
    host.shutdown().await?;

    let runtime = BoardRuntime::start(&root.path().join("joining"), false).await?;
    let document = runtime.docs.import_namespace(ticket.document.capability).await?;
    document.set_download_policy(DownloadPolicy::NothingExcept(Vec::new())).await?;
    let mut joining = runtime
        .attach(
            document,
            3,
            vec![other_addr.clone()],
            None,
            Some((host_addr.clone(), ticket.participant, ticket.upload_secret)),
        )
        .await?;
    let mut events = joining.document.subscribe().await?;
    joining.document.start_sync(vec![other_addr]).await?;
    let mut neighbor_up = false;
    let mut sync_finished = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !neighbor_up || !sync_finished {
            let event = events.next().await.transpose()?.context("DKG board event stream ended")?;
            match event {
                LiveEvent::NeighborUp(peer) if peer == other_id => neighbor_up = true,
                LiveEvent::SyncFinished(sync) if sync.peer == other_id && sync.result.is_ok() => {
                    sync_finished = true;
                },
                _ => {},
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("unrelated peer did not synchronize")??;
    let mut ready = joining.peer_ready.clone();
    assert!(
        tokio::time::timeout(Duration::from_millis(250), ready.wait_for(|ready| *ready))
            .await
            .is_err()
    );

    let (host, _) = BoardNode::create_for_test(&host_directory).await?;
    joining.document.start_sync(vec![blob_provider_address(&host)?]).await?;
    tokio::time::timeout(Duration::from_secs(10), joining.peer_ready.wait_for(|ready| *ready))
        .await
        .context("ticket endpoint did not synchronize after restart")??;
    joining.shutdown().await?;
    other.shutdown().await?;
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
    let data_directory = tempfile::tempdir_in(root.path())?;
    let data_directory = data_directory.path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs_err::set_permissions(data_directory, std::fs::Permissions::from_mode(0o700))?;
    }
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

    let error = BoardNode::create_for_test(data_directory)
        .await
        .err()
        .context("legacy board metadata unexpectedly reopened")?;
    assert!(error.to_string().contains("unsupported DKG board format"), "{error:#}");
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
    let (host, mut tickets) = BoardNode::create_for_test(&root.path().join("board")).await?;
    let ticket = tickets.remove(0);
    let encoded = ticket.to_string();
    let decoded = BoardTicket::from_str(&encoded)?;
    assert_eq!(decoded.to_string(), encoded);
    let mut trailing_bytes = ticket.encode_bytes();
    trailing_bytes.push(0);
    assert!(BoardTicket::decode_bytes(&trailing_bytes).is_err());
    let alternate_case = format!(
        "{}{}",
        BoardTicket::KIND,
        encoded[BoardTicket::KIND.len()..].to_ascii_uppercase(),
    );
    assert_ne!(alternate_case, encoded);
    assert!(BoardTicket::from_str(&alternate_case).is_err());

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
    let error = validate_artifact_length(oversized).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("DKG board artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
    );
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
async fn stalled_headers_do_not_block_authorized_uploads() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let client =
        BoardNode::join_for_test(&root.path().join("client"), ticket_for(&tickets, 1)).await?;
    let (endpoint, target) = match &client.publisher {
        Publisher::Remote { endpoint, target, .. } => (endpoint, target),
        Publisher::Local(_) => unreachable!(),
    };
    let mut stalled = Vec::new();
    for _ in 0..3 {
        let connection = endpoint.connect(target.clone(), UPLOAD_ALPN).await?;
        let (mut send, _recv) = connection.open_bi().await?;
        send.write_all(&[0]).await?;
        stalled.push((connection, send));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let slot = ArtifactSlot::Registration(1);
    let value = b"signed registration";
    tokio::time::timeout(Duration::from_millis(2500), client.publish(&slot, value)).await??;
    assert!(stalled.iter().all(|(connection, _)| connection.close_reason().is_none()));
    assert_eq!(host.read_unique(&slot).await?, Some(value.to_vec()));

    drop(stalled);
    client.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn upload_header_capacity_is_bounded() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let client =
        BoardNode::join_for_test(&root.path().join("client"), ticket_for(&tickets, 1)).await?;
    let (endpoint, target) = match &client.publisher {
        Publisher::Remote { endpoint, target, .. } => (endpoint, target),
        Publisher::Local(_) => unreachable!(),
    };
    for incomplete_header in [false, true] {
        let mut stalled = Vec::new();
        for _ in 0..16 {
            let connection = endpoint.connect(target.clone(), UPLOAD_ALPN).await?;
            let send = if incomplete_header {
                let (mut send, _recv) = connection.open_bi().await?;
                send.write_all(&[0]).await?;
                Some(send)
            } else {
                None
            };
            stalled.push((connection, send));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let excess = endpoint.connect(target.clone(), UPLOAD_ALPN).await?;
        let reason = tokio::time::timeout(Duration::from_secs(2), excess.closed()).await?;
        assert_upload_close_reason(reason, b"too many DKG board upload headers");

        tokio::time::timeout(Duration::from_secs(5), async {
            for (connection, _) in &stalled {
                assert_upload_close_reason(
                    connection.closed().await,
                    b"DKG board upload header timed out",
                );
            }
        })
        .await?;
        client.publish(&ArtifactSlot::Registration(1), b"signed registration").await?;
    }
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

#[tokio::test]
async fn blob_store_failure_is_reported() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, _) = BoardNode::create_for_test(&root.path().join("board")).await?;
    let slot = ArtifactSlot::Manifest;
    host.publish(&slot, b"manifest").await?;
    host.event_task.abort();
    host.blobs.shutdown().await?;

    let error = host.read_unique(&slot).await.unwrap_err();
    assert!(error.to_string().contains("failed to check DKG board blob"));
    let error = host.wait_unique(&slot, Duration::from_secs(1)).await.unwrap_err();
    assert!(error.to_string().contains("failed to check DKG board blob"));

    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unavailable_blob_remains_retryable() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let provider =
        BoardNode::join_for_test(&root.path().join("provider"), ticket_for(&tickets, 1)).await?;
    connect_blob_provider(&host, &provider).await?;
    let slot = ArtifactSlot::Manifest;
    let missing = b"unavailable";
    let hash = Hash::new(missing);
    host.publish_hash_for_test(&slot, hash, u64::try_from(missing.len())?).await?;
    host.remote_providers
        .write()
        .await
        .insert(hash, vec![provider.router.endpoint().id()]);

    assert!(host.read_unique(&slot).await?.is_none());
    let _tag = provider.blobs.blobs().add_slice(missing).await?;
    assert_eq!(host.wait_unique(&slot, Duration::from_secs(10)).await?, missing);

    provider.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn disconnected_blob_provider_fails_over() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let first =
        BoardNode::join_for_test(&root.path().join("first"), ticket_for(&tickets, 1)).await?;
    let second =
        BoardNode::join_for_test(&root.path().join("second"), ticket_for(&tickets, 2)).await?;
    connect_blob_provider(&host, &first).await?;
    connect_blob_provider(&host, &second).await?;
    let closed_connection = host
        .router
        .endpoint()
        .connect(blob_provider_address(&first)?, iroh_blobs::ALPN)
        .await?;
    closed_connection.close(1u32.into(), b"test disconnect");
    assert!(
        !host
            .fetch_blob(closed_connection, Hash::new(b"missing"), &ArtifactSlot::Manifest)
            .await?
    );
    let first_id = first.router.endpoint().id();
    first.shutdown().await?;

    let slot = ArtifactSlot::Manifest;
    let value = b"available from second provider";
    let hash = Hash::new(value);
    let _tag = second.blobs.blobs().add_slice(value).await?;
    host.publish_hash_for_test(&slot, hash, u64::try_from(value.len())?).await?;
    host.remote_providers
        .write()
        .await
        .insert(hash, vec![first_id, second.router.endpoint().id()]);

    assert_eq!(host.wait_unique(&slot, Duration::from_secs(10)).await?, value);
    second.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn local_fetch_error_is_reported() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let provider =
        BoardNode::join_for_test(&root.path().join("provider"), ticket_for(&tickets, 1)).await?;
    let connection = host
        .router
        .endpoint()
        .connect(blob_provider_address(&provider)?, iroh_blobs::ALPN)
        .await?;
    let (send, recv) = connection.open_bi().await?;
    let streams = StreamPair::new(connection.stable_id() as u64, recv, send);
    let failed_store_directory = root.path().join("failed-store");
    fs_err::create_dir(&failed_store_directory)?;
    let failed_store = FsStore::load(failed_store_directory).await?;
    failed_store.shutdown().await?;
    let hash = Hash::new(b"missing");
    let slot = ArtifactSlot::Manifest;
    let error = BoardNode::read_fetch_progress(
        failed_store.remote().fetch(streams, hash).stream(),
        hash,
        &slot,
    )
    .await
    .unwrap_err();
    let message = format!("{error:#}");
    assert_eq!(
        message,
        format!(
            "failed to download DKG board blob {hash} for {}: local failure: inner error: Error::Io: Error::Io: unexpected end of stream",
            slot.prefix()
        )
    );

    provider.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn local_download_import_failure_is_reported() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (host, tickets) = BoardNode::create_for_test(&root.path().join("host")).await?;
    let provider =
        BoardNode::join_for_test(&root.path().join("provider"), ticket_for(&tickets, 1)).await?;
    connect_blob_provider(&host, &provider).await?;
    let slot = ArtifactSlot::Manifest;
    let value = vec![7; 16 * 1024 + 1];
    let hash = Hash::new(&value);
    let _tag = provider.blobs.blobs().add_slice(&value).await?;
    host.publish_hash_for_test(&slot, hash, u64::try_from(value.len())?).await?;
    host.remote_providers
        .write()
        .await
        .insert(hash, vec![provider.router.endpoint().id()]);

    let data_directory = root.path().join("host/blobs/data");
    fs_err::remove_dir(&data_directory)?;
    fs_err::write(&data_directory, b"block blob imports")?;

    let error = host.read_unique(&slot).await.unwrap_err();
    assert!(format!("{error:#}").contains("failed to read DKG board blob"), "{error:#}");
    let error = host.wait_unique(&slot, Duration::from_secs(1)).await.unwrap_err();
    assert!(format!("{error:#}").contains("failed to read DKG board blob"));

    fs_err::remove_file(&data_directory)?;
    fs_err::create_dir(&data_directory)?;
    provider.shutdown().await?;
    host.shutdown().await?;
    Ok(())
}
