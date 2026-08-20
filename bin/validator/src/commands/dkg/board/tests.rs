use std::time::Duration;

use super::*;

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

async fn assert_board_contract(
    coordinator: &CoordinatorBoard,
    participants: &[ParticipantBoard],
) -> anyhow::Result<()> {
    let wait_for_manifest =
        participants[0].reader().wait_unique(&ArtifactSlot::Manifest, WAIT_TIMEOUT);
    let publish_manifest = async {
        tokio::task::yield_now().await;
        coordinator.publish(CommonArtifact::Manifest, b"manifest").await
    };
    let (manifest, publish_result) = tokio::join!(wait_for_manifest, publish_manifest);
    publish_result?;
    assert_eq!(manifest?, b"manifest");

    coordinator.publish(CommonArtifact::Manifest, b"manifest").await?;

    participants[0]
        .publish(ParticipantArtifact::Registration, b"registration")
        .await?;
    participants[0]
        .publish(ParticipantArtifact::Registration, b"registration")
        .await?;
    assert_eq!(
        coordinator
            .reader()
            .wait_unique(&ArtifactSlot::Registration(1), WAIT_TIMEOUT)
            .await?,
        b"registration"
    );

    assert!(coordinator.publish(CommonArtifact::ContextConfig, b"").await.is_err());
    assert!(coordinator.reader().read_unique(&ArtifactSlot::Registration(3)).await.is_err());

    coordinator.publish(CommonArtifact::Manifest, b"other manifest").await?;
    assert!(coordinator.reader().read_unique(&ArtifactSlot::Manifest).await.is_err());
    Ok(())
}

async fn shutdown_boards(
    coordinator: CoordinatorBoard,
    participants: Vec<ParticipantBoard>,
) -> anyhow::Result<()> {
    for participant in participants {
        participant.shutdown().await?;
    }
    coordinator.shutdown().await
}

#[tokio::test]
async fn memory_adapter_obeys_board_contract() -> anyhow::Result<()> {
    let (coordinator, participants) = CoordinatorBoard::create_memory(2)?;
    assert_board_contract(&coordinator, &participants).await?;
    shutdown_boards(coordinator, participants).await
}

#[tokio::test]
async fn iroh_adapter_obeys_board_contract() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (coordinator, tickets) =
        CoordinatorBoard::create_with_network(&root.path().join("coordinator"), 2, false).await?;
    let mut participants = Vec::new();
    for (position, ticket) in tickets.into_iter().enumerate() {
        participants.push(
            ParticipantBoard::join_with_network(
                &root.path().join(format!("participant-{}", position + 1)),
                ticket,
                2,
                false,
            )
            .await?,
        );
    }
    assert_board_contract(&coordinator, &participants).await?;
    shutdown_boards(coordinator, participants).await
}
