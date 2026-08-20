//! This module defines the artifact slots and board roles for storage key DKG.
//!
//! The coordinator and validators use separate board roles. Private adapters handle Iroh access
//! and storage.

use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

mod core;
mod iroh;

pub(super) use core::ArtifactSlot;

/// An opaque board address and one participant's publish permission.
#[derive(Clone)]
pub(super) struct BoardTicket {
    encoded: String,
    participant: u32,
}

impl BoardTicket {
    fn new(encoded: String, participant: u32) -> Self {
        Self { encoded, participant }
    }

    pub(super) fn participant(&self) -> u32 {
        self.participant
    }

    fn into_encoded(self) -> String {
        self.encoded
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

impl fmt::Display for BoardTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encoded)
    }
}

impl FromStr for BoardTicket {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let participant = iroh::validate_ticket(value)?;
        Ok(Self::new(value.to_owned(), participant))
    }
}

/// An artifact published by the ceremony coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommonArtifact {
    Manifest,
    DecryptionConfig,
    ContextConfig,
}

/// An artifact published by one ceremony participant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParticipantArtifact {
    Registration,
    DecryptionDealing,
    ContextDealing,
    TranscriptAcceptance,
}

/// The read-only view shared by both board roles.
pub(super) struct BoardReader {
    node: iroh::BoardNode,
}

impl BoardReader {
    /// Reads the unique content value published for one artifact slot.
    #[cfg(test)]
    pub(super) async fn read_unique(&self, slot: &ArtifactSlot) -> anyhow::Result<Option<Vec<u8>>> {
        self.node.read_unique(slot).await
    }

    /// Waits until one unique artifact has synchronized locally.
    pub(super) async fn wait_unique(
        &self,
        slot: &ArtifactSlot,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        self.node.wait_unique(slot, timeout).await
    }
}

/// The board role that coordinates and publishes common ceremony artifacts.
pub(super) struct CoordinatorBoard {
    reader: BoardReader,
}

impl CoordinatorBoard {
    /// Creates or resumes a ceremony board and returns one scoped ticket per participant.
    pub(super) async fn create(
        data_directory: &Path,
        participant_count: usize,
    ) -> anyhow::Result<(Self, Vec<BoardTicket>)> {
        Self::create_with_network(data_directory, participant_count, true).await
    }

    pub(super) async fn create_with_network(
        data_directory: &Path,
        participant_count: usize,
        use_network_services: bool,
    ) -> anyhow::Result<(Self, Vec<BoardTicket>)> {
        let (node, tickets) =
            iroh::create(data_directory, participant_count, use_network_services).await?;
        let tickets = tickets
            .into_iter()
            .map(|(encoded, participant)| BoardTicket::new(encoded, participant))
            .collect();
        Ok((Self { reader: BoardReader { node } }, tickets))
    }

    pub(super) fn reader(&self) -> &BoardReader {
        &self.reader
    }

    /// Publishes one common artifact without replacing another value in the same slot.
    pub(super) async fn publish(
        &self,
        artifact: CommonArtifact,
        value: &[u8],
    ) -> anyhow::Result<()> {
        self.reader.node.publish(&artifact.slot(), value).await?;
        Ok(())
    }

    /// Stops the board and flushes its persistent stores.
    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        self.reader.node.shutdown().await
    }
}

/// The board role held by one ceremony participant.
pub(super) struct ParticipantBoard {
    participant: u32,
    reader: BoardReader,
}

impl ParticipantBoard {
    /// Joins or resumes a ceremony board through a read and upload ticket.
    pub(super) async fn join(
        data_directory: &Path,
        ticket: BoardTicket,
        participant_count: usize,
    ) -> anyhow::Result<Self> {
        Self::join_with_network(data_directory, ticket, participant_count, true).await
    }

    pub(super) async fn join_with_network(
        data_directory: &Path,
        ticket: BoardTicket,
        participant_count: usize,
        use_network_services: bool,
    ) -> anyhow::Result<Self> {
        let participant = ticket.participant();
        let node = iroh::join(
            data_directory,
            &ticket.into_encoded(),
            participant_count,
            use_network_services,
        )
        .await?;
        Ok(Self {
            participant,
            reader: BoardReader { node },
        })
    }

    pub(super) fn reader(&self) -> &BoardReader {
        &self.reader
    }

    /// Publishes one artifact for the participant named by this board's ticket.
    pub(super) async fn publish(
        &self,
        artifact: ParticipantArtifact,
        value: &[u8],
    ) -> anyhow::Result<()> {
        self.reader.node.publish(&artifact.slot(self.participant), value).await?;
        Ok(())
    }

    /// Stops the board and flushes its persistent stores.
    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        self.reader.node.shutdown().await
    }
}
