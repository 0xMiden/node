//! This module defines the artifact slots and board roles for storage key DKG.
//!
//! The coordinator and validators use separate board roles. Private adapters handle Iroh access
//! and storage.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use miden_node_utils::shutdown::CancellationToken;

mod core;
mod iroh;
#[cfg(test)]
mod memory;
#[cfg(test)]
mod tests;

pub(super) use core::ArtifactSlot;

pub(super) use iroh::BoardTicket;

#[derive(Clone, Copy)]
pub(super) struct BoardPolicy {
    pub(super) genesis_commitment: [u8; 32],
    pub(super) threshold: usize,
    pub(super) epoch: [u8; 32],
}

#[cfg(test)]
pub(super) const TEST_POLICY: BoardPolicy = BoardPolicy {
    genesis_commitment: [0; 32],
    threshold: 1,
    epoch: [0; 32],
};

#[derive(Debug)]
pub(super) struct JoinCancelled;

impl fmt::Display for JoinCancelled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DKG board join cancelled")
    }
}

impl std::error::Error for JoinCancelled {}

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
    node: Transport,
}

enum Transport {
    Iroh(Box<iroh::BoardNode>),
    #[cfg(test)]
    Memory(memory::BoardNode),
}

impl Transport {
    async fn publish(&self, slot: &ArtifactSlot, value: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Iroh(node) => {
                node.publish(slot, value).await?;
                Ok(())
            },
            #[cfg(test)]
            Self::Memory(node) => node.publish(slot, value).await,
        }
    }

    #[cfg(test)]
    async fn read_unique(&self, slot: &ArtifactSlot) -> anyhow::Result<Option<Vec<u8>>> {
        match self {
            Self::Iroh(node) => node.read_unique(slot).await,
            Self::Memory(node) => node.read_unique(slot).await,
        }
    }

    async fn wait_unique(&self, slot: &ArtifactSlot, timeout: Duration) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Iroh(node) => node.wait_unique(slot, timeout).await,
            #[cfg(test)]
            Self::Memory(node) => node.wait_unique(slot, timeout).await,
        }
    }

    async fn shutdown(self) -> anyhow::Result<()> {
        match self {
            Self::Iroh(node) => (*node).shutdown().await,
            #[cfg(test)]
            Self::Memory(_) => Ok(()),
        }
    }
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
    pub(super) async fn create_with_network(
        data_directory: &Path,
        participant_count: usize,
        policy: &BoardPolicy,
        use_network_services: bool,
    ) -> anyhow::Result<(Self, Vec<BoardTicket>)> {
        let (node, tickets) = iroh::BoardNode::create_with_network(
            data_directory,
            participant_count,
            policy,
            use_network_services,
        )
        .await?;
        Ok((
            Self {
                reader: BoardReader { node: Transport::Iroh(Box::new(node)) },
            },
            tickets,
        ))
    }

    #[cfg(test)]
    pub(super) fn create_memory(
        participant_count: usize,
    ) -> anyhow::Result<(Self, Vec<ParticipantBoard>)> {
        let mut nodes = memory::create(participant_count)?.into_iter();
        let coordinator = Self {
            reader: BoardReader {
                node: Transport::Memory(nodes.next().expect("memory board includes a coordinator")),
            },
        };
        let participants = nodes
            .enumerate()
            .map(|(position, node)| {
                Ok(ParticipantBoard {
                    participant: u32::try_from(position + 1)?,
                    reader: BoardReader { node: Transport::Memory(node) },
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok((coordinator, participants))
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
        self.reader.node.publish(&artifact.slot(), value).await
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
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        Self::join_with_network(data_directory, ticket, participant_count, true, shutdown).await
    }

    pub(super) async fn join_with_network(
        data_directory: &Path,
        ticket: BoardTicket,
        participant_count: usize,
        use_network_services: bool,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        let participant = ticket.participant();
        let node = iroh::BoardNode::join_with_network(
            data_directory,
            ticket,
            participant_count,
            use_network_services,
            shutdown,
        )
        .await?;
        Ok(Self {
            participant,
            reader: BoardReader { node: Transport::Iroh(Box::new(node)) },
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
        self.reader.node.publish(&artifact.slot(self.participant), value).await
    }

    /// Stops the board and flushes its persistent stores.
    pub(super) async fn shutdown(self) -> anyhow::Result<()> {
        self.reader.node.shutdown().await
    }
}
