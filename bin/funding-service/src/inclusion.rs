//! Waiting for a funding transaction to commit.

use std::collections::HashMap;
use std::time::Duration;

use miden_node_tracing::warn;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, NoteInclusionProof};

use crate::LOG_TARGET;
use crate::node::RpcNodeClient;

// AWAIT INCLUSION
// ================================================================================================

/// The outcome of waiting for a set of notes to commit.
#[derive(Debug)]
pub enum Inclusion {
    /// Every note is committed. Holds a proof for every requested note.
    Committed(HashMap<NoteId, NoteInclusionProof>),
    /// The transaction expired without committing, so no note was created.
    Expired,
    /// The service is shutting down and stopped waiting.
    ShuttingDown,
}

/// Polls the node until every note in `note_ids` is committed, or until the transaction expires.
pub async fn await_inclusion(
    node: &RpcNodeClient,
    note_ids: &[NoteId],
    expiration_block: BlockNumber,
    poll_interval: Duration,
    shutdown: &CancellationToken,
) -> Inclusion {
    let mut found: HashMap<NoteId, NoteInclusionProof> = HashMap::new();

    loop {
        match node.committed_notes(note_ids).await {
            Ok(proofs) => found.extend(proofs),
            Err(err) => warn!(
                &err,
                target: LOG_TARGET,
                "Failed to look up the funding notes; retrying"
            ),
        }

        if found.len() == note_ids.len() {
            return Inclusion::Committed(found);
        }

        // The chain tip decides whether the transaction can still be included. A failure to read it
        // must not end the wait, because the notes may well commit.
        match node.chain_tip().await {
            Ok(tip) if tip >= expiration_block => {
                // The tip may have passed the expiration block while the last block was being
                // applied, so look once more before giving up.
                if let Ok(proofs) = node.committed_notes(note_ids).await {
                    found.extend(proofs);
                }

                if found.len() == note_ids.len() {
                    return Inclusion::Committed(found);
                }

                // A proof for any note proves that the transaction committed, so every note was
                // created and the missing proofs are only not visible yet. Giving up here would
                // report notes which exist as never created, and their assets would be lost,
                // because the service holds the only copy of a private note.
                if found.is_empty() {
                    return Inclusion::Expired;
                }
            },
            Ok(_) => {},
            Err(err) => warn!(
                &err,
                target: LOG_TARGET,
                "Failed to read the chain tip while waiting for the funding notes"
            ),
        }

        tokio::select! {
            () = tokio::time::sleep(poll_interval) => {},
            () = shutdown.cancelled() => return Inclusion::ShuttingDown,
        }
    }
}
