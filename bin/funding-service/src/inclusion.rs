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
        // The tip is read before the notes. The store only moves forward, so the lookup below
        // observes a store which is at least at this height. The expiration check depends on this
        // order.
        let tip = match node.committed_tip().await {
            Ok(tip) => Some(tip),
            Err(err) => {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "Failed to read the chain tip while waiting for the funding notes"
                );
                None
            },
        };

        let notes_read = match node.committed_notes(note_ids).await {
            Ok(proofs) => {
                found.extend(proofs);
                true
            },
            Err(err) => {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "Failed to look up the funding notes; retrying"
                );
                false
            },
        };

        if found.len() == note_ids.len() {
            return Inclusion::Committed(found);
        }


        if notes_read && found.is_empty() && tip.is_some_and(|tip| tip >= expiration_block) {
            return Inclusion::Expired;
        }

        tokio::select! {
            () = tokio::time::sleep(poll_interval) => {},
            () = shutdown.cancelled() => return Inclusion::ShuttingDown,
        }
    }
}
