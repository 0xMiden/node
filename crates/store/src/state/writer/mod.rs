//! Serialized block-write path for the store state.
//!
//! A single [`WriteWorker`] task owns the mutable trees and processes incoming [`WriteRequest`]s
//! one at a time via an mpsc channel. After each successful commit it publishes a new
//! [`StateSnapshot`] snapshot via an [`ArcSwap`], making the updated trees immediately visible to
//! wait-free readers.
//!
//! The [`BlockWriter`] and [`ProofWriter`] capabilities defined here are the only handles able
//! to feed this worker and to commit proofs; the submodules hold their entry points.

mod apply_block;
mod apply_proof;

mod worker;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use miden_node_tracing::{ErrorReport, miden_instrument};
use miden_protocol::block::SignedBlock;
use miden_protocol::protocol_config::ProtocolConfig;
use tokio::sync::{mpsc, oneshot};
pub(in crate::state) use worker::WriteWorker;

use crate::COMPONENT;
use crate::blocks::BlockStore;
use crate::errors::ApplyBlockError;

// WRITE CAPABILITIES
// ================================================================================================

/// The store's block-write capability.
///
/// Only handle able to apply blocks; obtained exactly once from [`LoadedState::start`](crate::state::LoadedState::start) and
/// deliberately not cloneable, so granting it to a single task (the block builder in sequencer
/// mode, the block sync loop in full-node mode) statically prevents every other component from
/// writing blocks.
///
/// Exposes no read access: holders that also need to query the store receive the
/// [`Arc<State>`](crate::state::State) returned alongside this capability by
/// [`LoadedState::start`](crate::state::LoadedState::start).
pub struct BlockWriter {
    /// The block store, used to persist proving inputs alongside applied blocks.
    pub(super) block_store: Arc<BlockStore>,
    /// Sender for block-write requests to the [`WriteWorker`] task. Never cloned out of this
    /// struct: the writer exits once it is dropped.
    pub(super) write_tx: mpsc::Sender<WriteRequest>,
}

/// The store's proof-write capability.
///
/// Only handle able to commit block proofs and advance the proven tip; obtained exactly once from
/// [`LoadedState::start`](crate::state::LoadedState::start) and deliberately not cloneable, so granting it to a single task (the
/// proof scheduler in sequencer mode, the proof sync loop in full-node mode) statically prevents
/// every other component from writing proofs.
///
/// Exposes no read access: the held state is only used internally to commit proofs and advance
/// the proven tip. Holders that also need to query the store receive the
/// [`Arc<State>`](crate::state::State) returned alongside this capability by
/// [`LoadedState::start`](crate::state::LoadedState::start).
pub struct ProofWriter {
    pub(super) state: Arc<crate::state::State>,
}

// WRITER TASK
// ================================================================================================

/// Handle of the store's write worker task, returned by [`LoadedState::start`](crate::state::LoadedState::start).
///
/// Awaiting it resolves once the writer has exited and released the tree storage it owns; a join
/// error carries a writer panic. The newtype ensures [`BlockWriter::stop`] can only be given the
/// store's own writer task, and deliberately does not expose [`tokio::task::JoinHandle::abort`]:
/// aborting the writer mid-write could leave the trees lagging the committed database state,
/// voiding the guarantee that an in-flight block write always completes.
#[must_use = "await the writer task to observe its exit, or pass it to `BlockWriter::stop`"]
pub struct WriterTask(pub(super) tokio::task::JoinHandle<()>);

impl Future for WriterTask {
    type Output = Result<(), tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

// WRITE REQUEST
// ================================================================================================

/// A request to apply a block, paired with a one-shot channel for the result.
pub(super) struct WriteRequest {
    signed_block: SignedBlock,
    protocol_config: Option<ProtocolConfig>,
    result_tx: oneshot::Sender<Result<(), ApplyBlockError>>,
    /// Span of the `apply_block` caller. The worker runs the write under it, keeping the write path
    /// in the caller's trace across the channel hop.
    span: miden_node_tracing::Span,
}

impl BlockWriter {
    /// Stops the store, waiting until the write worker has released the tree storage it owns.
    ///
    /// Consumes the capability — closing the write channel the write worker listens on — and then
    /// joins the writer task returned by [`LoadedState::start`](crate::state::LoadedState::start). The drop must precede the join
    /// or the write worker never observes the closed channel; doing both here keeps that ordering
    /// out of caller hands. Read-only [`State`](crate::state::State) references may outlive the
    /// stop.
    ///
    /// Callers that need the storage released deterministically must use this method instead of
    /// dropping: the node's `recover` command stops the store before the process exits, and the
    /// stress-test's store seeding stops it so the same data directory can be re-loaded (or its
    /// temporary directory deleted) immediately afterwards. The running node does not use this
    /// method — its writer exits via the shutdown token passed to
    /// [`State::load`](crate::state::State::load) and is joined through the node's task set.
    ///
    /// # Panics
    ///
    /// Panics if the writer task panicked.
    pub async fn stop(self, writer_task: WriterTask) {
        drop(self);
        writer_task.await.expect("write worker task should not panic");
    }

    /// Apply changes of a new block to the DB and in-memory data structures.
    ///
    /// Supply the active configuration if its commitment is not yet stored. The configuration
    /// must match the block header. New configurations are committed with the block.
    /// If the configuration is omitted and its commitment is not stored, this method returns
    /// `DatabaseError::ProtocolConfigNotFound` through `ApplyBlockError`.
    ///
    /// Blocks are forwarded to the store's write worker task, which processes them one at a
    /// time.
    /// Readers are unaffected while a block is being applied: they keep reading from the previous
    /// in-memory snapshot until the writer atomically publishes the new one.
    #[miden_instrument(
        target = COMPONENT,
        err,
    )]
    pub async fn apply_block(
        &mut self,
        signed_block: SignedBlock,
        protocol_config: Option<ProtocolConfig>,
    ) -> Result<(), ApplyBlockError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.write_tx
            .send(WriteRequest {
                signed_block,
                protocol_config,
                result_tx,
                span: miden_node_tracing::Span::current(),
            })
            .await
            .map_err(|e| ApplyBlockError::WriterTaskSendFailed(e.as_report()))?;
        result_rx.await?
    }
}
