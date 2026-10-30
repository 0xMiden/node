//! Abstraction to synchronize state modifications.
//!
//! The [State] provides data access and modifications methods, its main purpose is to ensure that
//! data is atomically written, and that reads are consistent.

mod block_lifecycle;
mod bootstrap;
mod disk_monitor;
mod lifecycle;
mod loader;
mod replica;
mod snapshots;
mod tip;
mod view;
mod writer;

use std::path::PathBuf;
use std::sync::Arc;

pub use lifecycle::LoadedState;
use miden_protocol::block::BlockNumber;
pub use replica::{BlockCache, BlockNotification, ProofCache, ProofNotification};
pub(crate) use snapshots::RecentSnapshots;
use tokio::sync::watch;
pub(crate) use view::StateSnapshot;
pub use view::{ScopedBlockNum, ScopedBlockRange, StateView, StateWitnesses, TransactionInputs};
pub use writer::{BlockWriter, ProofWriter, WriterTask};

use crate::blocks::BlockStore;
use crate::db::Db;
use crate::proven_tip::ProvenTipWriter;

// CHAIN STATE
// ================================================================================================

/// The rollup state, read-only.
///
/// Mutations go through the [`BlockWriter`] and [`ProofWriter`] capabilities returned by
/// [`LoadedState::start`]; every holder of this type can only query and subscribe.
///
/// Caller-composed reads use [`State::read`] to acquire matching database and tree snapshots.
/// Endpoints awaiting migration use [`State::view`]. This type also exposes chain-tip queries,
/// subscriptions, and block-store access.
pub struct State {
    /// Root directory containing the store's on-disk data.
    data_directory: PathBuf,

    /// The database which stores block headers, nullifiers, notes, and the latest states of
    /// accounts.
    db: Arc<Db>,

    /// The block store which stores full block contents for all blocks.
    block_store: Arc<BlockStore>,

    /// Recent immutable tree generations, shared with the block writer.
    ///
    /// Readers look up the generation matching their SQLite transaction's tip. Legacy views load
    /// the latest generation; acquired readers keep their generation alive after cache eviction.
    snapshots: Arc<RecentSnapshots>,

    /// The latest proven-in-sequence block number, updated by the proof scheduler or `apply_proof`.
    proven_tip: ProvenTipWriter,

    /// Watch sender fired after each block is committed. Replicas subscribe via
    /// `subscribe_committed_tip()` to be woken when new blocks arrive.
    committed_tip_tx: Arc<watch::Sender<BlockNumber>>,

    /// FIFO cache of recent committed blocks for replica subscriptions. When a subscriber needs a
    /// block that has been evicted, it falls back to loading from the block store.
    pub(crate) block_cache: BlockCache,

    /// FIFO cache of recent block proofs for replica subscriptions. When a subscriber needs a proof
    /// that has been evicted, it falls back to loading from the block store.
    pub(crate) proof_cache: ProofCache,
}

impl State {
    /// Runs caller-owned read logic against matching database and tree snapshots.
    ///
    /// The closure runs on a blocking worker and releases its read resources before this method
    /// returns. Acquisition retries mismatched generations for up to 500 milliseconds.
    /// Other asynchronous work belongs outside the closure.
    pub async fn read<R, E, F>(&self, read: F) -> Result<R, E>
    where
        F: FnOnce(crate::read::ReadView<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<crate::DatabaseError> + Send + 'static,
    {
        crate::read::acquire::read(
            self.db.reader(),
            Arc::clone(&self.snapshots),
            self.subscribe_committed_tip(),
            read,
        )
        .await
    }
}
