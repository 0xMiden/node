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
mod tip;
mod view;
mod writer;

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
pub use lifecycle::LoadedState;
use miden_protocol::block::BlockNumber;
pub use replica::{BlockCache, BlockNotification, ProofCache, ProofNotification};
use tokio::sync::watch;
pub use view::{ScopedBlockNum, ScopedBlockRange, StateView, StateWitnesses, TransactionInputs};
use view::{SnapshotGuard, StateSnapshot};
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
/// All tree and database reads go through a request-scoped [`StateView`] obtained from
/// [`State::view`]; this type itself only exposes chain-tip queries, subscriptions, and
/// block-store access.
pub struct State {
    /// Root directory containing the store's on-disk data.
    data_directory: PathBuf,

    /// The database which stores block headers, nullifiers, notes, and the latest states of
    /// accounts.
    db: Arc<Db>,

    /// The block store which stores full block contents for all blocks.
    block_store: Arc<BlockStore>,

    /// Atomically swappable pointer to the latest in-memory state snapshot.
    ///
    /// Readers load the snapshot wait-free via [`ArcSwap::load_full`]; the
    /// [`WriteWorker`](writer::WriteWorker) task atomically replaces the pointer after each
    /// committed block. Readers holding an old snapshot are unaffected by the swap.
    latest_snapshot: Arc<ArcSwap<StateSnapshot>>,

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
