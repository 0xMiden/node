//! Request-scoped, consistent read view of the store.
//!
//! Endpoints that have not migrated to [`State::read`] use [`StateView`]. It pins one tree
//! snapshot, and block-scoped queries are bounded by its height through the [`scoped`] proof types.
//! Each database query opens its own transaction. Caller-composed reads use [`State::read`] to pair
//! the tree snapshot with a single SQLite transaction.
//!
use std::ops::RangeInclusive;
use std::sync::Arc;

use miden_node_tracing::Span;
use miden_protocol::block::{BlockNumber, Blockchain};

use crate::account_state_forest::{AccountStateForest, AccountStateForestBackendReader};
use crate::db::{Db, HISTORICAL_BLOCK_RETENTION};
use crate::errors::{DatabaseError, RangeBelowRetention, RangeBeyondTip};
use crate::state::State;

mod scoped;
pub use scoped::{ScopedBlockNum, ScopedBlockRange};

mod snapshot;
pub(in crate::state) use snapshot::PublishedGenerations;
pub(crate) use snapshot::StateSnapshot;

mod account;
mod block;
mod inclusion_proofs;
mod note;
mod protocol_config;
mod state_witnesses;
pub use state_witnesses::StateWitnesses;
mod sync;

// STATE VIEW
// ================================================================================================

/// A consistent read view of the store, pinned at its snapshot's block height.
///
/// Obtained from [`State::view`]; create one per request and drop it when the request completes.
/// Holding a view pins a snapshot generation (and thereby the `RocksDB` snapshots backing the
/// trees), so it must not be stored in long-lived structs.
///
/// Reads that are technically not block-scoped (for example, immutable content-addressed data)
/// also live here so that every read path flows through one type.
pub struct StateView {
    snapshot: Arc<StateSnapshot>,
    db: Arc<Db>,
}

impl State {
    /// Returns a read view pinned at the current chain tip (wait-free, no lock required).
    ///
    /// The view is frozen: it is unaffected if the writer publishes a new snapshot while it is
    /// held.
    ///
    /// Use this only for one single-expression read (`state.view().get_account(..)`),
    /// where the temporary view drops at the end of the statement. Two `view()` calls observe
    /// potentially *different* snapshots — a block can commit between them — so reads that must
    /// be mutually consistent (e.g. a query and the tip it was served at) must share one view via
    /// [`Self::with_view`]. Binding a view to a variable is also discouraged: it keeps the
    /// snapshot generation pinned until the end of the scope.
    pub fn view(&self) -> StateView {
        StateView {
            snapshot: self.snapshots.latest(),
            db: Arc::clone(&self.db),
        }
    }

    /// Runs a read operation over a view pinned at the current chain tip, dropping the view — and
    /// releasing its snapshot generation — as soon as the operation completes.
    ///
    /// This is the required form whenever multiple reads must observe the *same* snapshot: the
    /// closure's view is one consistent generation, whereas consecutive [`Self::view`] calls may
    /// straddle a commit. The typical case is pairing a query with [`StateView::tip`] so a
    /// response reports exactly the height it was served at.
    ///
    /// The closure receives a shared reference, so the view cannot escape the call, and the
    /// snapshot is not pinned through unrelated work that follows (e.g. response encoding). A
    /// *single* read doesn't need it — `state.view().get_account(..)` drops its temporary view at
    /// the end of the statement.
    ///
    /// Work in the closure should be kept to low-complexity compute over the view, ideally with no
    /// I/O and no other `.await` points. Anything slower holds the pinned snapshot, and therefore
    /// its underlying `RocksDB` snapshot, for as long as it runs.
    pub async fn with_view<R>(&self, f: impl AsyncFnOnce(&StateView) -> R) -> R {
        let view = self.view();
        f(&view).await
    }
}

impl StateView {
    /// Returns this view's tip as a scoped block number for tip-bounded database queries.
    pub fn tip(&self) -> ScopedBlockNum {
        ScopedBlockNum::new(self.snapshot.latest_block_num())
    }

    /// Returns the pinned snapshot's blockchain MMR.
    ///
    /// The MMR is the only part of the snapshot that is purely in-memory and therefore safe to
    /// access directly on an async worker thread. The account and nullifier trees may be backed
    /// by `RocksDB` and are deliberately not reachable here — they must be accessed through
    /// [`Self::with_inner_read_blocking`].
    fn blockchain(&self) -> &Blockchain {
        &self.snapshot.blockchain
    }

    /// Validates that `block_num` does not exceed this view's chain tip, returning the scoped block
    /// number required by block-bounded database queries.
    fn scope_block(&self, block_num: BlockNumber) -> Option<ScopedBlockNum> {
        (block_num <= *self.tip()).then(|| ScopedBlockNum::new(block_num))
    }

    /// Validates that `range` does not extend beyond this view's chain tip, returning the scoped
    /// range required by range-bounded database queries.
    ///
    /// Every range-scoped read on this type calls this before touching the database, so callers
    /// never need to pre-validate ranges themselves.
    fn scope_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> Result<ScopedBlockRange, RangeBeyondTip> {
        let tip = *self.tip();
        if *range.end() > tip {
            return Err(RangeBeyondTip { chain_tip: tip, block_to: *range.end() });
        }
        Ok(ScopedBlockRange::new(range))
    }

    /// Validates `range` like [`Self::scope_range`], and also validates that `range` ends inside
    /// the account history retention window.
    ///
    /// The store deletes account history rows that stop being valid at or below
    /// `tip - HISTORICAL_BLOCK_RETENTION`. A range that ends below that block can miss updates, so
    /// account state sync reads must use this check.
    fn scope_retained_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> Result<ScopedBlockRange, DatabaseError> {
        let range = self.scope_range(range)?;
        let oldest_retained =
            BlockNumber::from(self.tip().as_u32().saturating_sub(HISTORICAL_BLOCK_RETENTION));
        if range.end() < oldest_retained {
            return Err(RangeBelowRetention { oldest_retained, block_to: range.end() }.into());
        }
        Ok(range)
    }

    /// Runs a synchronous read-only operation over the pinned state snapshot on Tokio's blocking
    /// path.
    ///
    /// The account and nullifier trees may be backed by `RocksDB`, so tree access must not run on
    /// an async worker thread directly. This helper preserves the current tracing span while
    /// moving the closure body into `block_in_place`.
    fn with_inner_read_blocking<R>(&self, f: impl FnOnce(&StateSnapshot) -> R) -> R {
        let span = Span::current();
        tokio::task::block_in_place(|| span.in_scope(|| f(&self.snapshot)))
    }

    /// Runs a synchronous read-only operation over the account state forest snapshot on Tokio's
    /// blocking path.
    ///
    /// See [`Self::with_inner_read_blocking`] for why this uses `block_in_place`.
    fn with_forest_read_blocking<R>(
        &self,
        f: impl FnOnce(&AccountStateForest<AccountStateForestBackendReader>) -> R,
    ) -> R {
        self.with_inner_read_blocking(|snapshot| f(&snapshot.forest))
    }
}
