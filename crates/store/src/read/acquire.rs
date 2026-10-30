use std::sync::Arc;
use std::time::Duration;

use miden_node_db::sqlite::{DbReader, ReadTransaction as SqlReadTransaction};
use miden_node_tracing::{Instrument, info_span, miden_instrument, miden_span_record};
use miden_protocol::block::BlockNumber;
use tokio::sync::watch;

use super::{ReadTransaction, ReadView, StateSnapshot};
use crate::{COMPONENT, DatabaseError};

/// Maximum time spent waiting for a matching database and tree snapshot.
///
/// A block write commits its SQLite changes first, then applies the `RocksDB` tree updates and
/// publishes the corresponding tree snapshot. These writes span separate storage engines and
/// cannot be committed atomically, so a reader can briefly observe different chain tips. In that
/// case, acquisition waits for the tree snapshot to catch up to the committed block. The 500 ms
/// budget allows a short delay, including connection-pool and scheduling waits, while bounding
/// request latency if a matching pair remains unavailable.
const ACQUISITION_TIMEOUT: Duration = Duration::from_millis(500);

/// Runs a read operation with a SQLite transaction and tree snapshot at the same block.
///
/// SQLite commits before the corresponding tree snapshot is published. Acquisition releases
/// mismatched snapshots and retries, waiting for publication when the trees are behind. The read
/// operation runs once, after a matching pair is acquired.
pub(crate) async fn read<R, E, F>(
    reader: &DbReader,
    snapshots: Arc<crate::state::RecentSnapshots>,
    mut committed: watch::Receiver<BlockNumber>,
    read: F,
) -> Result<R, E>
where
    F: FnOnce(ReadView<'_>) -> Result<R, E> + Send + 'static,
    R: Send + 'static,
    E: From<DatabaseError> + Send + 'static,
{
    let deadline = tokio::time::Instant::now() + ACQUISITION_TIMEOUT;
    // Retry if the SQL tip has not been published to the tree history yet, or if its generation was
    // evicted before lookup. A retained generation can be acquired even after the writer has
    // published newer blocks.
    let AcquiredRead { snapshot, transaction } = loop {
        let acquired =
            tokio::time::timeout_at(deadline, acquire(reader, &snapshots, &mut committed))
                .await
                .map_err(|_| E::from(DatabaseError::ReadSnapshotUnavailable))?
                .map_err(E::from)?;
        if let Some(acquired) = acquired {
            break acquired;
        }
    };
    let block_num = snapshot.latest_block_num();

    let result = transaction
        .run("store read", move |tx| {
            Ok::<_, DatabaseError>(read(ReadView {
                tx: ReadTransaction::new(tx),
                snapshot: StateSnapshot {
                    block_num,
                    blockchain: &snapshot.blockchain,
                },
            }))
        })
        .instrument(info_span!(
            target: crate::COMPONENT,
            "store.read.action",
            snapshot.block.number = block_num.as_u32(),
        ))
        .await;

    // End the transaction on both success and failure, preserving the caller's error if cleanup
    // also fails.
    let closed = transaction.close().await.map_err(DatabaseError::from);
    let value = result.map_err(E::from)??;
    closed.map_err(E::from)?;
    Ok(value)
}

/// A database transaction and immutable tree snapshot at the same committed block.
struct AcquiredRead {
    snapshot: Arc<crate::state::StateSnapshot>,
    transaction: SqlReadTransaction,
}

/// Attempts to acquire matching snapshots, returning `None` when acquisition must be retried.
///
/// The tree history is searched by the SQL tip, so newer publications do not force a retry while
/// that generation remains retained. Each attempt records the SQL tip and matching tree height,
/// or the latest published height if no match exists. Waiting for tree publication is part of the attempt.
#[miden_instrument(
    target = COMPONENT,
    name = "store.read.acquire",
)]
async fn acquire(
    reader: &DbReader,
    snapshots: &crate::state::RecentSnapshots,
    committed: &mut watch::Receiver<BlockNumber>,
) -> Result<Option<AcquiredRead>, DatabaseError> {
    // Mark earlier publications as seen before examining SQL and the trees.
    //
    // A publication during this attempt must remain unseen so that `changed()` below
    // returns immediately. Marking it seen after the checks could miss the notification
    // that resolves the mismatch and make acquisition wait for another block.
    committed.borrow_and_update();
    let transaction = reader.begin_read().await.map_err(DatabaseError::from)?;
    // The first query establishes SQLite's snapshot; BEGIN DEFERRED alone does not. Reading the tip
    // here fixes the height that the tree snapshot must match.
    let header = transaction
        .run("store read tip", move |tx| {
            let header = crate::db::queries::select_chain_tip(tx)?.ok_or_else(|| {
                DatabaseError::DataCorrupted("block headers table is empty".into())
            })?;
            Ok::<_, DatabaseError>(header)
        })
        .await?;
    let block_num = header.block_num();
    let snapshot = snapshots.get(block_num);
    let tree_block_num = snapshot.as_ref().map_or_else(
        || snapshots.latest().latest_block_num(),
        |snapshot| snapshot.latest_block_num(),
    );
    miden_span_record!(block.number = block_num, snapshot.block.number = tree_block_num);
    if let Some(snapshot) = snapshot {
        // This is a cheap sanity check that matching heights identify the same block. Both
        // commitments are available in memory; no disk reads or hashing are needed.
        if snapshot.blockchain.as_mmr().get(block_num.as_usize()).ok() != Some(header.commitment())
        {
            return Err(DatabaseError::DataCorrupted(
                "database tip does not match the published blockchain".into(),
            ));
        }
        return Ok(Some(AcquiredRead { snapshot, transaction }));
    }
    // Release the SQL snapshot before retrying. If its tree generation was evicted, a fresh SQL
    // transaction can see a retained block. If SQL is ahead, wait for tree publication before
    // opening another transaction.
    //
    // After committing SQL, the writer may use the same reader pool to resolve consumed-note IDs
    // before publishing the trees. Holding transactions while waiting could exhaust that pool and
    // prevent the writer from making progress. Releasing them avoids this circular wait, at the
    // cost of potentially observing a newer SQL tip on the next attempt.
    let wait_for_publication = block_num > tree_block_num;
    transaction.close().await.map_err(DatabaseError::from)?;
    if wait_for_publication {
        committed.changed().await.map_err(|_| DatabaseError::ReadSnapshotUnavailable)?;
    }
    Ok(None)
}
