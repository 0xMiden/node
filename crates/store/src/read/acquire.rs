use std::sync::Arc;
use std::time::Duration;

use miden_node_db::sqlite::DbReader;
use miden_node_tracing::{Instrument, Span, field, info_span};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::block::BlockNumber;
use tokio::sync::watch;
use tokio::time::timeout;

use super::{ReadTransaction, ReadView, StateSnapshot};
use crate::DatabaseError;

/// How long a reader waits for the next tree publication before retrying.
///
/// A block write commits its SQLite changes first, then applies the `RocksDB` tree updates and
/// publishes the corresponding tree snapshot. These writes span separate storage engines and
/// cannot be committed atomically, so a reader can briefly observe different chain tips. In that
/// case, acquisition releases the connection and waits for tree publication.
const TREE_PUBLICATION_TIMEOUT: Duration = Duration::from_millis(500);

/// The result of one snapshot acquisition attempt. A retry returns the unused caller closure.
enum Attempt<R, F> {
    Complete(R),
    Retry(F),
    WaitForPublication(F, Span),
}

/// Runs a read operation with a SQLite transaction and tree snapshot at the same block.
///
/// SQLite commits before the corresponding tree snapshot is published. Acquisition releases
/// mismatched snapshots and retries, waiting for publication when the trees are behind. The read
/// operation runs once, after a matching pair is acquired.
pub(crate) async fn read<R, E, F>(
    reader: &DbReader,
    load_snapshot: impl Fn(BlockNumber) -> Arc<crate::state::StateSnapshot> + Clone + Send + 'static,
    mut committed: watch::Receiver<BlockNumber>,
    mut read: F,
) -> Result<R, E>
where
    F: FnOnce(ReadView<'_>) -> Result<R, E> + Send + 'static,
    R: Send + 'static,
    E: From<DatabaseError> + Send + 'static,
{
    let caller = CancellationToken::new();
    let _cancel_on_drop = caller.drop_guard_ref();

    loop {
        // Mark earlier publications as seen so an update during this attempt wakes the retry.
        committed.borrow_and_update();
        let load_snapshot = load_snapshot.clone();
        let acquisition = info_span!(
            "store.read.acquire",
            block.number = field::Empty,
            snapshot.block.number = field::Empty,
        );
        let caller = caller.clone();
        let attempt = reader
            .read("store read", move |tx| -> Result<_, DatabaseError> {
                let acquisition = acquisition.entered();
                // The first query establishes the SQLite snapshot used by the caller.
                let header = crate::db::queries::select_chain_tip(tx)?.ok_or_else(|| {
                    DatabaseError::DataCorrupted("block headers table is empty".into())
                })?;
                let block_num = header.block_num();
                let snapshot = load_snapshot(block_num);
                let tree_block_num = snapshot.latest_block_num();
                acquisition.record("block.number", block_num.as_u32());
                acquisition.record("snapshot.block.number", tree_block_num.as_u32());
                if block_num > tree_block_num {
                    return Ok(Attempt::WaitForPublication(read, acquisition.exit()));
                }
                if block_num < tree_block_num {
                    return Ok(Attempt::Retry(read));
                }
                if snapshot.blockchain.as_mmr().get(block_num.as_usize()).ok()
                    != Some(header.commitment())
                {
                    return Err(DatabaseError::DataCorrupted(
                        "database tip does not match the published blockchain".into(),
                    ));
                }
                drop(acquisition);

                if caller.is_cancelled() {
                    return Err(DatabaseError::ReadSnapshotUnavailable);
                }
                let _action =
                    info_span!("store.read.action", snapshot.block.number = block_num.as_u32())
                        .entered();
                Ok(Attempt::Complete(read(ReadView {
                    tx: ReadTransaction::new(tx),
                    snapshot: &StateSnapshot {
                        block_num,
                        blockchain: &snapshot.blockchain,
                        account_tree: &snapshot.account_tree,
                        forest: &snapshot.forest,
                        nullifier_tree: &snapshot.nullifier_tree,
                    },
                })))
            })
            .await?;
        read = match attempt {
            Attempt::Complete(result) => return result,
            Attempt::Retry(read) => read,
            Attempt::WaitForPublication(read, span) => {
                // The writer may need this reader connection before it can publish the trees. The
                // blocking job has released both snapshots before we wait.
                let published =
                    timeout(TREE_PUBLICATION_TIMEOUT, committed.changed()).instrument(span).await;
                if !matches!(published, Ok(Ok(()))) {
                    return Err(DatabaseError::ReadSnapshotUnavailable.into());
                }
                read
            },
        };
    }
}
