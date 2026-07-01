use std::path::{Path, PathBuf};
use std::time::Duration;

use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_node_utils::tracing::{miden_instrument, miden_span_record};

use crate::COMPONENT;
use crate::state::State;

impl State {
    /// Spawns a background task that periodically records the on-disk size of every store data path
    /// as `OTel` span attributes.
    pub fn spawn_disk_monitor(&self) -> tokio::task::JoinHandle<()> {
        let data_directory = self.data_directory.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(5));
            loop {
                interval.tick().await;
                let _ = measure_disk_space_usage(data_directory.clone()).await;
            }
        })
    }
}

#[miden_instrument(
    target = COMPONENT,
    name = "measure_disk_space_usage",
    skip_all,
    err,
)]
async fn measure_disk_space_usage(data_dir: PathBuf) -> Result<(), tokio::task::JoinError> {
    let usage = spawn_blocking_in_current_span(move || measure_disk_usage_bytes(&data_dir)).await?;
    miden_span_record!(
        db.sqlite.size = usage.sqlite_db,
        db.sqlite.wal.size = usage.sqlite_wal,
        db.block_store.size = usage.block_store,
    );
    #[cfg(feature = "rocksdb")]
    {
        miden_span_record!(
            db.account_tree.size = usage.account_tree,
            db.nullifier_tree.size = usage.nullifier_tree,
            db.account_state_forest.size = usage.account_state_forest,
        );
    }

    Ok(())
}

/// Byte counts for each on-disk storage component.
struct DiskUsage {
    sqlite_db: u64,
    sqlite_wal: u64,
    block_store: u64,
    #[cfg(feature = "rocksdb")]
    account_tree: u64,
    #[cfg(feature = "rocksdb")]
    nullifier_tree: u64,
    #[cfg(feature = "rocksdb")]
    account_state_forest: u64,
}

/// Collects on-disk byte sizes for every store data path under `data_dir`.
fn measure_disk_usage_bytes(data_dir: &Path) -> DiskUsage {
    DiskUsage {
        sqlite_db: path_size_bytes(&data_dir.join("miden-store.sqlite3")),
        sqlite_wal: path_size_bytes(&data_dir.join("miden-store.sqlite3-wal")),
        block_store: dir_size_bytes(&data_dir.join("blocks")),
        #[cfg(feature = "rocksdb")]
        account_tree: dir_size_bytes(&data_dir.join("accounttree")),
        #[cfg(feature = "rocksdb")]
        nullifier_tree: dir_size_bytes(&data_dir.join("nullifiertree")),
        #[cfg(feature = "rocksdb")]
        account_state_forest: dir_size_bytes(&data_dir.join("accountstateforest")),
    }
}

/// Returns the byte length of the file at `path`, or `0` if it does not exist.
fn path_size_bytes(path: &Path) -> u64 {
    fs_err::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Returns the total byte length of all files in `path` iteratively, or `0` on any error.
fn dir_size_bytes(path: &Path) -> u64 {
    let mut to_process = vec![path.to_path_buf()];
    let mut total = 0u64;
    while let Some(dir) = to_process.pop() {
        let Ok(entries) = fs_err::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    to_process.push(entry.path());
                } else {
                    total += meta.len();
                }
            }
        }
    }
    total
}
