//! A blocking handle over the framework's connection pools, for testing query functions.
//!
//! Query functions take a [`ReadTx`]/[`WriteTx`], which the pools only ever hand out inside a
//! `read`/`write` closure on an async call. That is the right shape for production code, but it
//! would force every query-level test to be `async`. [`TestDb`] owns a current-thread runtime and
//! blocks on those calls, so the tests stay plain `#[test]` functions while still exercising the
//! same pools, PRAGMAs, and transaction behaviour the node uses.

use std::path::{Path, PathBuf};

use diesel::Connection;
use miden_node_db::sqlite::{DbReader, DbWriter, ReadTx, WriteTx};
use miden_node_db::{DatabaseError, default_connection_pool_size};
use tokio::runtime::Runtime;

use crate::db::migrations::bootstrap_database;

/// A database with framework handles over it, driven synchronously.
///
/// While the store is mid-migration off diesel, [`TestDb::diesel_conn`] also hands out diesel
/// connections over the same file so tests can drive the read queries still living in
/// [`crate::db::models`].
pub(crate) struct TestDb {
    // Held as `Option` so [`Drop`] can drop the pools inside the runtime's context: their pooled
    // connections are closed on a blocking task, which panics without a runtime to spawn it on.
    writer: Option<DbWriter>,
    reader: Option<DbReader>,
    runtime: Runtime,
    path: PathBuf,
}

impl TestDb {
    /// Bootstraps a throwaway database in the OS temp directory and opens handles over it.
    ///
    /// The temporary directory is intentionally leaked so the file outlives the handle; these are
    /// test databases in the OS temp directory.
    pub(crate) fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
        let path = temp_dir.path().join("test.sqlite3");
        bootstrap_database(&path).expect("database should bootstrap");
        let _kept_dir = temp_dir.keep();

        Self::open(&path)
    }

    /// Opens handles over an existing, already migrated database file.
    pub(crate) fn open(path: &Path) -> Self {
        let (writer, reader) =
            miden_node_db::sqlite::open_with_pool_size(path, default_connection_pool_size())
                .expect("temp file sqlite should always work");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime should build");

        Self {
            writer: Some(writer),
            reader: Some(reader),
            runtime,
            path: path.to_path_buf(),
        }
    }

    /// Opens a fresh diesel connection over the same database file.
    ///
    /// Reads not yet migrated to the framework still run on diesel; WAL mode makes the extra
    /// connection safe alongside the framework pools.
    pub(crate) fn diesel_conn(&self) -> diesel::SqliteConnection {
        let mut conn = diesel::SqliteConnection::establish(
            self.path.to_str().expect("temp database path should be valid UTF-8"),
        )
        .expect("temp file sqlite should always work");
        miden_node_db::configure_connection_on_creation(&mut conn)
            .expect("connection PRAGMAs should apply");
        conn
    }

    /// Runs `query` inside a read-only transaction.
    pub(crate) fn read<R, E, F>(&self, query: F) -> Result<R, E>
    where
        F: FnOnce(&ReadTx<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<DatabaseError> + Send + 'static,
    {
        let reader = self.reader.as_ref().expect("handles live until drop");
        self.runtime.block_on(reader.read("test read", query))
    }

    /// Runs `query` inside a read-write transaction, committing it if `query` returns `Ok`.
    pub(crate) fn write<R, E, F>(&self, query: F) -> Result<R, E>
    where
        F: FnOnce(&WriteTx<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<DatabaseError> + Send + 'static,
    {
        let writer = self.writer.as_ref().expect("handles live until drop");
        self.runtime.block_on(writer.write("test write", query))
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _guard = self.runtime.enter();
        self.writer.take();
        self.reader.take();
    }
}
