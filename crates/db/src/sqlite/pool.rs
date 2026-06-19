//! Async connection pool over raw `rusqlite`, mirroring the legacy diesel [`Db`](crate::Db) shape
//! but exposing only read/write transactions.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use deadpool::Runtime;
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleError, RecycleResult};
use deadpool_sync::SyncWrapper;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use tracing::Instrument;

use crate::sqlite::tx::{ReadTx, WriteTx};
use crate::{DatabaseError, default_connection_pool_size};

/// Per-connection prepared-statement cache capacity. Raised above rusqlite's default of 16 because
/// the store keeps a larger set of distinct statements.
const STATEMENT_CACHE_CAPACITY: usize = 64;

// CONNECTION MANAGER
// =================================================================================================

/// Errors raised while creating or recycling a pooled connection.
///
/// Internal to the pool: callers only ever observe a [`DatabaseError`] (pool failures are boxed into
/// [`DatabaseError::ConnectionPoolObtainError`]), so this type is not part of the public API.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SqliteManagerError {
    /// Opening the database file failed.
    #[error("failed to open the sqlite database")]
    Open(#[source] rusqlite::Error),
    /// Applying the per-connection PRAGMAs failed.
    #[error("failed to configure the sqlite connection")]
    Configure(#[source] rusqlite::Error),
    /// The pooled connection's mutex was poisoned by a panic during a previous interaction.
    #[error("the pooled sqlite connection is poisoned")]
    Poisoned,
}

struct SqliteManager {
    path: PathBuf,
}

impl Manager for SqliteManager {
    type Type = SyncWrapper<Connection>;
    type Error = SqliteManagerError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let path = self.path.clone();
        SyncWrapper::new(Runtime::Tokio1, move || {
            let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(SqliteManagerError::Open)?;
            configure_connection(&conn).map_err(SqliteManagerError::Configure)?;
            Ok(conn)
        })
        .await
    }

    async fn recycle(
        &self,
        conn: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        if conn.is_mutex_poisoned() {
            return Err(RecycleError::Backend(SqliteManagerError::Poisoned));
        }
        Ok(())
    }
}

/// Applies the per-connection PRAGMAs and statement-cache sizing.
fn configure_connection(conn: &Connection) -> rusqlite::Result<()> {
    // WAL allows concurrent readers while a writer holds the lock; foreign keys enforce referential
    // integrity; busy_timeout makes concurrent writers wait instead of failing immediately.
    conn.execute_batch(
        "PRAGMA busy_timeout = 5000;
         PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;",
    )?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
    Ok(())
}

// DATABASE
// =================================================================================================

/// A rusqlite-backed connection pool. Cloning shares the underlying pool.
#[derive(Clone)]
pub struct Database {
    pool: Pool<SqliteManager>,
}

impl Database {
    /// Opens a pool over `database_filepath` with the default pool size.
    pub fn new(database_filepath: &Path) -> Result<Self, DatabaseError> {
        Self::new_with_pool_size(database_filepath, default_connection_pool_size())
    }

    /// Opens a pool over `database_filepath` with the given pool size.
    pub fn new_with_pool_size(
        database_filepath: &Path,
        connection_pool_size: NonZeroUsize,
    ) -> Result<Self, DatabaseError> {
        let manager = SqliteManager { path: database_filepath.to_path_buf() };
        let pool = Pool::builder(manager).max_size(connection_pool_size.get()).build()?;
        Ok(Self { pool })
    }

    /// Checks out a connection and pins it for the caller's exclusive, long-lived use.
    pub async fn pinned_connection(&self) -> Result<PinnedConnection, DatabaseError> {
        let conn = self
            .pool
            .get()
            .in_current_span()
            .await
            .map_err(|err| DatabaseError::ConnectionPoolObtainError(Box::new(err)))?;
        Ok(PinnedConnection { conn })
    }

    /// Runs `query` inside a read-only (`DEFERRED`, never committed) transaction.
    pub async fn read<R, E, F>(&self, msg: impl ToString + Send, query: F) -> Result<R, E>
    where
        F: FnOnce(&ReadTx<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<DatabaseError> + Send + 'static,
    {
        self.pinned_connection().await.map_err(E::from)?.read(msg, query).await
    }

    /// Runs `query` inside a read-write (`IMMEDIATE`) transaction, committing on `Ok`.
    pub async fn write<R, E, F>(&self, msg: impl ToString + Send, query: F) -> Result<R, E>
    where
        F: FnOnce(&WriteTx<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<DatabaseError> + Send + 'static,
    {
        self.pinned_connection().await.map_err(E::from)?.write(msg, query).await
    }
}

// PINNED CONNECTION
// =================================================================================================

/// A connection checked out of [`Database`]'s pool and held for the caller's exclusive use. Useful
/// for a hot event loop whose queries should never wait on the shared pool.
pub struct PinnedConnection {
    conn: Object<SqliteManager>,
}

impl PinnedConnection {
    /// Runs `query` inside a read-only (`DEFERRED`, never committed) transaction on the pinned
    /// connection.
    pub async fn read<R, E, F>(&self, msg: impl ToString + Send, query: F) -> Result<R, E>
    where
        F: FnOnce(&ReadTx<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<DatabaseError> + Send + 'static,
    {
        let msg = msg.to_string();
        let span = tracing::Span::current();
        self.conn
            .interact(move |conn| {
                let _guard = span.enter();
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Deferred)
                    .map_err(|err| E::from(DatabaseError::from(err)))?;
                let read = ReadTx::new(&tx);
                query(&read)
                // `tx` is dropped here without a commit, rolling back any (erroneous) writes.
            })
            .await
            .map_err(|err| E::from(DatabaseError::interact(&msg, &err)))?
    }

    /// Runs `query` inside a read-write (`IMMEDIATE`) transaction on the pinned connection,
    /// committing on `Ok`.
    pub async fn write<R, E, F>(&self, msg: impl ToString + Send, query: F) -> Result<R, E>
    where
        F: FnOnce(&WriteTx<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<DatabaseError> + Send + 'static,
    {
        let msg = msg.to_string();
        let span = tracing::Span::current();
        self.conn
            .interact(move |conn| {
                let _guard = span.enter();
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|err| E::from(DatabaseError::from(err)))?;
                let write = WriteTx::new(&tx);
                let result = query(&write)?;
                tx.commit().map_err(|err| E::from(DatabaseError::from(err)))?;
                Ok(result)
            })
            .await
            .map_err(|err| E::from(DatabaseError::interact(&msg, &err)))?
    }
}
