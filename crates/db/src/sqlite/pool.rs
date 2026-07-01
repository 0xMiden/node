//! Async connection pool over raw `rusqlite`.
//!
//! SQLite permits only a single writer at a time, so the pool is split into a **single** writer
//! connection and a pool of read-only connections. Writes (`write`/`begin_write`) serialize on the
//! one writer; reads (`read`/`begin_read`) run concurrently on the reader pool. This makes the
//! single-writer model structural (rather than relying on lock contention) and lets a held write
//! transaction stay open without starving readers.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use deadpool::Runtime;
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleError, RecycleResult};
use deadpool_sync::SyncWrapper;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use tracing::Instrument;

use crate::sqlite::tx::{ReadTx, WriteTx};
use crate::{DatabaseError, default_connection_pool_size};

/// Per-connection prepared-statement cache capacity. Raised well above rusqlite's default of 16
/// because we keep a large set of distinct statements; the bounded connection pools cap total
/// cached-statement memory.
const STATEMENT_CACHE_CAPACITY: usize = 512;

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
    /// When set, connections are configured `PRAGMA query_only = ON` and skip the writer-only
    /// `journal_mode` setup — used for the reader pool.
    query_only: bool,
}

impl Manager for SqliteManager {
    type Type = SyncWrapper<Connection>;
    type Error = SqliteManagerError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let path = self.path.clone();
        let query_only = self.query_only;
        SyncWrapper::new(Runtime::Tokio1, move || {
            let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(SqliteManagerError::Open)?;
            configure_connection(&conn, query_only).map_err(SqliteManagerError::Configure)?;
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
        // Safety net for a held transaction handle dropped without `commit`/`rollback`: roll back
        // any still-open transaction so the next user gets a clean connection.
        conn.interact(|conn| {
            if !conn.is_autocommit() {
                let _ = conn.execute_batch("ROLLBACK");
            }
        })
        .await
        .map_err(|_| RecycleError::Backend(SqliteManagerError::Poisoned))?;
        Ok(())
    }
}

/// Applies the per-connection PRAGMAs and statement-cache sizing.
///
/// Both pools open the file `READ_WRITE`; reader connections are made read-only at runtime with
/// `PRAGMA query_only = ON` (which, unlike opening `READ_ONLY`, still lets them create the WAL
/// `-shm` file and read a WAL database).
fn configure_connection(conn: &Connection, query_only: bool) -> rusqlite::Result<()> {
    // busy_timeout makes concurrent writers wait instead of failing immediately; foreign keys
    // enforce referential integrity.
    if query_only {
        // A query_only connection cannot set `journal_mode` (it is a write); WAL is already
        // persisted in the file header by the writer / migration path.
        conn.execute_batch(
            "PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;
             PRAGMA query_only = ON;",
        )?;
    } else {
        // WAL allows concurrent readers while the writer holds the lock.
        conn.execute_batch(
            "PRAGMA busy_timeout = 5000;
             PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;",
        )?;
    }
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
    // Register the `array` extension so the cacheable IN-list helpers can bind lists via
    // `rarray(?)` (see `crate::sqlite::in_list`).
    rusqlite::vtab::array::load_module(conn)?;
    Ok(())
}

// DATABASE
// =================================================================================================

/// A rusqlite-backed connection pool. Cloning shares the underlying pools.
///
/// Holds a single writer connection and a pool of reader connections (see the module docs).
#[derive(Clone)]
pub struct Database {
    writer: Pool<SqliteManager>,
    readers: Pool<SqliteManager>,
}

impl Database {
    /// Opens a database over `database_filepath` with the default reader-pool size.
    pub fn new(database_filepath: &Path) -> Result<Self, DatabaseError> {
        Self::new_with_pool_size(database_filepath, default_connection_pool_size())
    }

    /// Opens a database over `database_filepath` with the given reader-pool size. The writer is
    /// always a single connection.
    pub fn new_with_pool_size(
        database_filepath: &Path,
        connection_pool_size: NonZeroUsize,
    ) -> Result<Self, DatabaseError> {
        let writer = Pool::builder(SqliteManager {
            path: database_filepath.to_path_buf(),
            query_only: false,
        })
        .max_size(1)
        .build()?;
        let readers = Pool::builder(SqliteManager {
            path: database_filepath.to_path_buf(),
            query_only: true,
        })
        .max_size(connection_pool_size.get())
        .build()?;
        Ok(Self { writer, readers })
    }

    /// Checks the single writer connection out of the pool.
    async fn checkout_writer(&self) -> Result<Object<SqliteManager>, DatabaseError> {
        self.writer
            .get()
            .in_current_span()
            .await
            .map_err(|err| DatabaseError::ConnectionPoolObtainError(Box::new(err)))
    }

    /// Checks a reader connection out of the pool.
    async fn checkout_reader(&self) -> Result<Object<SqliteManager>, DatabaseError> {
        self.readers
            .get()
            .in_current_span()
            .await
            .map_err(|err| DatabaseError::ConnectionPoolObtainError(Box::new(err)))
    }

    /// Runs `query` inside a read-only (`DEFERRED`, never committed) transaction on a reader
    /// connection.
    pub async fn read<R, E, F>(&self, msg: impl ToString + Send, query: F) -> Result<R, E>
    where
        F: FnOnce(&ReadTx<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<DatabaseError> + Send + 'static,
    {
        let conn = self.checkout_reader().await.map_err(E::from)?;
        let msg = msg.to_string();
        let span = tracing::Span::current();
        conn.interact(move |conn| {
            let _guard = span.enter();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(|err| E::from(DatabaseError::from(err)))?;
            query(&ReadTx::new(&tx))
            // `tx` is dropped here without a commit, rolling back any writes.
        })
        .await
        .map_err(|err| E::from(DatabaseError::interact(&msg, &err)))?
    }

    /// Runs `query` inside a read-write (`IMMEDIATE`) transaction on the single writer connection,
    /// committing on `Ok`.
    pub async fn write<R, E, F>(&self, msg: impl ToString + Send, query: F) -> Result<R, E>
    where
        F: FnOnce(&WriteTx<'_>) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: From<DatabaseError> + Send + 'static,
    {
        let conn = self.checkout_writer().await.map_err(E::from)?;
        let msg = msg.to_string();
        let span = tracing::Span::current();
        conn.interact(move |conn| {
            let _guard = span.enter();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|err| E::from(DatabaseError::from(err)))?;
            let result = query(&WriteTx::new(&tx))?;
            tx.commit().map_err(|err| E::from(DatabaseError::from(err)))?;
            Ok(result)
        })
        .await
        .map_err(|err| E::from(DatabaseError::interact(&msg, &err)))?
    }

    /// Begins a read-only (`DEFERRED`) transaction on a reader connection and returns a handle held
    /// across `.await` points. See [`ReadTransaction`].
    pub async fn begin_read(&self) -> Result<ReadTransaction, DatabaseError> {
        let conn = self.checkout_reader().await?;
        run_tx_stmt(&conn, "BEGIN DEFERRED").await?;
        Ok(ReadTransaction { conn })
    }

    /// Begins a read-write (`IMMEDIATE`) transaction on the single writer connection and returns a
    /// handle held across `.await` points. The handle must be committed (or it rolls back). See
    /// [`WriteTransaction`].
    pub async fn begin_write(&self) -> Result<WriteTransaction, DatabaseError> {
        let conn = self.checkout_writer().await?;
        run_tx_stmt(&conn, "BEGIN IMMEDIATE").await?;
        Ok(WriteTransaction { conn })
    }
}

// HELD TRANSACTIONS
// =================================================================================================

/// Runs a transaction-control statement (`BEGIN`/`COMMIT`/`ROLLBACK`) on a checked-out connection.
async fn run_tx_stmt(
    conn: &Object<SqliteManager>,
    stmt: &'static str,
) -> Result<(), DatabaseError> {
    conn.interact(move |conn| conn.execute_batch(stmt))
        .await
        .map_err(|err| DatabaseError::interact(stmt, &err))?
        .map_err(DatabaseError::from)
}

/// A read transaction (`DEFERRED`) held across `.await` points, on a reader connection.
///
/// Run batches of synchronous queries with [`run`](Self::run); the transaction stays open between
/// calls, so a request handler can interleave queries with async work on a single consistent
/// snapshot. The transaction is read-only and ends (rolls back) when the handle is dropped, or
/// explicitly via [`close`](Self::close).
pub struct ReadTransaction {
    conn: Object<SqliteManager>,
}

impl ReadTransaction {
    /// Runs a batch of read queries against the open transaction.
    pub async fn run<R, E, F>(&self, msg: impl ToString + Send, query: F) -> Result<R, E>
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
                query(&ReadTx::new(conn))
            })
            .await
            .map_err(|err| E::from(DatabaseError::interact(&msg, &err)))?
    }

    /// Ends the transaction explicitly (rolls back; a read transaction has nothing to commit).
    pub async fn close(self) -> Result<(), DatabaseError> {
        run_tx_stmt(&self.conn, "ROLLBACK").await
    }
}

/// A read-write transaction (`IMMEDIATE`) held across `.await` points, on the single writer
/// connection.
///
/// Run batches of synchronous queries with [`run`](Self::run); the transaction stays open between
/// calls, so a request handler can interleave reads and writes with async work atomically. Finish
/// with [`commit`](Self::commit) to persist, or [`rollback`](Self::rollback) to discard; if the
/// handle is dropped without either, the pool rolls the transaction back when the connection is
/// recycled.
///
/// The handle holds the sole writer connection for its whole lifetime.
pub struct WriteTransaction {
    conn: Object<SqliteManager>,
}

impl WriteTransaction {
    /// Runs a batch of read/write queries against the open transaction.
    pub async fn run<R, E, F>(&self, msg: impl ToString + Send, query: F) -> Result<R, E>
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
                query(&WriteTx::new(conn))
            })
            .await
            .map_err(|err| E::from(DatabaseError::interact(&msg, &err)))?
    }

    /// Commits the transaction, persisting all writes.
    pub async fn commit(self) -> Result<(), DatabaseError> {
        run_tx_stmt(&self.conn, "COMMIT").await
    }

    /// Rolls back the transaction, discarding all writes.
    pub async fn rollback(self) -> Result<(), DatabaseError> {
        run_tx_stmt(&self.conn, "ROLLBACK").await
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::path::{Path, PathBuf};

    use rusqlite::Connection;

    use super::Database;
    use crate::DatabaseError;

    /// A throwaway file-backed database; the pools open existing files `READ_WRITE` only, so the
    /// file and schema are created up front.
    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("miden-node-db-pool-{name}-{}.sqlite3", std::process::id()));
            let db = Self { path };
            db.remove_files();
            let conn = Connection::open(&db.path).expect("create db file");
            conn.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY);")
                .expect("create table");
            db
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn remove_files(&self) {
            let _ = fs_err::remove_file(&self.path);
            let _ = fs_err::remove_file(self.path.with_extension("sqlite3-wal"));
            let _ = fs_err::remove_file(self.path.with_extension("sqlite3-shm"));
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            self.remove_files();
        }
    }

    fn open_db(temp: &TempDb) -> Database {
        Database::new_with_pool_size(temp.path(), NonZeroUsize::new(4).unwrap()).unwrap()
    }

    async fn count_items(db: &Database) -> i64 {
        db.read::<_, DatabaseError, _>("count", |r| {
            Ok(r.query("SELECT COUNT(*) FROM items", &[], |row| row.get::<i64>(0))?
                .into_iter()
                .next()
                .unwrap_or(0))
        })
        .await
        .unwrap()
    }

    async fn insert_committed(db: &Database, id: i64) {
        let tx = db.begin_write().await.unwrap();
        tx.run::<_, DatabaseError, _>("insert", move |w| {
            w.execute("INSERT INTO items (id) VALUES (?1)", &[&id])?;
            Ok(())
        })
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn held_write_transaction_commits_across_awaits() {
        let temp = TempDb::new("commit");
        let db = open_db(&temp);

        let tx = db.begin_write().await.unwrap();
        tx.run::<_, DatabaseError, _>("insert-1", |w| {
            w.execute("INSERT INTO items (id) VALUES (?1)", &[&1i64])?;
            Ok(())
        })
        .await
        .unwrap();

        // Interleave async work between statements on the same still-open transaction.
        tokio::task::yield_now().await;

        tx.run::<_, DatabaseError, _>("insert-2", |w| {
            w.execute("INSERT INTO items (id) VALUES (?1)", &[&2i64])?;
            Ok(())
        })
        .await
        .unwrap();

        tx.commit().await.unwrap();

        assert_eq!(count_items(&db).await, 2);
    }

    #[tokio::test]
    async fn dropped_write_transaction_rolls_back() {
        let temp = TempDb::new("rollback");
        let db = open_db(&temp);

        {
            let tx = db.begin_write().await.unwrap();
            tx.run::<_, DatabaseError, _>("insert", |w| {
                w.execute("INSERT INTO items (id) VALUES (?1)", &[&1i64])?;
                Ok(())
            })
            .await
            .unwrap();
            // `tx` is dropped here without a commit.
        }

        // The sole writer connection is reused; `recycle` must have rolled back the orphaned
        // transaction, otherwise this `BEGIN IMMEDIATE` would fail with "cannot start a transaction
        // within a transaction". The first insert must not have persisted.
        insert_committed(&db, 2).await;
        assert_eq!(count_items(&db).await, 1);
    }

    #[tokio::test]
    async fn reads_proceed_while_write_transaction_is_held() {
        let temp = TempDb::new("concurrent");
        let db = open_db(&temp);
        insert_committed(&db, 1).await;

        // Hold an open write transaction with an uncommitted insert.
        let tx = db.begin_write().await.unwrap();
        tx.run::<_, DatabaseError, _>("insert-uncommitted", |w| {
            w.execute("INSERT INTO items (id) VALUES (?1)", &[&2i64])?;
            Ok(())
        })
        .await
        .unwrap();

        // A read on the reader pool proceeds (does not block on the writer) and does not see the
        // uncommitted row.
        assert_eq!(count_items(&db).await, 1);

        tx.commit().await.unwrap();
        assert_eq!(count_items(&db).await, 2);
    }

    #[tokio::test]
    async fn reader_connections_are_query_only() {
        let temp = TempDb::new("query_only");
        let db = open_db(&temp);

        let query_only = db
            .read::<_, DatabaseError, _>("pragma", |r| {
                Ok(r.query("PRAGMA query_only", &[], |row| row.get::<i64>(0))?
                    .into_iter()
                    .next()
                    .unwrap_or(0))
            })
            .await
            .unwrap();
        assert_eq!(query_only, 1, "reader connections must be query_only");

        // A write attempted on a reader connection is rejected.
        let result = db
            .read::<(), DatabaseError, _>("rejected-write", |r| {
                r.query("INSERT INTO items (id) VALUES (99)", &[], |_| Ok(()))?;
                Ok(())
            })
            .await;
        assert!(result.is_err(), "writes on a reader connection must fail");
    }
}
