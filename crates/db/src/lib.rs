mod conv;
mod errors;
mod manager;

use std::num::NonZeroUsize;
use std::path::Path;

pub use conv::{DatabaseTypeConversionError, SqlTypeConvert};
use diesel::{RunQueryDsl, SqliteConnection};
pub use errors::{DatabaseError, SchemaVerificationError};
pub use manager::{ConnectionManager, ConnectionManagerError, configure_connection_on_creation};
use tracing::Instrument;

pub type Result<T, E = DatabaseError> = std::result::Result<T, E>;

/// Returns the default SQLite connection pool size.
///
/// Defaults to twice the available CPU parallelism. If the OS cannot report the available
/// parallelism, fall back to two connections.
pub fn default_connection_pool_size() -> NonZeroUsize {
    let available_cores = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let connection_count = available_cores.saturating_mul(2);
    NonZeroUsize::new(connection_count).expect("connection count must be non-zero")
}

/// Database handle that provides fundamental operations that various components of Miden Node can
/// utililze for their storage needs.
#[derive(Clone)]
pub struct Db {
    pool: deadpool_diesel::Pool<ConnectionManager, deadpool::managed::Object<ConnectionManager>>,
}

impl Db {
    /// Creates a new database instance with the provided connection pool.
    pub fn new(database_filepath: &Path) -> Result<Self, DatabaseError> {
        Self::new_with_pool_size(database_filepath, default_connection_pool_size())
    }

    /// Creates a new database instance with the provided connection pool size.
    pub fn new_with_pool_size(
        database_filepath: &Path,
        connection_pool_size: NonZeroUsize,
    ) -> Result<Self, DatabaseError> {
        let manager = ConnectionManager::new(database_filepath.to_str().unwrap());
        let pool = deadpool_diesel::Pool::builder(manager)
            .max_size(connection_pool_size.get())
            .build()?;
        Ok(Self { pool })
    }

    /// Create and commit a transaction with the queries added in the provided closure
    pub async fn transact<R, E, Q, M>(&self, msg: M, query: Q) -> std::result::Result<R, E>
    where
        Q: Send
            + for<'a, 't> FnOnce(&'a mut SqliteConnection) -> std::result::Result<R, E>
            + 'static,
        R: Send + 'static,
        M: Send + ToString,
        E: From<diesel::result::Error>,
        E: From<DatabaseError>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let conn = self
            .pool
            .get()
            .in_current_span()
            .await
            .map_err(|e| DatabaseError::ConnectionPoolObtainError(Box::new(e)))?;

        let span = tracing::Span::current();
        conn.interact(move |conn| {
            let _guard = span.enter();
            <_ as diesel::Connection>::transaction::<R, E, Q>(conn, query)
        })
        .await
        .map_err(|err| E::from(DatabaseError::interact(&msg.to_string(), &err)))?
    }

    /// Run the query _without_ a transaction
    pub async fn query<R, E, Q, M>(&self, msg: M, query: Q) -> std::result::Result<R, E>
    where
        Q: Send + FnOnce(&mut SqliteConnection) -> std::result::Result<R, E> + 'static,
        R: Send + 'static,
        M: Send + ToString,
        E: From<DatabaseError>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| DatabaseError::ConnectionPoolObtainError(Box::new(e)))?;

        let span = tracing::Span::current();
        conn.interact(move |conn| {
            let _guard = span.enter();
            let r = query(conn)?;
            Ok(r)
        })
        .await
        .map_err(|err| E::from(DatabaseError::interact(&msg.to_string(), &err)))?
    }
}
