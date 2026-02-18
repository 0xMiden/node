mod conv;
mod errors;
mod manager;

use std::path::Path;

pub use conv::{DatabaseTypeConversionError, SqlTypeConvert};
use diesel::{RunQueryDsl, SqliteConnection};
pub use errors::{DatabaseError, DatabaseSetupError};
pub use manager::{ConnectionManager, ConnectionManagerError, configure_connection_on_creation};
use tracing::Instrument;

pub type Result<T, E = DatabaseError> = std::result::Result<T, E>;

/// Database handle that provides fundamental operations that various components of Miden Node can
/// utililze for their storage needs.
pub struct Db {
    pool: deadpool_diesel::Pool<ConnectionManager, deadpool::managed::Object<ConnectionManager>>,
}

impl Db {
    /// Creates a new database instance with the provided connection pool.
    pub fn new(database_filepath: &Path) -> Result<Self, DatabaseSetupError> {
        let manager = ConnectionManager::new(database_filepath.to_str().unwrap());
        let pool = deadpool_diesel::Pool::builder(manager).max_size(16).build()?;
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

        conn.interact(|conn| <_ as diesel::Connection>::transaction::<R, E, Q>(conn, query))
            .in_current_span()
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

        conn.interact(move |conn| {
            let r = query(conn)?;
            Ok(r)
        })
        .await
        .map_err(|err| E::from(DatabaseError::interact(&msg.to_string(), &err)))?
    }
}
