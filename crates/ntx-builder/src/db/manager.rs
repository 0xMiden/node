//! A minimal connection manager wrapper.
//!
//! Only required to setup connection parameters, specifically `WAL`.

use deadpool_sync::InteractError;
use diesel::{RunQueryDsl, SqliteConnection};

#[derive(thiserror::Error, Debug)]
pub enum ConnectionManagerError {
    #[error("failed to apply connection parameter")]
    ConnectionParamSetup(#[source] diesel::result::Error),
    #[error("SQLite pool interaction failed: {0}")]
    InteractError(String),
    #[error("failed to create a new connection")]
    ConnectionCreate(#[source] deadpool_diesel::Error),
    #[error("failed to recycle connection")]
    PoolRecycle(#[source] deadpool::managed::RecycleError<deadpool_diesel::Error>),
}

impl ConnectionManagerError {
    /// Converts from `InteractError`.
    ///
    /// Required since `InteractError` has at least one enum variant that is _not_ `Send +
    /// Sync` and hence prevents the `Sync` auto implementation.
    pub fn interact(msg: &(impl ToString + ?Sized), e: &InteractError) -> Self {
        let msg = msg.to_string();
        Self::InteractError(format!("{msg} failed: {e:?}"))
    }
}

/// Create a connection manager with per-connection setup.
///
/// Particularly, `foreign_key` checks are enabled and using a write-append-log for journaling.
pub(crate) struct ConnectionManager {
    pub(crate) manager: deadpool_diesel::sqlite::Manager,
}

impl ConnectionManager {
    pub(crate) fn new(database_path: &str) -> Self {
        let manager = deadpool_diesel::sqlite::Manager::new(
            database_path.to_owned(),
            deadpool_diesel::sqlite::Runtime::Tokio1,
        );
        Self { manager }
    }
}

impl deadpool::managed::Manager for ConnectionManager {
    type Type = deadpool_sync::SyncWrapper<SqliteConnection>;
    type Error = ConnectionManagerError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let conn = self.manager.create().await.map_err(ConnectionManagerError::ConnectionCreate)?;

        conn.interact(configure_connection_on_creation)
            .await
            .map_err(|e| ConnectionManagerError::interact("Connection setup", &e))??;
        Ok(conn)
    }

    async fn recycle(
        &self,
        conn: &mut Self::Type,
        metrics: &deadpool_diesel::Metrics,
    ) -> deadpool::managed::RecycleResult<Self::Error> {
        self.manager.recycle(conn, metrics).await.map_err(|err| {
            deadpool::managed::RecycleError::Backend(ConnectionManagerError::PoolRecycle(err))
        })?;
        Ok(())
    }
}

pub(crate) fn configure_connection_on_creation(
    conn: &mut SqliteConnection,
) -> Result<(), ConnectionManagerError> {
    // Enable the WAL mode. This allows concurrent reads while a write is in progress.
    diesel::sql_query("PRAGMA journal_mode=WAL")
        .execute(conn)
        .map_err(ConnectionManagerError::ConnectionParamSetup)?;

    // Enable foreign key checks.
    diesel::sql_query("PRAGMA foreign_keys=ON")
        .execute(conn)
        .map_err(ConnectionManagerError::ConnectionParamSetup)?;

    // Set busy timeout so concurrent writers wait instead of immediately failing.
    diesel::sql_query("PRAGMA busy_timeout=5000")
        .execute(conn)
        .map_err(ConnectionManagerError::ConnectionParamSetup)?;
    Ok(())
}
