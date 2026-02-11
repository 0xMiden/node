use deadpool_sync::InteractError;

use crate::db::manager::ConnectionManagerError;

// DATABASE ERRORS
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("setup deadpool connection pool failed")]
    ConnectionPoolObtainError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    Diesel(#[from] diesel::result::Error),
    #[error("SQLite pool interaction failed: {0}")]
    InteractError(String),
    #[error("schema verification failed")]
    SchemaVerification(#[from] SchemaVerificationError),
    #[error("connection manager error")]
    ConnectionManager(#[source] ConnectionManagerError),
}

impl DatabaseError {
    /// Converts from `InteractError`.
    ///
    /// Required since `InteractError` has at least one enum variant that is _not_ `Send +
    /// Sync` and hence prevents the `Sync` auto implementation. This does an internal
    /// conversion to string while maintaining convenience.
    pub fn interact(msg: &(impl ToString + ?Sized), e: &InteractError) -> Self {
        let msg = msg.to_string();
        Self::InteractError(format!("{msg} failed: {e:?}"))
    }
}

// DATABASE SETUP ERRORS
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum DatabaseSetupError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("database error")]
    Database(#[from] DatabaseError),
    #[error("pool build error")]
    PoolBuild(#[source] deadpool::managed::BuildError),
}

// SCHEMA VERIFICATION ERRORS
// ================================================================================================

/// Errors that can occur during schema verification.
#[derive(Debug, thiserror::Error)]
pub enum SchemaVerificationError {
    #[error("failed to create in-memory reference database")]
    InMemoryDbCreation(#[source] diesel::ConnectionError),
    #[error("failed to apply migrations to reference database")]
    MigrationApplication(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to extract schema from database")]
    SchemaExtraction(#[source] diesel::result::Error),
    #[error(
        "schema mismatch: expected {expected_count} objects, found {actual_count} \
         ({missing_count} missing, {extra_count} unexpected)"
    )]
    Mismatch {
        expected_count: usize,
        actual_count: usize,
        missing_count: usize,
        extra_count: usize,
    },
}
