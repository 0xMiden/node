use std::any::type_name;
use std::io;

use deadpool_sync::InteractError;
use thiserror::Error;

// SCHEMA VERIFICATION ERROR
// =================================================================================================

/// Errors that can occur during schema verification.
#[derive(Debug, Error)]
pub enum SchemaVerificationError {
    #[error("failed to create in-memory reference database")]
    InMemoryDbCreation(#[source] diesel::ConnectionError),
    #[error("failed to apply migrations to reference database")]
    MigrationApplication(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
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

// DATABASE ERROR
// =================================================================================================

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("SQLite pool interaction failed: {0}")]
    InteractError(String),
    #[error("setup deadpool connection pool failed")]
    ConnectionPoolObtainError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("conversion from SQL to rust type {to} failed")]
    ConversionSqlToRust {
        #[source]
        inner: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        to: &'static str,
    },
    #[error(transparent)]
    Diesel(#[from] diesel::result::Error),
    #[error("schema verification failed")]
    SchemaVerification(#[from] SchemaVerificationError),
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("pool build error")]
    PoolBuild(#[from] deadpool::managed::BuildError),
    #[error("Setup deadpool connection pool failed")]
    Pool(#[from] deadpool::managed::PoolError<deadpool_diesel::Error>),
}

impl DatabaseError {
    /// Converts from `InteractError`
    ///
    /// Note: Required since `InteractError` has at least one enum
    /// variant that is _not_ `Send + Sync` and hence prevents the
    /// `Sync` auto implementation.
    /// This does an internal conversion to string while maintaining
    /// convenience.
    ///
    /// Using `MSG` as const so it can be called as
    /// `.map_err(DatabaseError::interact::<"Your message">)`
    pub fn interact(msg: &(impl ToString + ?Sized), e: &InteractError) -> Self {
        let msg = msg.to_string();
        Self::InteractError(format!("{msg} failed: {e:?}"))
    }

    /// Failed to convert an SQL entry to a rust representation
    pub fn conversiont_from_sql<RT, E, MaybeE>(err: MaybeE) -> DatabaseError
    where
        MaybeE: Into<Option<E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        DatabaseError::ConversionSqlToRust {
            inner: err.into().map(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>),
            to: type_name::<RT>(),
        }
    }

    /// Creates a deserialization error with a static context string and the original error.
    ///
    /// This is a convenience wrapper around [`ConversionSqlToRust`](Self::ConversionSqlToRust).
    pub fn deserialization(
        context: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::ConversionSqlToRust {
            inner: Some(Box::new(source)),
            to: context,
        }
    }
}
