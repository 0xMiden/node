use std::any::type_name;
use std::io;

use deadpool_sync::InteractError;
use thiserror::Error;

// DATABASE SETUP ERROR
// =================================================================================================

#[derive(Debug, Error)]
pub enum DatabaseSetupError {
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("database error")]
    Database(#[from] DatabaseError),
    #[error("pool build error")]
    PoolBuild(#[from] deadpool::managed::BuildError),
    #[error("Setup deadpool connection pool failed")]
    Pool(#[from] deadpool::managed::PoolError<deadpool_diesel::Error>),
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
}
