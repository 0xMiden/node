mod conv;
mod errors;
pub mod migration;
pub mod sqlite;

use std::num::NonZeroUsize;

pub use conv::{DatabaseTypeConversionError, SqlTypeConvert};
pub use errors::{DatabaseError, SchemaVerificationError};

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

#[doc(hidden)]
pub use miden_node_persistence as persistence;
