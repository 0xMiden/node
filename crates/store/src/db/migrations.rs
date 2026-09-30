use std::path::Path;

use miden_node_db::DatabaseError;
use miden_node_tracing::{info, miden_instrument};

use crate::{COMPONENT, LOG_TARGET};

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

#[miden_instrument(
    level = "debug",
    target = COMPONENT,
    err,
)]
pub fn bootstrap_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info!(
        target: LOG_TARGET,
        "Bootstrapping database schema",
        migration.count = migrator.schema_hashes().len()
    );

    migrator.bootstrap(database_filepath).map_err(DatabaseError::migration)?;

    Ok(())
}

#[miden_instrument(
    level = "debug",
    target = COMPONENT,
    err,
)]
pub fn migrate_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info!(
        target: LOG_TARGET,
        "Applying database migrations",
        migration.count = migrator.schema_hashes().len()
    );

    migrator.migrate(database_filepath).map_err(DatabaseError::migration)?;

    Ok(())
}

#[miden_instrument(
    level = "debug",
    target = COMPONENT,
    err,
)]
pub fn verify_latest_schema(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info!(
        target: LOG_TARGET,
        "Verifying database schema",
        migration.count = migrator.schema_hashes().len()
    );

    migrator
        .verify_latest_schema(database_filepath)
        .map_err(DatabaseError::migration)?;

    Ok(())
}

#[cfg(test)]
mod tests;
