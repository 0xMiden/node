use std::path::Path;

use anyhow::{Result as AnyhowResult, ensure};
use miden_node_db::DatabaseError;
use miden_node_tracing::{info, instrument};
use rusqlite::{Connection, OpenFlags};

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

#[instrument(level = "debug", err)]
pub fn bootstrap_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info!(
        "Bootstrapping database schema",
        migration.count = migrator.schema_hashes().len()
    );

    migrator
        .create_database(database_filepath)
        .and_then(|mut database| database.migrate_to(migrator.latest_version()))
        .map_err(DatabaseError::migration)?;

    Ok(())
}

#[instrument(level = "debug", err)]
pub fn migrate_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    reject_populated_legacy_database(database_filepath).map_err(DatabaseError::migration)?;
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info!("Applying database migrations", migration.count = migrator.schema_hashes().len());

    migrator
        .open_database(database_filepath)
        .and_then(|mut database| database.migrate_to(migrator.latest_version()))
        .map_err(DatabaseError::migration)?;

    Ok(())
}

#[instrument(level = "debug", err)]
pub fn verify_latest_schema(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info!("Verifying database schema", migration.count = migrator.schema_hashes().len());

    migrator
        .verify_latest_schema(database_filepath)
        .map_err(DatabaseError::migration)?;

    Ok(())
}

#[cfg(test)]
mod tests;

/// Rejects old history before migration can commit changes to its schema or metadata.
fn reject_populated_legacy_database(path: &Path) -> AnyhowResult<()> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > 0 && version < 9 {
        let populated: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM block_headers) OR EXISTS(SELECT 1 FROM transactions)",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            !populated,
            "transaction log persistence requires a fresh data directory; preserve the existing directory and bootstrap a new store"
        );
    }
    Ok(())
}
