use std::path::Path;

use miden_node_db::DatabaseError;
use miden_node_tracing::{info_v2, instrument_v2};

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

#[instrument_v2(level = "debug", err)]
pub fn bootstrap_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info_v2!(
        "Bootstrapping database schema",
        migration.count = migrator.schema_hashes().len()
    );

    migrator
        .create_database(database_filepath)
        .and_then(|mut database| database.migrate_to(migrator.latest_version()))
        .map_err(DatabaseError::migration)?;

    Ok(())
}

#[instrument_v2(level = "debug", err)]
pub fn migrate_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info_v2!("Applying database migrations", migration.count = migrator.schema_hashes().len());

    migrator
        .open_database(database_filepath)
        .and_then(|mut database| database.migrate_to(migrator.latest_version()))
        .map_err(DatabaseError::migration)?;

    Ok(())
}

#[instrument_v2(level = "debug", err)]
pub fn verify_latest_schema(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info_v2!("Verifying database schema", migration.count = migrator.schema_hashes().len());

    migrator
        .verify_latest_schema(database_filepath)
        .map_err(DatabaseError::migration)?;

    Ok(())
}

#[cfg(test)]
mod tests;
