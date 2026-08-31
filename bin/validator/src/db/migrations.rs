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
mod tests {
    use anyhow::Result;
    use miden_node_db::migration::{SchemaHash, SchemaHashes};

    use super::*;

    const EXPECTED_SCHEMA_HASHES: [SchemaHash; 2] = [
        SchemaHash::from_hex("f2f6af5e22d8d0273524a227417339279d1a694c3802a8f3f7cc4b31e21ee035"),
        SchemaHash::from_hex("d47452a5312db149b49e6f2681c8f766a3f5aa65598df2194e86b064243960b4"),
    ];

    #[test]
    fn migration_schema_hashes_are_stable() -> Result<()> {
        let migrator = migrator()?;

        assert_eq!(migrator.schema_hashes(), SchemaHashes(&EXPECTED_SCHEMA_HASHES));
        Ok(())
    }
}
