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

    const EXPECTED_SCHEMA_HASHES: [SchemaHash; 3] = [
        SchemaHash::from_hex("f2f6af5e22d8d0273524a227417339279d1a694c3802a8f3f7cc4b31e21ee035"),
        SchemaHash::from_hex("5e91b956814dcd627a69417f48231de70e01a8aa97b32e7d3a1db67c077cb4f3"),
        SchemaHash::from_hex("360e9e80a20b94285acaebcb103e7632906d0ade683ea9072603ccfd34e30464"),
    ];

    #[test]
    fn migration_schema_hashes_are_stable() -> Result<()> {
        let migrator = migrator()?;

        assert_eq!(migrator.schema_hashes(), SchemaHashes(&EXPECTED_SCHEMA_HASHES));
        Ok(())
    }
}
