use std::path::Path;

use miden_node_db::DatabaseError;
use tracing::instrument;

use crate::COMPONENT;

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

#[instrument(level = "debug", target = COMPONENT, skip_all, err)]
pub fn bootstrap_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    tracing::info!(
        target: COMPONENT,
        migration_count = migrator.schema_hashes().len(),
        "Bootstrapping database schema"
    );

    migrator.bootstrap(database_filepath).map_err(DatabaseError::migration)?;
    Ok(())
}

#[instrument(level = "debug", target = COMPONENT, skip_all, err)]
pub fn migrate_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    tracing::info!(
        target: COMPONENT,
        migration_count = migrator.schema_hashes().len(),
        "Applying database migrations"
    );

    migrator.migrate(database_filepath).map_err(DatabaseError::migration)?;
    Ok(())
}

#[instrument(level = "debug", target = COMPONENT, skip_all, err)]
pub fn verify_latest_schema(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    tracing::info!(
        target: COMPONENT,
        migration_count = migrator.schema_hashes().len(),
        "Verifying database schema"
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

    const EXPECTED_SCHEMA_HASHES: [SchemaHash; 1] = [SchemaHash::from_hex(
        "f0631571c590d8b3d183b1fe2dca397e584337d935b7015c58c034a8289c5263",
    )];

    #[test]
    fn migration_schema_hashes_are_stable() -> Result<()> {
        let migrator = migrator()?;

        assert_eq!(migrator.schema_hashes(), SchemaHashes(&EXPECTED_SCHEMA_HASHES));
        Ok(())
    }
}
