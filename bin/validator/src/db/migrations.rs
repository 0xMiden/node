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

    migrator
        .create_database(database_filepath)
        .and_then(|mut database| database.migrate_to(migrator.latest_version()))
        .map_err(DatabaseError::migration)?;
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

    migrator
        .open_database(database_filepath)
        .and_then(|mut database| database.migrate_to(migrator.latest_version()))
        .map_err(DatabaseError::migration)?;
    info!(target: LOG_TARGET, "Database migrations completed");
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

    const EXPECTED_SCHEMA_HASHES: [SchemaHash; 5] = [
        SchemaHash::from_hex("616c6ea4220985e67cda942f28f6e16b8b7d0f9eb25f772544c28ab8561f995c"),
        SchemaHash::from_hex("b515225768eeb647a456a6e13f6d4f449b25218bf385ab5f30a4d9f43550e459"),
        SchemaHash::from_hex("c4893a9f1e4702bd1ed68d76ffeabfd9daef9b31f922c83373e50e14dd10b579"),
        SchemaHash::from_hex("0cd30601af887ad6baf71ad793fa5a08bdaeb34ea5113e6bc5d506530d486047"),
        SchemaHash::from_hex("027a6c42055bc813284d2a710e972fe240ec5f50cfc9fc21d498b8109d9dfe65"),
    ];

    #[test]
    fn migration_schema_hashes_are_stable() -> Result<()> {
        let migrator = migrator()?;

        assert_eq!(migrator.schema_hashes(), SchemaHashes(&EXPECTED_SCHEMA_HASHES));
        Ok(())
    }
}
