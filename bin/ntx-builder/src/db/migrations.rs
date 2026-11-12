use std::path::Path;

use miden_node_db::DatabaseError;
use miden_node_tracing::{info, instrument};

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

#[instrument(level = "debug", err)]
pub fn bootstrap_database(database_filepath: &Path) -> Result<(), DatabaseError> {
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
pub fn migrate_database(database_filepath: &Path) -> Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info!("Applying database migrations", migration.count = migrator.schema_hashes().len());

    migrator
        .open_database(database_filepath)
        .and_then(|mut database| database.migrate_to(migrator.latest_version()))
        .map_err(DatabaseError::migration)?;
    Ok(())
}

#[instrument(level = "debug", err)]
pub fn verify_latest_schema(database_filepath: &Path) -> Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    info!("Verifying database schema", migration.count = migrator.schema_hashes().len());

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

    const EXPECTED_SCHEMA_HASHES: [SchemaHash; 6] = [
        SchemaHash::from_hex("c631b773787903a3dd5ea4df5e7374119b3f02b35bacf14d11eacd8d8500e3d9"),
        SchemaHash::from_hex("26b17298444f674b06327ae7289516fe75b59926741b1221ebf36735822d116a"),
        SchemaHash::from_hex("6f27c48c71d173366c90752c330bf888332923e68a290ac3acdb5861539120e8"),
        SchemaHash::from_hex("638b3991fe1b025ab8820e5cfc902d82d212a6bd3eb26d29af3959de1487ea5c"),
        SchemaHash::from_hex("95f93ed0b68d3719a7ea450376e96af1772f7947ddc82fb0a90dac80e049525c"),
        SchemaHash::from_hex("1a0246fd8fd16e298e9eaf73e70f2eafbe68f74da3e5aa8d5c628eddd22f466d"),
    ];

    #[test]
    fn migration_schema_hashes_are_stable() -> Result<()> {
        let migrator = migrator()?;

        assert_eq!(migrator.schema_hashes(), SchemaHashes(&EXPECTED_SCHEMA_HASHES));
        Ok(())
    }
}
