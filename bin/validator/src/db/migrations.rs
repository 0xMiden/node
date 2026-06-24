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
    use std::process::Command;

    use anyhow::{Context, Result, ensure};
    use miden_node_db::migration::{SchemaHash, SchemaHashes};

    use super::*;

    const EXPECTED_SCHEMA_HASHES: [SchemaHash; 1] = [SchemaHash::from_hex(
        "100025e3daa05c2f7d5be2dc6ff096dbe916f1af4d95ae27cdfb2e23d6f0723a",
    )];

    #[test]
    fn migration_schema_hashes_are_stable() -> Result<()> {
        let migrator = migrator()?;

        assert_eq!(migrator.schema_hashes(), SchemaHashes(&EXPECTED_SCHEMA_HASHES));
        Ok(())
    }

    #[test]
    #[ignore = "requires diesel CLI; CI runs this in the diesel-schema job"]
    fn diesel_schema_is_in_sync_with_migrations() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let database_filepath = temp_dir.path().join("validator.sqlite3");
        bootstrap_database(&database_filepath)?;

        let output = Command::new("diesel")
            .arg("print-schema")
            .arg("--database-url")
            .arg(&database_filepath)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .context(
                "failed to run diesel CLI; install it with \
                 `cargo install diesel_cli --no-default-features --features sqlite`",
            )?;

        ensure!(
            output.status.success(),
            "diesel print-schema failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let generated =
            String::from_utf8(output.stdout).context("diesel CLI output is not UTF-8")?;
        assert_eq!(generated, include_str!("schema.rs"));
        Ok(())
    }
}
