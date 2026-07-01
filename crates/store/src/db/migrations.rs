use std::path::Path;

use miden_node_db::DatabaseError;
use miden_node_utils::tracing::miden_instrument;

use crate::{COMPONENT, LOG_TARGET};

include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));

#[miden_instrument(level = "debug", target = COMPONENT, skip_all, err)]
pub fn bootstrap_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    tracing::info!(
        target: LOG_TARGET,
        migration_count = migrator.schema_hashes().len(),
        "Bootstrapping database schema"
    );

    migrator.bootstrap(database_filepath).map_err(DatabaseError::migration)?;

    Ok(())
}

#[miden_instrument(level = "debug", target = COMPONENT, skip_all, err)]
pub fn migrate_database(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    tracing::info!(
        target: LOG_TARGET,
        migration_count = migrator.schema_hashes().len(),
        "Applying database migrations"
    );

    migrator.migrate(database_filepath).map_err(DatabaseError::migration)?;

    Ok(())
}

#[miden_instrument(level = "debug", target = COMPONENT, skip_all, err)]
pub fn verify_latest_schema(database_filepath: &Path) -> std::result::Result<(), DatabaseError> {
    let migrator = migrator().map_err(DatabaseError::migration)?;
    tracing::info!(
        target: LOG_TARGET,
        migration_count = migrator.schema_hashes().len(),
        "Verifying database schema"
    );

    migrator
        .verify_latest_schema(database_filepath)
        .map_err(DatabaseError::migration)?;

    Ok(())
}

#[cfg(test)]
pub(crate) fn test_connection() -> diesel::SqliteConnection {
    use diesel::{Connection, SqliteConnection};

    let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
    let database_filepath = temp_dir.path().join("test.sqlite3");
    bootstrap_database(&database_filepath).expect("database should bootstrap");

    let conn = SqliteConnection::establish(
        database_filepath.to_str().expect("temp database path should be valid UTF-8"),
    )
    .expect("temp file sqlite should always work");
    let _kept_dir = temp_dir.keep();
    conn
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use anyhow::{Context, Result, ensure};
    use miden_node_db::migration::{SchemaHash, SchemaHashes};

    use super::*;

    const EXPECTED_SCHEMA_HASHES: [SchemaHash; 3] = [
        SchemaHash::from_hex("d8f0b2f5c2d7011c2a806ebdb7ddf3d957a6edeed065ccf21019205ebc1a01a4"),
        SchemaHash::from_hex("c68edd8e9f345926b9bde34e2651ca70ee5665ac10c0002f78f589647f7a0d11"),
        SchemaHash::from_hex("9dd91717599abe702e8727f72369ea78302154acf4fdaa5b0f811e405030c7d6"),
    ];

    #[test]
    fn migration_schema_hashes_are_stable() -> Result<()> {
        let migrator = migrator()?;

        pretty_assertions::assert_eq!(
            migrator.schema_hashes(),
            SchemaHashes(&EXPECTED_SCHEMA_HASHES)
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires diesel CLI; CI runs this in the diesel-schema job"]
    fn diesel_schema_is_in_sync_with_migrations() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let database_filepath = temp_dir.path().join("store.sqlite3");
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
