use anyhow::{Context, Result, bail, ensure};
use rusqlite::Connection;

use super::{
    CodeMigration, Migration, MigrationRef, MigratorBuilder, SchemaHash, SqlMigration, schema,
};

/// Applies base migrations to new databases and code migrations to existing databases.
#[derive(Debug)]
pub struct Migrator {
    base_migrations: Vec<SqlMigration>,
    code_migrations: Vec<CodeMigration>,
    expected_schema_hashes: Vec<SchemaHash>,
}

impl Migrator {
    pub(super) fn new(
        base_migrations: Vec<SqlMigration>,
        code_migrations: Vec<CodeMigration>,
        expected_schema_hashes: Vec<SchemaHash>,
    ) -> Self {
        let migration_count = base_migrations.len() + code_migrations.len();
        assert!(
            !expected_schema_hashes.is_empty(),
            "migrator must contain at least one migration"
        );
        assert_eq!(
            expected_schema_hashes.len(),
            migration_count,
            "migrator schema hash count must match migration count"
        );
        Self {
            base_migrations,
            code_migrations,
            expected_schema_hashes,
        }
    }

    /// Creates a migration builder backed by an in-memory SQLite database.
    pub fn builder() -> Result<MigratorBuilder> {
        MigratorBuilder::new()
    }

    /// Returns the schema hash expected after all migrations have been applied.
    pub fn final_schema_hash(&self) -> SchemaHash {
        *self
            .expected_schema_hashes
            .last()
            .expect("migrator must contain at least one schema hash")
    }

    /// Returns the schema hashes expected after each migration.
    pub fn schema_hashes(&self) -> &[SchemaHash] {
        &self.expected_schema_hashes
    }

    /// Applies missing migrations to `conn`.
    pub fn migrate(&self, conn: &mut Connection) -> Result<()> {
        let current_version = self.version_check(conn)?;
        let base_versions = self.base_migrations.len();

        let mut applied_version = current_version;
        if applied_version == 0 {
            for (idx, migration) in self.base_migrations.iter().enumerate() {
                let version = idx + 1;
                self.apply_migration(conn, version, MigrationRef::Sql(migration))?;
                applied_version = version;
            }
        }

        let code_start = applied_version.saturating_sub(base_versions);
        for (idx, migration) in self.code_migrations.iter().enumerate().skip(code_start) {
            let version = base_versions + idx + 1;
            self.apply_migration(conn, version, MigrationRef::Code(migration))?;
        }

        Ok(())
    }

    fn version_check(&self, conn: &Connection) -> Result<usize> {
        let current_version =
            schema::get_version(conn).context("failed to read database version")?;
        let total_versions = self.expected_schema_hashes.len();

        ensure!(
            current_version <= total_versions,
            "database version {current_version} is newer than migrator version {total_versions}"
        );

        let base_versions = self.base_migrations.len();
        if current_version > 0 && current_version < base_versions {
            let name = self.migration_name(current_version).unwrap_or("<unknown>");
            bail!(
                "database version {current_version} \"{name}\" is inside the base migration range; \
                 base migrations are only supported for new databases"
            );
        }

        if current_version > 0 {
            self.verify_current_schema(conn, current_version)?;
        }

        Ok(current_version)
    }

    fn apply_migration(
        &self,
        conn: &mut Connection,
        version: usize,
        migration: MigrationRef<'_>,
    ) -> Result<()> {
        let name = migration.name();
        let tx = conn.transaction().with_context(|| {
            format!("failed to start transaction for migration {version} \"{name}\"")
        })?;

        migration
            .apply(&tx)
            .with_context(|| format!("failed to apply migration {version} \"{name}\""))?;
        self.verify_migration_schema(&tx, version, name)?;
        schema::set_version(&tx, version).with_context(|| {
            format!("failed to update user_version for migration {version} \"{name}\"")
        })?;
        tx.commit()
            .with_context(|| format!("failed to commit migration {version} \"{name}\""))
    }

    fn verify_current_schema(&self, conn: &Connection, version: usize) -> Result<()> {
        let name = self.migration_name(version).unwrap_or("<unknown>");
        let expected = self.expected_schema_hashes[version - 1];
        let actual = SchemaHash::new(conn).with_context(|| {
            format!("failed to compute schema hash at database version {version} \"{name}\"")
        })?;

        ensure!(
            actual == expected,
            "schema hash mismatch at database version {version} \"{name}\": expected {expected}, \
             got {actual}"
        );
        Ok(())
    }

    fn verify_migration_schema(
        &self,
        conn: &Connection,
        version: usize,
        name: &'static str,
    ) -> Result<()> {
        let expected = self.expected_schema_hashes[version - 1];
        let actual = SchemaHash::new(conn).with_context(|| {
            format!("failed to compute schema hash after migration {version} \"{name}\"")
        })?;

        ensure!(
            actual == expected,
            "schema hash mismatch after migration {version} \"{name}\": expected {expected}, got \
             {actual}"
        );
        Ok(())
    }

    fn migration_name(&self, version: usize) -> Option<&'static str> {
        if version == 0 {
            return None;
        }

        if version <= self.base_migrations.len() {
            return Some(self.base_migrations[version - 1].name);
        }

        self.code_migrations
            .get(version - self.base_migrations.len() - 1)
            .map(Migration::name)
    }
}
