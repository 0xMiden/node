use anyhow::{Context, Result, bail, ensure};
use rusqlite::Connection;

use super::{
    CodeMigration, Migration, MigrationBodyRef, MigratorBuilder, SchemaHash, SqlMigration,
    apply_migration_transaction, schema,
};

/// Applies base migrations to new databases and code migrations to existing databases.
#[derive(Debug)]
pub struct Migrator {
    base_migrations: Vec<SqlMigration>,
    code_migrations: Vec<CodeMigration>,
    expected_schema_hashes: Vec<SchemaHash>,
}

impl Migrator {
    pub(super) fn empty() -> Self {
        Self {
            base_migrations: Vec::new(),
            code_migrations: Vec::new(),
            expected_schema_hashes: Vec::new(),
        }
    }

    /// Creates a migration builder backed by an in-memory SQLite database.
    pub fn builder() -> Result<MigratorBuilder> {
        MigratorBuilder::new()
    }

    pub(super) fn next_version(&self) -> usize {
        self.expected_schema_hashes.len() + 1
    }

    pub(super) fn assert_can_push_base(&self) {
        assert!(
            self.code_migrations.is_empty(),
            "cannot add base migration after code migrations have started"
        );
    }

    pub(super) fn push_base(&mut self, migration: SqlMigration, schema_hash: SchemaHash) {
        self.assert_can_push_base();
        self.base_migrations.push(migration);
        self.expected_schema_hashes.push(schema_hash);
    }

    pub(super) fn push_code(&mut self, migration: CodeMigration, schema_hash: SchemaHash) {
        self.code_migrations.push(migration);
        self.expected_schema_hashes.push(schema_hash);
    }

    pub(super) fn validate(&self) -> Result<()> {
        let migration_count = self.base_migrations.len() + self.code_migrations.len();
        ensure!(
            !self.expected_schema_hashes.is_empty(),
            "cannot build migrator without migrations"
        );
        ensure!(
            self.expected_schema_hashes.len() == migration_count,
            "migrator schema hash count {} must match migration count {migration_count}",
            self.expected_schema_hashes.len()
        );
        Ok(())
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
                self.apply_migration(conn, version, MigrationBodyRef::Sql(migration))?;
                applied_version = version;
            }
        }

        let code_start = applied_version.saturating_sub(base_versions);
        for (idx, migration) in self.code_migrations.iter().enumerate().skip(code_start) {
            let version = base_versions + idx + 1;
            self.apply_migration(conn, version, MigrationBodyRef::Code(migration))?;
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
        migration: MigrationBodyRef<'_>,
    ) -> Result<()> {
        let name = migration.name();
        apply_migration_transaction(conn, version, migration, |actual| {
            self.verify_migration_schema_hash(actual, version, name)
        })
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

    fn verify_migration_schema_hash(
        &self,
        actual: SchemaHash,
        version: usize,
        name: &'static str,
    ) -> Result<()> {
        let expected = self.expected_schema_hashes[version - 1];

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
