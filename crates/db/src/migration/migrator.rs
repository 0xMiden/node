use anyhow::{Context, Result, bail, ensure};
use rusqlite::Connection;

use super::{
    CodeMigration, Migration, MigrationBodyRef, MigratorBuilder, SchemaHash, SqlMigration,
    apply_migration_transaction, schema,
};

/// Applies versioned database migrations.
///
/// A migrator is built from two ordered migration sets: base SQL migrations followed by code
/// migrations. Base migrations are pure SQL snapshots of migrations whose resulting schema we
/// retain, but whose Rust migration code we no longer want to support. Because that old migration
/// path is intentionally unsupported, base migrations are only applied when creating a new database
/// whose `PRAGMA user_version` is zero. Existing databases are never allowed to run only part of
/// the base SQL set; once a database has a non-zero version, it must already be at or beyond the
/// end of the base migrations.
///
/// Code migrations run after the base SQL set. For existing databases, the migrator reads
/// `user_version`, verifies that the current schema hash matches the expected hash for that
/// version, and then applies only the missing code migrations. Each migration runs in its own
/// transaction and commits only after the resulting schema hash matches the hash computed by the
/// builder.
///
/// Construct a migrator with [`Migrator::builder`] by pushing base migrations first and code
/// migrations second, or call [`Migrator::generate`] from a `build.rs` to generate that builder
/// chain from a migration directory. Callers should snapshot [`Migrator::schema_hashes`] in tests
/// so accidental schema changes are caught, especially when replacing a code migration with
/// equivalent base SQL.
#[derive(Debug)]
pub struct Migrator {
    base_migrations: Vec<SqlMigration>,
    code_migrations: Vec<CodeMigration>,
    expected_schema_hashes: Vec<SchemaHash>,
}

impl Migrator {
    /// Creates an empty migrator used as the builder's backing storage.
    ///
    /// Empty migrators are not exposed to callers; [`MigratorBuilder::build`] validates that at
    /// least one migration was pushed before returning a migrator.
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

    /// Returns the version number that will be assigned to the next migration.
    ///
    /// Versions are one-based and follow insertion order across base migrations first and then code
    /// migrations.
    pub(super) fn next_version(&self) -> usize {
        self.expected_schema_hashes.len() + 1
    }

    /// Adds a base SQL migration and the schema hash expected after it runs.
    ///
    /// This is used by [`MigratorBuilder`] after it has already applied the migration to its
    /// in-memory reference database. The caller must ensure `schema_hash` is the hash of that
    /// reference database after this migration. Base migrations must be added before any code
    /// migration.
    pub(super) fn push_base_unchecked(&mut self, migration: SqlMigration, schema_hash: SchemaHash) {
        assert!(
            self.code_migrations.is_empty(),
            "cannot add base migration after code migrations have started"
        );
        self.base_migrations.push(migration);
        self.expected_schema_hashes.push(schema_hash);
    }

    /// Adds a code migration and the schema hash expected after it runs.
    ///
    /// This is used by [`MigratorBuilder`] after it has already applied the migration to its
    /// in-memory reference database. The caller must ensure `schema_hash` is the hash of that
    /// reference database after this migration.
    pub(super) fn push_code_unchecked(
        &mut self,
        migration: CodeMigration,
        schema_hash: SchemaHash,
    ) {
        self.code_migrations.push(migration);
        self.expected_schema_hashes.push(schema_hash);
    }

    /// Validates invariants that must hold before a migrator can be returned to callers.
    ///
    /// A migrator must contain at least one migration and must have exactly one expected schema
    /// hash for each migration.
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
    ///
    /// Callers can use these hashes in tests when converting a code migration into base SQL: the
    /// replacement SQL should produce the same hash at the same migration index.
    pub fn schema_hashes(&self) -> &[SchemaHash] {
        &self.expected_schema_hashes
    }

    /// Applies missing migrations to `conn`.
    ///
    /// New databases, where `PRAGMA user_version` is zero, receive all base migrations followed by
    /// all code migrations. Existing databases must already be past the base migration range; only
    /// missing code migrations are applied. Every migration runs in its own transaction, updates
    /// `user_version`, and commits only after the resulting schema hash matches the expected hash.
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

    /// Reads and validates the database version before any missing migrations are applied.
    ///
    /// This rejects databases newer than the migrator, databases inside the base migration range,
    /// and databases whose current schema hash does not match the expected hash for their current
    /// version.
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

    /// Applies one migration transaction and verifies its resulting schema hash.
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

    /// Verifies that an existing database still matches the schema hash for its `user_version`.
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

    /// Verifies that a freshly applied migration produced the expected schema hash.
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

    /// Returns the migration name for a one-based migration version.
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
