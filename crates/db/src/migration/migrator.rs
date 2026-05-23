use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use rusqlite::Connection;

use super::entry::{Migration, MigrationEntry, SqlMigration, apply_migration_and_verify_schema};
use super::{MigratorBuilder, SchemaHash, SchemaHashes, schema};

/// Applies versioned database migrations.
///
/// A migrator is built from two ordered migration sets: retired SQL migrations followed by active
/// migrations. Retired migrations are pure SQL snapshots of older active migrations whose schema we
/// retain, but whose upgrade path we no longer want to support. Because that old migration path is
/// intentionally unsupported, retired migrations are only applied when creating a new database whose
/// `PRAGMA user_version` is zero. Existing databases are never allowed to run only part of the
/// retired SQL set; once a database has a non-zero version, it must already be at or beyond the end
/// of the retired migrations.
///
/// Active migrations run after the retired SQL set and can be pure SQL or Rust functions. For
/// existing databases, the migrator reads `user_version`, verifies that the current schema hash
/// matches the expected hash for that version, and then applies only the missing active migrations.
/// Each migration runs in its own transaction and commits only after the resulting schema hash
/// matches the hash computed by the builder.
///
/// Construct a migrator with [`Migrator::builder`] by pushing retired migrations first and active
/// migrations second, or call [`Migrator::generate`] from a `build.rs` to generate that builder
/// chain from a migration directory. Callers should snapshot [`Migrator::schema_hashes`] in tests
/// so accidental schema changes are caught, especially when replacing active migrations with
/// equivalent retired SQL.
#[derive(Debug)]
pub struct Migrator {
    retired_migrations: Vec<SqlMigration>,
    active_migrations: Vec<Migration>,
    expected_schema_hashes: Vec<SchemaHash>,
}

impl Migrator {
    /// Creates an empty migrator used as the builder's backing storage.
    ///
    /// Empty migrators are not exposed to callers; [`MigratorBuilder::build`] validates that at
    /// least one migration was pushed before returning a migrator.
    pub(super) fn empty() -> Self {
        Self {
            retired_migrations: Vec::new(),
            active_migrations: Vec::new(),
            expected_schema_hashes: Vec::new(),
        }
    }

    /// Creates a migration builder backed by an in-memory SQLite database.
    pub fn builder() -> Result<MigratorBuilder> {
        MigratorBuilder::new()
    }

    /// Returns the version number that will be assigned to the next migration.
    ///
    /// Versions are one-based and follow insertion order across retired migrations first and then
    /// active migrations.
    pub(super) fn next_version(&self) -> usize {
        self.expected_schema_hashes.len() + 1
    }

    /// Adds a retired SQL migration and the schema hash expected after it runs.
    ///
    /// This is used by [`MigratorBuilder`] after it has already applied the migration to its
    /// in-memory reference database. The caller must ensure `schema_hash` is the hash of that
    /// reference database after this migration. Retired migrations must be added before any active
    /// migration.
    pub(super) fn push_retired_unchecked(
        &mut self,
        migration: SqlMigration,
        schema_hash: SchemaHash,
    ) {
        assert!(
            self.active_migrations.is_empty(),
            "cannot add retired migration after active migrations have started"
        );
        self.retired_migrations.push(migration);
        self.expected_schema_hashes.push(schema_hash);
    }

    /// Adds an active migration and the schema hash expected after it runs.
    ///
    /// This is used by [`MigratorBuilder`] after it has already applied the migration to its
    /// in-memory reference database. The caller must ensure `schema_hash` is the hash of that
    /// reference database after this migration.
    pub(super) fn push_active_unchecked(&mut self, migration: Migration, schema_hash: SchemaHash) {
        self.active_migrations.push(migration);
        self.expected_schema_hashes.push(schema_hash);
    }

    /// Validates invariants that must hold before a migrator can be returned to callers.
    ///
    /// A migrator must contain at least one migration and must have exactly one expected schema
    /// hash for each migration.
    pub(super) fn validate(&self) -> Result<()> {
        let migration_count = self.retired_migrations.len() + self.active_migrations.len();
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
    /// Callers can use these hashes in tests when retiring active migrations into SQL: the
    /// replacement SQL should produce the same hash at the same migration index.
    pub fn schema_hashes(&self) -> SchemaHashes<'_> {
        SchemaHashes(&self.expected_schema_hashes)
    }

    /// Applies missing migrations to the database at `database_filepath`.
    ///
    /// New databases, where `PRAGMA user_version` is zero, receive all retired migrations followed
    /// by all active migrations. Existing databases must already be past the retired migration
    /// range; only missing active migrations are applied. Every migration runs in its own transaction,
    /// updates `user_version`, and commits only after the resulting schema hash matches the
    /// expected hash.
    pub fn migrate(&self, database_filepath: impl AsRef<Path>) -> Result<()> {
        let database_filepath = database_filepath.as_ref();
        let mut conn = Connection::open(database_filepath)
            .with_context(|| format!("failed to open database {}", database_filepath.display()))?;

        self.migrate_connection(&mut conn)
    }

    fn migrate_connection(&self, conn: &mut Connection) -> Result<()> {
        let current_version = self.version_check(conn)?;
        let retired_versions = self.retired_migrations.len();

        let mut applied_version = current_version;
        if applied_version == 0 {
            for (idx, migration) in self.retired_migrations.iter().enumerate() {
                let version = idx + 1;
                self.apply_migration(conn, version, migration)?;
                applied_version = version;
            }
        }

        let active_start = applied_version.saturating_sub(retired_versions);
        for (idx, migration) in self.active_migrations.iter().enumerate().skip(active_start) {
            let version = retired_versions + idx + 1;
            self.apply_migration(conn, version, migration)?;
        }

        Ok(())
    }

    /// Reads and validates the database version before any missing migrations are applied.
    ///
    /// This rejects databases newer than the migrator, databases inside the retired migration
    /// range, and databases whose current schema hash does not match the expected hash for their
    /// current version.
    fn version_check(&self, conn: &Connection) -> Result<usize> {
        let current_version =
            schema::get_version(conn).context("failed to read database version")?;
        let total_versions = self.expected_schema_hashes.len();

        ensure!(
            current_version <= total_versions,
            "database version {current_version} is newer than migrator version {total_versions}"
        );

        let retired_versions = self.retired_migrations.len();
        if current_version > 0 && current_version < retired_versions {
            let name = self.migration_name(current_version).unwrap_or("<unknown>");
            bail!(
                "database version {current_version} \"{name}\" is inside the retired migration \
                 range; retired migrations can only initialize new databases"
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
        migration: &impl MigrationEntry,
    ) -> Result<()> {
        let name = migration.name();
        let expected = self.expected_schema_hashes[version - 1];
        apply_migration_and_verify_schema(conn, version, migration, expected)
            .with_context(|| format!("failed to apply migration {version} \"{name}\""))
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

    /// Returns the migration name for a one-based migration version.
    fn migration_name(&self, version: usize) -> Option<&'static str> {
        if version == 0 {
            return None;
        }

        if version <= self.retired_migrations.len() {
            return Some(self.retired_migrations[version - 1].name());
        }

        self.active_migrations
            .get(version - self.retired_migrations.len() - 1)
            .map(MigrationEntry::name)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use anyhow::Result;
    use rusqlite::{Connection, Transaction};

    use super::super::{Migrator, schema};

    fn add_items_index(tx: &Transaction<'_>) -> Result<()> {
        tx.execute_batch("CREATE INDEX idx_items_value ON items(value);")?;
        Ok(())
    }

    fn add_item_height(tx: &Transaction<'_>) -> Result<()> {
        tx.execute_batch("ALTER TABLE items ADD COLUMN height INTEGER;")?;
        Ok(())
    }

    fn create_extra_table_when_items_exist(tx: &Transaction<'_>) -> Result<()> {
        let item_count: i64 = tx.query_row("SELECT COUNT(*) FROM items", [], |row| row.get(0))?;
        if item_count > 0 {
            tx.execute_batch("CREATE TABLE unexpected (id INTEGER PRIMARY KEY);")?;
        }
        Ok(())
    }

    fn create_items_table(tx: &Transaction<'_>) -> Result<()> {
        tx.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);")?;
        Ok(())
    }

    fn object_exists(conn: &Connection, name: &str) -> Result<bool> {
        let exists = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?1)",
            [name],
            |row| row.get::<_, bool>(0),
        )?;
        Ok(exists)
    }

    struct TestDatabase {
        path: PathBuf,
    }

    impl TestDatabase {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("miden-node-db-migrator-{name}-{}.sqlite3", std::process::id()));
            let db = Self { path };
            db.remove_files();
            db
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn open(&self) -> Result<Connection> {
            Connection::open(&self.path).map_err(Into::into)
        }

        fn remove_files(&self) {
            let _ = fs_err::remove_file(&self.path);
            let _ = fs_err::remove_file(self.path.with_extension("sqlite3-wal"));
            let _ = fs_err::remove_file(self.path.with_extension("sqlite3-shm"));
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            self.remove_files();
        }
    }

    #[test]
    fn migrates_new_database_through_retired_and_code() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_retired(
                "create items",
                "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);",
            )?
            .push_code("add item height", add_item_height)?
            .build()?;

        let db = TestDatabase::new("migrates_new_database_through_retired_and_code");
        migrator.migrate(db.path())?;

        let conn = db.open()?;
        assert_eq!(schema::get_version(&conn)?, 2);
        conn.execute("INSERT INTO items (id, value, height) VALUES (1, 'a', 10)", [])?;
        Ok(())
    }

    #[test]
    fn migrates_new_database_with_code_only_migration() -> Result<()> {
        let migrator =
            Migrator::builder()?.push_code("create items", create_items_table)?.build()?;

        let db = TestDatabase::new("migrates_new_database_with_code_only_migration");
        migrator.migrate(db.path())?;

        let conn = db.open()?;
        assert_eq!(schema::get_version(&conn)?, 1);
        conn.execute("INSERT INTO items (id, value) VALUES (1, 'a')", [])?;
        Ok(())
    }

    #[test]
    fn migrates_new_database_with_sql_only_migration() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_sql("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);")?
            .build()?;

        let db = TestDatabase::new("migrates_new_database_with_sql_only_migration");
        migrator.migrate(db.path())?;

        let conn = db.open()?;
        assert_eq!(schema::get_version(&conn)?, 1);
        conn.execute("INSERT INTO items (id, value) VALUES (1, 'a')", [])?;
        Ok(())
    }

    #[test]
    fn applies_missing_code_migrations_to_existing_database() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_retired(
                "create items",
                "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);",
            )?
            .push_code("index item values", add_items_index)?
            .build()?;

        let db = TestDatabase::new("applies_missing_code_migrations_to_existing_database");
        {
            let conn = db.open()?;
            conn.execute_batch(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);
                 PRAGMA user_version = 1;",
            )?;
        }

        migrator.migrate(db.path())?;

        let conn = db.open()?;
        assert_eq!(schema::get_version(&conn)?, 2);
        assert!(object_exists(&conn, "idx_items_value")?);
        Ok(())
    }

    #[test]
    fn rejects_existing_database_inside_retired_migration_range() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_retired("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY);")?
            .push_retired("create notes", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")?
            .build()?;

        let db = TestDatabase::new("rejects_existing_database_inside_retired_migration_range");
        {
            let conn = db.open()?;
            conn.execute_batch(
                "CREATE TABLE items (id INTEGER PRIMARY KEY);
                 PRAGMA user_version = 1;",
            )?;
        }

        let err = migrator.migrate(db.path()).expect_err("migration should fail");
        assert!(err.to_string().contains("inside the retired migration range"));
        Ok(())
    }

    #[test]
    fn verifies_current_schema_before_applying_missing_migrations() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_retired("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY);")?
            .build()?;

        let db = TestDatabase::new("verifies_current_schema_before_applying_missing_migrations");
        migrator.migrate(db.path())?;
        {
            let conn = db.open()?;
            conn.execute_batch("CREATE TABLE tampered (id INTEGER PRIMARY KEY);")?;
        }

        let err = migrator.migrate(db.path()).expect_err("migration should fail");
        assert!(err.to_string().contains("schema hash mismatch at database version 1"));
        Ok(())
    }

    #[test]
    fn rolls_back_code_migration_when_schema_hash_mismatches() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_retired("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY);")?
            .push_code("conditionally create extra", create_extra_table_when_items_exist)?
            .build()?;

        let db = TestDatabase::new("rolls_back_code_migration_when_schema_hash_mismatches");
        {
            let conn = db.open()?;
            conn.execute_batch(
                "CREATE TABLE items (id INTEGER PRIMARY KEY);
                 INSERT INTO items (id) VALUES (1);
                 PRAGMA user_version = 1;",
            )?;
        }

        let err = migrator.migrate(db.path()).expect_err("migration should fail");
        assert!(err.to_string().contains("failed to apply migration 2"));
        assert!(err.chain().any(|cause| cause.to_string().contains("schema hash mismatch")));

        let conn = db.open()?;
        assert_eq!(schema::get_version(&conn)?, 1);
        assert!(!object_exists(&conn, "unexpected")?);
        Ok(())
    }
}
