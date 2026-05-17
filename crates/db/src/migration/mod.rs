use std::fmt;
use std::marker::PhantomData;

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, Transaction};

mod schema_hash;

pub use schema_hash::SchemaHash;

/// A pure SQL migration used to bootstrap new databases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseMigration {
    name: &'static str,
    sql: &'static str,
}

impl BaseMigration {
    /// Returns the migration name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the SQL executed by this migration.
    pub fn sql(&self) -> &'static str {
        self.sql
    }
}

/// A Rust migration function executed inside a SQLite transaction.
pub type CodeMigrationFn = for<'conn> fn(&Transaction<'conn>) -> Result<()>;

/// A migration implemented in Rust.
#[derive(Clone, Copy)]
pub struct CodeMigration {
    name: &'static str,
    apply: CodeMigrationFn,
}

impl CodeMigration {
    /// Returns the migration name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl fmt::Debug for CodeMigration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeMigration")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Builder phase which allows adding base migrations.
pub enum BaseMigrationPhase {}

/// Builder phase after code migrations have started.
pub enum CodeMigrationPhase {}

/// Builds a [`Migrator`] while computing expected schema hashes on an in-memory database.
pub struct MigratorBuilder<Phase = BaseMigrationPhase> {
    /// Connection to an in-memory SQLite database used to verify the migrations as they are added.
    reference: Connection,
    /// List of base migrations added so far.
    ///
    /// New base migrations cannot be added after code migrations have started.
    base_migrations: Vec<BaseMigration>,
    /// List of code migrations added so far.
    code_migrations: Vec<CodeMigration>,
    /// Chronological list of computed schema hashes for each migration.
    ///
    /// The length of this list should always match the number of migrations added so far.
    schema_hashes: Vec<SchemaHash>,
    _phase: PhantomData<Phase>,
}

impl MigratorBuilder<BaseMigrationPhase> {
    /// Adds a pure SQL base migration.
    pub fn push_base(mut self, name: &'static str, sql: &'static str) -> Result<Self> {
        let version = self.schema_hashes.len() + 1;
        let hash = Self::apply_migration(&mut self.reference, version, |tx| {
            tx.execute_batch(sql).map_err(Into::into)
        })
        .with_context(|| format!("failed to apply base migration {version}: {name}"))?;

        self.base_migrations.push(BaseMigration { name, sql });
        self.schema_hashes.push(hash);
        Ok(self)
    }
}

impl<T> MigratorBuilder<T> {
    pub fn push_code(
        mut self,
        name: &'static str,
        apply: CodeMigrationFn,
    ) -> Result<MigratorBuilder<CodeMigrationPhase>> {
        let version = self.schema_hashes.len() + 1;
        let hash = Self::apply_migration(&mut self.reference, version, apply)
            .with_context(|| format!("failed to apply code migration {version}: {name}"))?;

        self.code_migrations.push(CodeMigration { name, apply });
        self.schema_hashes.push(hash);
        Ok(MigratorBuilder {
            reference: self.reference,
            base_migrations: self.base_migrations,
            code_migrations: self.code_migrations,
            schema_hashes: self.schema_hashes,
            _phase: PhantomData,
        })
    }

    /// Returns a migrator containing all migrations and their expected schema hashes.
    #[must_use]
    pub fn build(self) -> Migrator {
        Migrator {
            base_migrations: self.base_migrations,
            code_migrations: self.code_migrations,
            expected_schema_hashes: self.schema_hashes,
        }
    }

    fn apply_migration(
        conn: &mut Connection,
        version: usize,
        migration_fn: impl FnOnce(&Transaction) -> Result<()>,
    ) -> Result<SchemaHash> {
        let tx = conn.transaction().context("failed to begin transaction")?;
        migration_fn(&tx).context("failed to execute migration function")?;
        set_user_version(&tx, version).context("failed to set `user_version`")?;
        let hash = SchemaHash::new(&tx).context("failed to compute schema hash")?;
        tx.commit().context("failed to commit transaction")?;

        Ok(hash)
    }
}

/// Applies base migrations to new databases and code migrations to existing databases.
#[derive(Debug)]
pub struct Migrator {
    base_migrations: Vec<BaseMigration>,
    code_migrations: Vec<CodeMigration>,
    expected_schema_hashes: Vec<SchemaHash>,
}

impl Migrator {
    /// Creates a migration builder backed by an in-memory SQLite database.
    pub fn builder() -> Result<MigratorBuilder> {
        let reference = Connection::open_in_memory()
            .context("failed to create in-memory migration database")?;

        Ok(MigratorBuilder {
            reference,
            base_migrations: Vec::new(),
            code_migrations: Vec::new(),
            schema_hashes: Vec::new(),
            _phase: PhantomData,
        })
    }

    /// Applies missing migrations to `conn`.
    pub fn migrate(&self, conn: &mut Connection) -> Result<()> {
        let current_version = read_user_version(conn).context("failed to read database version")?;
        let total_versions = self.expected_schema_hashes.len();

        ensure!(
            current_version <= total_versions,
            "database version {current_version} is newer than migrator version {total_versions}"
        );

        let base_versions = self.base_migrations.len();
        if current_version > 0 && current_version < base_versions {
            let name = self.migration_name(current_version).unwrap_or("<unknown>");
            bail!(
                "database version {current_version} {name:?} is inside the base migration range; \
                 base migrations are only supported for new databases"
            );
        }

        if current_version > 0 {
            self.verify_current_schema(conn, current_version)?;
        }

        let mut applied_version = current_version;
        if applied_version == 0 {
            for (idx, migration) in self.base_migrations.iter().enumerate() {
                let version = idx + 1;
                self.apply_base(conn, version, migration)?;
                applied_version = version;
            }
        }

        let code_start = applied_version.saturating_sub(base_versions);
        for (idx, migration) in self.code_migrations.iter().enumerate().skip(code_start) {
            let version = base_versions + idx + 1;
            self.apply_code(conn, version, migration)?;
        }

        Ok(())
    }

    /// Returns the base migrations.
    #[must_use]
    pub fn base_migrations(&self) -> &[BaseMigration] {
        &self.base_migrations
    }

    /// Returns the code migrations.
    #[must_use]
    pub fn code_migrations(&self) -> &[CodeMigration] {
        &self.code_migrations
    }

    /// Returns the expected schema hash for each migration version.
    #[must_use]
    pub fn expected_schema_hashes(&self) -> &[SchemaHash] {
        &self.expected_schema_hashes
    }

    fn apply_base(
        &self,
        conn: &mut Connection,
        version: usize,
        migration: &BaseMigration,
    ) -> Result<()> {
        let tx = conn.transaction().with_context(|| {
            format!("failed to start transaction for migration {version} {:?}", migration.name)
        })?;

        tx.execute_batch(migration.sql)
            .with_context(|| format!("failed to apply migration {version} {:?}", migration.name))?;
        self.verify_migration_schema(&tx, version, migration.name)?;
        set_user_version(&tx, version).with_context(|| {
            format!("failed to update user_version for migration {version} {:?}", migration.name)
        })?;
        tx.commit()
            .with_context(|| format!("failed to commit migration {version} {:?}", migration.name))
    }

    fn apply_code(
        &self,
        conn: &mut Connection,
        version: usize,
        migration: &CodeMigration,
    ) -> Result<()> {
        let tx = conn.transaction().with_context(|| {
            format!("failed to start transaction for migration {version} {:?}", migration.name)
        })?;

        (migration.apply)(&tx)
            .with_context(|| format!("failed to apply migration {version} {:?}", migration.name))?;
        self.verify_migration_schema(&tx, version, migration.name)?;
        set_user_version(&tx, version).with_context(|| {
            format!("failed to update user_version for migration {version} {:?}", migration.name)
        })?;
        tx.commit()
            .with_context(|| format!("failed to commit migration {version} {:?}", migration.name))
    }

    fn verify_current_schema(&self, conn: &Connection, version: usize) -> Result<()> {
        let name = self.migration_name(version).unwrap_or("<unknown>");
        let expected = self.expected_schema_hashes[version - 1];
        let actual = SchemaHash::new(conn).with_context(|| {
            format!("failed to compute schema hash at database version {version} {name:?}")
        })?;

        ensure!(
            actual == expected,
            "schema hash mismatch at database version {version} {name:?}: expected {expected}, \
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
            format!("failed to compute schema hash after migration {version} {name:?}")
        })?;

        ensure!(
            actual == expected,
            "schema hash mismatch after migration {version} {name:?}: expected {expected}, got \
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
            .map(CodeMigration::name)
    }
}

fn read_user_version(conn: &Connection) -> Result<usize> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    ensure!(version >= 0, "database user_version is negative: {version}");
    usize::try_from(version).context("database user_version does not fit into usize")
}

fn set_user_version(conn: &Connection, version: usize) -> Result<()> {
    let version = version_to_user_version(version)?;
    conn.execute_batch(&format!("PRAGMA user_version = {version};"))?;
    Ok(())
}

fn version_to_user_version(version: usize) -> Result<i32> {
    i32::try_from(version).with_context(|| {
        format!("migration version {version} exceeds SQLite user_version i32 range")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn object_exists(conn: &Connection, name: &str) -> Result<bool> {
        let exists = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?1)",
            [name],
            |row| row.get::<_, bool>(0),
        )?;
        Ok(exists)
    }

    #[test]
    fn migrates_new_database_through_base_and_code() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_base("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);")?
            .push_code("add item height", add_item_height)?
            .build();

        let mut conn = Connection::open_in_memory()?;
        migrator.migrate(&mut conn)?;

        assert_eq!(read_user_version(&conn)?, 2);
        conn.execute("INSERT INTO items (id, value, height) VALUES (1, 'a', 10)", [])?;
        Ok(())
    }

    #[test]
    fn applies_missing_code_migrations_to_existing_database() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_base("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);")?
            .push_code("index item values", add_items_index)?
            .build();

        let mut conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);
             PRAGMA user_version = 1;",
        )?;

        migrator.migrate(&mut conn)?;

        assert_eq!(read_user_version(&conn)?, 2);
        assert!(object_exists(&conn, "idx_items_value")?);
        Ok(())
    }

    #[test]
    fn rejects_existing_database_inside_base_migration_range() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_base("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY);")?
            .push_base("create notes", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")?
            .build();

        let mut conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY);
             PRAGMA user_version = 1;",
        )?;

        let err = migrator.migrate(&mut conn).expect_err("migration should fail");
        assert!(err.to_string().contains("inside the base migration range"));
        Ok(())
    }

    #[test]
    fn verifies_current_schema_before_applying_missing_migrations() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_base("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY);")?
            .build();

        let mut conn = Connection::open_in_memory()?;
        migrator.migrate(&mut conn)?;
        conn.execute_batch("CREATE TABLE tampered (id INTEGER PRIMARY KEY);")?;

        let err = migrator.migrate(&mut conn).expect_err("migration should fail");
        assert!(err.to_string().contains("schema hash mismatch at database version 1"));
        Ok(())
    }

    #[test]
    fn rolls_back_code_migration_when_schema_hash_mismatches() -> Result<()> {
        let migrator = Migrator::builder()?
            .push_base("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY);")?
            .push_code("conditionally create extra", create_extra_table_when_items_exist)?
            .build();

        let mut conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY);
             INSERT INTO items (id) VALUES (1);
             PRAGMA user_version = 1;",
        )?;

        let err = migrator.migrate(&mut conn).expect_err("migration should fail");
        assert!(err.to_string().contains("schema hash mismatch after migration 2"));
        assert_eq!(read_user_version(&conn)?, 1);
        assert!(!object_exists(&conn, "unexpected")?);
        Ok(())
    }
}
