use std::marker::PhantomData;

use anyhow::{Context, Result, bail, ensure};
use rusqlite::Connection;

use super::{CodeMigrationFn, Migration, Migrator, SchemaHash, schema};

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
    base_migrations: Vec<Migration>,
    /// List of code migrations added so far.
    code_migrations: Vec<Migration>,
    /// Chronological list of computed schema hashes for each migration.
    ///
    /// The length of this list should always match the number of migrations added so far.
    schema_hashes: Vec<SchemaHash>,
    _phase: PhantomData<Phase>,
}

impl MigratorBuilder<BaseMigrationPhase> {
    pub(super) fn new() -> Result<Self> {
        let reference = Connection::open_in_memory()
            .context("failed to create in-memory migration database")?;

        Ok(Self {
            reference,
            base_migrations: Vec::new(),
            code_migrations: Vec::new(),
            schema_hashes: Vec::new(),
            _phase: PhantomData,
        })
    }

    /// Adds a pure SQL base migration.
    pub fn push_base(mut self, name: &'static str, sql: &'static str) -> Result<Self> {
        let version = self.schema_hashes.len() + 1;
        let migration = Migration::base(name, sql);
        let hash = Self::apply_migration(&mut self.reference, version, &migration)
            .with_context(|| format!("failed to apply base migration {version}: {name}"))?;

        self.base_migrations.push(migration);
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
        let migration = Migration::code(name, apply);
        let hash = Self::apply_migration(&mut self.reference, version, &migration)
            .with_context(|| format!("failed to apply code migration {version}: {name}"))?;

        self.code_migrations.push(migration);
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
        Migrator::new(self.base_migrations, self.code_migrations, self.schema_hashes)
    }

    /// Asserts that the schema hash for a migration version matches `expected`.
    pub fn assert_schema_hash(self, version: usize, expected: SchemaHash) -> Result<Self> {
        ensure!(version > 0, "schema hash assertion version must be at least 1");

        let Some(actual) = self.schema_hashes.get(version - 1).copied() else {
            bail!(
                "cannot assert schema hash for migration version {version}; builder has only {} \
                 migrations",
                self.schema_hashes.len()
            );
        };

        let name = self.migration_name(version).unwrap_or("<unknown>");
        ensure!(
            actual == expected,
            "schema hash mismatch for migration {version} \"{name}\": expected {expected}, got \
             {actual}"
        );

        Ok(self)
    }

    fn apply_migration(
        conn: &mut Connection,
        version: usize,
        migration: &Migration,
    ) -> Result<SchemaHash> {
        let tx = conn.transaction().context("failed to begin transaction")?;
        migration.apply(&tx).context("failed to execute migration function")?;
        schema::set_version(&tx, version).context("failed to set `user_version`")?;
        let hash = SchemaHash::new(&tx).context("failed to compute schema hash")?;
        tx.commit().context("failed to commit transaction")?;

        Ok(hash)
    }

    fn migration_name(&self, version: usize) -> Option<&'static str> {
        if version == 0 {
            return None;
        }

        if version <= self.base_migrations.len() {
            return Some(self.base_migrations[version - 1].name());
        }

        self.code_migrations
            .get(version - self.base_migrations.len() - 1)
            .map(Migration::name)
    }
}
