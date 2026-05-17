use std::marker::PhantomData;

use anyhow::{Context, Result};
use rusqlite::{Connection, Transaction};

use super::{
    BaseMigration, CodeMigration, CodeMigrationFn, Migrator, SchemaHash, set_user_version,
};

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
