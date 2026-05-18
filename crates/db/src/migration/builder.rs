use anyhow::{Context, Result};
use rusqlite::Connection;

use super::{
    CodeMigrationFn, Migration, MigrationBodyRef, Migrator, SchemaHash, apply_migration_transaction,
};

/// Builds a [`Migrator`] while computing expected schema hashes on an in-memory database.
pub struct MigratorBuilder {
    /// Connection to an in-memory SQLite database used to verify the migrations as they are added.
    reference: Connection,
    /// Migrator being built.
    migrator: Migrator,
}

impl MigratorBuilder {
    pub(super) fn new() -> Result<Self> {
        let reference = Connection::open_in_memory()
            .context("failed to create in-memory migration database")?;

        Ok(Self { reference, migrator: Migrator::empty() })
    }

    /// Adds a pure SQL base migration.
    pub fn push_base(mut self, name: &'static str, sql: &'static str) -> Result<Self> {
        self.migrator.assert_can_push_base();
        let version = self.migrator.next_version();
        let migration = Migration::base(name, sql);
        let hash: SchemaHash = apply_migration_transaction(
            &mut self.reference,
            version,
            MigrationBodyRef::Sql(&migration),
            Ok::<SchemaHash, anyhow::Error>,
        )
        .with_context(|| format!("failed to apply base migration {version}: {name}"))?;

        self.migrator.push_base(migration, hash);
        Ok(self)
    }

    /// Adds a Rust migration function.
    pub fn push_code(mut self, name: &'static str, apply: CodeMigrationFn) -> Result<Self> {
        let version = self.migrator.next_version();
        let migration = Migration::code(name, apply);
        let hash: SchemaHash = apply_migration_transaction(
            &mut self.reference,
            version,
            MigrationBodyRef::Code(&migration),
            Ok::<SchemaHash, anyhow::Error>,
        )
        .with_context(|| format!("failed to apply code migration {version}: {name}"))?;

        self.migrator.push_code(migration, hash);
        Ok(self)
    }

    /// Returns a migrator containing all migrations and their expected schema hashes.
    pub fn build(self) -> Result<Migrator> {
        self.migrator.validate()?;
        Ok(self.migrator)
    }
}
