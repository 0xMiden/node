use anyhow::{Context, Result, ensure};
use rusqlite::Connection;

use super::{CodeMigrationFn, Migration, MigrationRef, Migrator, SchemaHash, schema};

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
        assert!(
            self.migrator.code_migrations.is_empty(),
            "cannot add base migration after code migrations have started"
        );
        let version = self.migrator.expected_schema_hashes.len() + 1;
        let migration = Migration::base(name, sql);
        let hash =
            Self::apply_migration(&mut self.reference, version, MigrationRef::Sql(&migration))
                .with_context(|| format!("failed to apply base migration {version}: {name}"))?;

        self.migrator.base_migrations.push(migration);
        self.migrator.expected_schema_hashes.push(hash);
        Ok(self)
    }

    /// Adds a Rust migration function.
    pub fn push_code(mut self, name: &'static str, apply: CodeMigrationFn) -> Result<Self> {
        let version = self.migrator.expected_schema_hashes.len() + 1;
        let migration = Migration::code(name, apply);
        let hash =
            Self::apply_migration(&mut self.reference, version, MigrationRef::Code(&migration))
                .with_context(|| format!("failed to apply code migration {version}: {name}"))?;

        self.migrator.code_migrations.push(migration);
        self.migrator.expected_schema_hashes.push(hash);
        Ok(self)
    }

    /// Returns a migrator containing all migrations and their expected schema hashes.
    pub fn build(self) -> Result<Migrator> {
        ensure!(!self.migrator.is_empty(), "cannot build migrator without migrations");
        self.migrator.assert_invariants();
        Ok(self.migrator)
    }

    fn apply_migration(
        conn: &mut Connection,
        version: usize,
        migration: MigrationRef<'_>,
    ) -> Result<SchemaHash> {
        let tx = conn.transaction().context("failed to begin transaction")?;
        migration.apply(&tx).context("failed to execute migration function")?;
        schema::set_version(&tx, version).context("failed to set `user_version`")?;
        let hash = SchemaHash::new(&tx).context("failed to compute schema hash")?;
        tx.commit().context("failed to commit transaction")?;

        Ok(hash)
    }
}
