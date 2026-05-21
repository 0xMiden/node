use std::fmt;

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, Transaction};

use super::schema::{self, SchemaHash};

/// A migration entry that can be executed inside a SQLite transaction.
pub(super) trait MigrationEntry {
    /// Returns the migration name used in diagnostics.
    fn name(&self) -> &'static str;

    /// Executes the migration body inside `tx`.
    fn execute_migration(&self, tx: &Transaction<'_>) -> Result<()>;
}

/// A pure SQL migration.
pub(super) struct SqlMigration {
    name: &'static str,
    sql: &'static str,
}

impl SqlMigration {
    pub(super) fn new(name: &'static str, sql: &'static str) -> Self {
        Self { name, sql }
    }
}

impl MigrationEntry for SqlMigration {
    fn name(&self) -> &'static str {
        self.name
    }

    fn execute_migration(&self, tx: &Transaction<'_>) -> Result<()> {
        tx.execute_batch(self.sql).map_err(Into::into)
    }
}

impl fmt::Debug for SqlMigration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlMigration").field("name", &self.name).finish_non_exhaustive()
    }
}

/// A Rust migration function.
pub(super) struct CodeMigration {
    name: &'static str,
    apply: CodeMigrationFn,
}

impl CodeMigration {
    pub(super) fn new(name: &'static str, apply: CodeMigrationFn) -> Self {
        Self { name, apply }
    }
}

impl MigrationEntry for CodeMigration {
    fn name(&self) -> &'static str {
        self.name
    }

    fn execute_migration(&self, tx: &Transaction<'_>) -> Result<()> {
        (self.apply)(tx)
    }
}

impl fmt::Debug for CodeMigration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeMigration")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// An active migration that remains supported for existing databases.
pub(super) enum Migration {
    Sql(SqlMigration),
    Code(CodeMigration),
}

impl Migration {
    pub(super) fn sql(name: &'static str, sql: &'static str) -> Self {
        Self::Sql(SqlMigration::new(name, sql))
    }

    pub(super) fn code(name: &'static str, apply: CodeMigrationFn) -> Self {
        Self::Code(CodeMigration::new(name, apply))
    }
}

impl MigrationEntry for Migration {
    fn name(&self) -> &'static str {
        match self {
            Self::Sql(migration) => migration.name(),
            Self::Code(migration) => migration.name(),
        }
    }

    fn execute_migration(&self, tx: &Transaction<'_>) -> Result<()> {
        match self {
            Self::Sql(migration) => migration.execute_migration(tx),
            Self::Code(migration) => migration.execute_migration(tx),
        }
    }
}

impl fmt::Debug for Migration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sql(migration) => fmt::Debug::fmt(migration, f),
            Self::Code(migration) => fmt::Debug::fmt(migration, f),
        }
    }
}

/// Applies `migration`, sets `user_version`, commits, and returns the resulting schema hash.
pub(super) fn apply_migration(
    conn: &mut Connection,
    version: usize,
    migration: &impl MigrationEntry,
) -> Result<SchemaHash> {
    apply_migration_transaction(conn, version, migration, Ok::<SchemaHash, anyhow::Error>)
}

/// Applies `migration`, verifies the resulting schema hash, sets `user_version`, and commits.
pub(super) fn apply_migration_and_verify_schema(
    conn: &mut Connection,
    version: usize,
    migration: &impl MigrationEntry,
    expected: SchemaHash,
) -> Result<()> {
    apply_migration_transaction(conn, version, migration, |actual| {
        ensure!(actual == expected, "schema hash mismatch: expected {expected}, got {actual}");
        Ok(())
    })
}

fn apply_migration_transaction<T>(
    conn: &mut Connection,
    version: usize,
    migration: &impl MigrationEntry,
    verify_hash: impl FnOnce(SchemaHash) -> Result<T>,
) -> Result<T> {
    let tx = conn.transaction().context("failed to start transaction")?;

    migration.execute_migration(&tx).context("failed to execute migration")?;
    let schema_hash = SchemaHash::new(&tx).context("failed to compute schema hash")?;
    let result = verify_hash(schema_hash)?;
    schema::set_version(&tx, version).context("failed to update user_version")?;
    tx.commit().context("failed to commit transaction")?;

    Ok(result)
}

/// A Rust migration function executed inside a SQLite transaction.
pub type CodeMigrationFn = for<'conn> fn(&Transaction<'conn>) -> Result<()>;
