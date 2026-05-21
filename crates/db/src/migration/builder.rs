use anyhow::{Context, Result};
use rusqlite::Connection;

use super::entry::{CodeMigrationFn, Migration, SqlMigration, apply_migration};
use super::{Migrator, SchemaHash};

/// Builds a [`Migrator`] while computing expected schema hashes on an in-memory database.
///
/// ```ignore
/// use miden_node_db::migration::{Migrator, SchemaHash};
/// use rusqlite::Transaction;
///
/// fn add_item_height(tx: &Transaction<'_>) -> anyhow::Result<()> {
///     tx.execute_batch("ALTER TABLE items ADD COLUMN height INTEGER;")?;
///     Ok(())
/// }
///
/// fn migrator() -> anyhow::Result<Migrator> {
///     Migrator::builder()?
///         .push_retired(
///             "001_create_items",
///             "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);",
///         )?
///         .push_sql("002_index_items", "CREATE INDEX idx_items_value ON items(value);")?
///         .push_code("003_add_item_height", add_item_height)?
///         .build()
/// }
///
/// const EXPECTED_SCHEMA_HASHES: [SchemaHash; 3] = [
///     SchemaHash::from_hex(
///         "1111111111111111111111111111111111111111111111111111111111111111",
///     ),
///     SchemaHash::from_hex(
///         "2222222222222222222222222222222222222222222222222222222222222222",
///     ),
///     SchemaHash::from_hex(
///         "3333333333333333333333333333333333333333333333333333333333333333",
///     ),
/// ];
///
/// #[test]
/// fn migration_schema_hashes_are_stable() -> anyhow::Result<()> {
///     let migrator = migrator()?;
///
///     assert_eq!(migrator.schema_hashes(), &EXPECTED_SCHEMA_HASHES);
///     Ok(())
/// }
/// ```
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

    /// Adds a pure SQL retired migration.
    ///
    /// Retired migrations initialize fresh databases from SQL that replaces old active migrations. They
    /// must be pushed before any active migration.
    pub fn push_retired(mut self, name: &'static str, sql: &'static str) -> Result<Self> {
        let version = self.migrator.next_version();
        let migration = SqlMigration::new(name, sql);
        let hash: SchemaHash = apply_migration(&mut self.reference, version, &migration)
            .with_context(|| format!("failed to apply retired migration {version} \"{name}\""))?;

        self.migrator.push_retired_unchecked(migration, hash);
        Ok(self)
    }

    /// Adds a SQL migration that remains supported for existing databases.
    pub fn push_sql(mut self, name: &'static str, sql: &'static str) -> Result<Self> {
        let version = self.migrator.next_version();
        let migration = Migration::sql(name, sql);
        let hash: SchemaHash = apply_migration(&mut self.reference, version, &migration)
            .with_context(|| format!("failed to apply SQL migration {version} \"{name}\""))?;

        self.migrator.push_active_unchecked(migration, hash);
        Ok(self)
    }

    /// Adds a Rust migration function.
    pub fn push_code(mut self, name: &'static str, apply: CodeMigrationFn) -> Result<Self> {
        let version = self.migrator.next_version();
        let migration = Migration::code(name, apply);
        let hash: SchemaHash = apply_migration(&mut self.reference, version, &migration)
            .with_context(|| format!("failed to apply code migration {version} \"{name}\""))?;

        self.migrator.push_active_unchecked(migration, hash);
        Ok(self)
    }

    /// Returns a migrator containing all migrations and their expected schema hashes.
    pub fn build(self) -> Result<Migrator> {
        self.migrator.validate()?;
        Ok(self.migrator)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use rusqlite::{Connection, Transaction};

    use super::super::{Migrator, SchemaHash};

    fn add_item_height(tx: &Transaction<'_>) -> Result<()> {
        tx.execute_batch("ALTER TABLE items ADD COLUMN height INTEGER;")?;
        Ok(())
    }

    #[test]
    fn empty_builder_returns_error() -> Result<()> {
        let err = Migrator::builder()?.build().expect_err("empty builder should fail");
        assert!(err.to_string().contains("cannot build migrator without migrations"));
        Ok(())
    }

    #[test]
    #[should_panic(expected = "cannot add retired migration after active migrations have started")]
    fn panics_when_adding_retired_after_active_migration() {
        let _builder = Migrator::builder()
            .expect("builder should be created")
            .push_sql("create items", "CREATE TABLE items (id INTEGER PRIMARY KEY);")
            .expect("SQL migration should be added")
            .push_retired("add notes", "CREATE TABLE notes (id INTEGER PRIMARY KEY);");
    }

    #[test]
    fn exposes_schema_hashes() -> Result<()> {
        let reference = Connection::open_in_memory()?;
        reference.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);")?;
        let retired_hash = SchemaHash::new(&reference)?;
        reference.execute_batch("CREATE INDEX idx_items_value ON items(value);")?;
        let sql_hash = SchemaHash::new(&reference)?;
        reference.execute_batch("ALTER TABLE items ADD COLUMN height INTEGER;")?;
        let final_hash = SchemaHash::new(&reference)?;

        let migrator = Migrator::builder()?
            .push_retired(
                "create items",
                "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);",
            )?
            .push_sql("index item values", "CREATE INDEX idx_items_value ON items(value);")?
            .push_code("add item height", add_item_height)?
            .build()?;

        assert_eq!(migrator.schema_hashes(), &[retired_hash, sql_hash, final_hash]);
        Ok(())
    }
}
