use std::fmt;

use anyhow::Result;
use rusqlite::Transaction;

mod builder;
mod migrator;
pub mod schema;

pub use builder::{BaseMigrationPhase, CodeMigrationPhase, MigratorBuilder};
pub use migrator::Migrator;
pub use schema::SchemaHash;

type MigrationFn = dyn for<'conn> Fn(&Transaction<'conn>) -> Result<()> + Send + Sync + 'static;

/// A migration with a name and executable body.
struct Migration {
    name: &'static str,
    apply: Box<MigrationFn>,
}

impl Migration {
    pub(super) fn base(name: &'static str, sql: &'static str) -> Self {
        Self {
            name,
            apply: Box::new(move |tx| tx.execute_batch(sql).map_err(Into::into)),
        }
    }

    pub(super) fn code(name: &'static str, apply: CodeMigrationFn) -> Self {
        Self { name, apply: Box::new(apply) }
    }

    /// Returns the migration name.
    fn name(&self) -> &'static str {
        self.name
    }

    pub(super) fn apply(&self, tx: &Transaction<'_>) -> Result<()> {
        (self.apply)(tx)
    }
}

impl fmt::Debug for Migration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Migration").field("name", &self.name).finish_non_exhaustive()
    }
}

/// A Rust migration function executed inside a SQLite transaction.
pub type CodeMigrationFn = for<'conn> fn(&Transaction<'conn>) -> Result<()>;

#[cfg(test)]
mod tests {
    use super::*;

    use rusqlite::Connection;

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

        assert_eq!(schema::get_version(&conn)?, 2);
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

        assert_eq!(schema::get_version(&conn)?, 2);
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
        assert_eq!(schema::get_version(&conn)?, 1);
        assert!(!object_exists(&conn, "unexpected")?);
        Ok(())
    }
}
