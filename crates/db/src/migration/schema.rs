use std::fmt;

use anyhow::{Context, Result, ensure};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// A schema fingerprint computed from ordered entries in `sqlite_schema`.
///
/// The hash includes each non-internal schema object's type, name, table name, and normalized SQL.
/// Normalization trims trailing semicolons and collapses whitespace, then entries are ordered by
/// object type, name, and table name before hashing. This makes the hash stable across object
/// creation order while still detecting changes to tables, indexes, views, triggers, constraints,
/// and object names.
///
/// This is a drift-detection fingerprint, not a semantic SQLite schema model. It does not parse SQL
/// or understand equivalent SQL forms. For example, two semantically equivalent declarations can
/// hash differently if SQLite stores their SQL text differently, while behavior not represented in
/// `sqlite_schema.sql` is outside the hash. SQLite-internal objects whose names start with
/// `sqlite_` are intentionally ignored.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SchemaHash([u8; 32]);

impl SchemaHash {
    /// Parses a schema hash from its hex representation.
    ///
    /// Expects exactly 64 hex characters and panics otherwise.
    pub const fn from_hex(hex: &str) -> Self {
        assert!(hex.len() == 64, "schema hash must be 64 hex characters");

        let mut hash = [0_u8; 32];
        let bytes = hex.as_bytes();
        let mut idx = 0;
        while idx < 32 {
            let high = hex_digit(bytes[idx * 2]);
            let low = hex_digit(bytes[idx * 2 + 1]);
            hash[idx] = (high << 4) | low;
            idx += 1;
        }

        Self(hash)
    }

    /// Computes the hash for the database schema.
    ///
    /// See [`SchemaHash`] for what is included and the limits of this fingerprint.
    pub fn new(conn: &Connection) -> Result<Self> {
        let mut stmt = conn
            .prepare(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema \
                 WHERE sql IS NOT NULL \
                 AND name NOT LIKE 'sqlite_%' \
                 ORDER BY type, name, tbl_name",
            )
            .context("failed to prepare sqlite_schema query")?;

        let rows = stmt
            .query_map([], |row| {
                Ok(SchemaEntry {
                    object_type: row.get(0)?,
                    name: row.get(1)?,
                    table_name: row.get(2)?,
                    sql: normalize_sql(&row.get::<_, String>(3)?),
                })
            })
            .context("failed to query sqlite_schema rows")?;

        let schema_entries = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to read sqlite_schema rows")?;

        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "schema-hash-v1");
        for entry in schema_entries {
            hash_field(&mut hasher, &entry.object_type);
            hash_field(&mut hasher, &entry.name);
            hash_field(&mut hasher, &entry.table_name);
            hash_field(&mut hasher, &entry.sql);
        }

        let digest = hasher.finalize();
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        Ok(Self(hash))
    }
}

struct SchemaEntry {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

impl fmt::Display for SchemaHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn normalize_sql(sql: &str) -> String {
    sql.trim_end()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn hash_field(hasher: &mut Sha256, field: &str) {
    hasher.update(field.len().to_le_bytes());
    hasher.update(field.as_bytes());
}

const fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid schema hash hex digit"),
    }
}

pub fn get_version(conn: &Connection) -> Result<usize> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    ensure!(version >= 0, "database user_version is negative: {version}");
    usize::try_from(version).context("database user_version does not fit into usize")
}

pub fn set_version(conn: &Connection, version: usize) -> Result<()> {
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

    #[test]
    fn schema_hash_round_trips_as_hex() {
        const HASH: SchemaHash = SchemaHash::from_hex(
            "abababababababababababababababababababababababababababababababab",
        );

        assert_eq!(HASH.to_string(), "ab".repeat(32));
    }

    #[test]
    fn schema_hash_is_stable_across_creation_order() -> Result<()> {
        let left = Connection::open_in_memory()?;
        left.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);
             CREATE TABLE notes (id INTEGER PRIMARY KEY, item_id INTEGER);
             CREATE INDEX idx_notes_item_id ON notes(item_id);",
        )?;

        let right = Connection::open_in_memory()?;
        right.execute_batch(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, item_id INTEGER);
             CREATE INDEX idx_notes_item_id ON notes(item_id);
             CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);",
        )?;

        assert_eq!(SchemaHash::new(&left)?, SchemaHash::new(&right)?);
        Ok(())
    }

    #[test]
    fn schema_hash_changes_for_object_identity() -> Result<()> {
        let left = Connection::open_in_memory()?;
        left.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);")?;

        let right = Connection::open_in_memory()?;
        right.execute_batch("CREATE TABLE entries (id INTEGER PRIMARY KEY, value TEXT);")?;

        assert_ne!(SchemaHash::new(&left)?, SchemaHash::new(&right)?);
        Ok(())
    }

    #[test]
    fn schema_hash_changes_for_views_triggers_indexes_and_constraints() -> Result<()> {
        let base = Connection::open_in_memory()?;
        base.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, value INTEGER);")?;
        let base_hash = SchemaHash::new(&base)?;

        let with_index = Connection::open_in_memory()?;
        with_index.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, value INTEGER);
             CREATE INDEX idx_items_value ON items(value);",
        )?;
        assert_ne!(base_hash, SchemaHash::new(&with_index)?);

        let with_view = Connection::open_in_memory()?;
        with_view.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, value INTEGER);
             CREATE VIEW item_values AS SELECT value FROM items;",
        )?;
        assert_ne!(base_hash, SchemaHash::new(&with_view)?);

        let with_trigger = Connection::open_in_memory()?;
        with_trigger.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, value INTEGER);
             CREATE TRIGGER items_positive_value
             BEFORE INSERT ON items
             WHEN NEW.value < 0
             BEGIN
                 SELECT RAISE(ABORT, 'negative value');
             END;",
        )?;
        assert_ne!(base_hash, SchemaHash::new(&with_trigger)?);

        let with_constraints = Connection::open_in_memory()?;
        with_constraints.execute_batch(
            "CREATE TABLE items (
                 id INTEGER PRIMARY KEY,
                 value INTEGER UNIQUE CHECK (value > 0)
             );",
        )?;
        assert_ne!(base_hash, SchemaHash::new(&with_constraints)?);

        Ok(())
    }
}
