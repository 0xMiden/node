use std::fmt;

use anyhow::{Context, Result, ensure};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// A schema hash computed from normalized SQL entries in `sqlite_master`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SchemaHash([u8; 32]);

impl SchemaHash {
    /// Computes the schema hash for `conn`.
    pub fn new(conn: &Connection) -> Result<Self> {
        let mut stmt = conn
            .prepare(
                "SELECT sql FROM sqlite_master \
                 WHERE sql IS NOT NULL \
                 AND name NOT LIKE 'sqlite_%'",
            )
            .context("failed to prepare sqlite_master schema query")?;

        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .context("failed to query sqlite_master schema rows")?;

        let mut normalized_sql = rows
            .map(|row| row.map(|sql| normalize_sql(&sql)))
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to read sqlite_master schema rows")?;
        normalized_sql.sort_unstable();

        let mut hasher = Sha256::new();
        for sql in normalized_sql {
            hasher.update(sql.as_bytes());
            hasher.update(b"\0");
        }

        let digest = hasher.finalize();
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        Ok(Self(hash))
    }

    /// Returns the raw hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
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
