//! Read/write transaction wrappers and the [`Row`] accessor.
//!
//! [`ReadTx`] and [`WriteTx`] are the only handles callers ever touch; the underlying
//! `rusqlite::Transaction` is private. Every query verb prepares its statement with `prepare_cached`,
//! so prepared statements are always cached. `execute` exists only on [`WriteTx`], so a function
//! that receives `&ReadTx` cannot compile a mutation.

use rusqlite::Transaction;
use rusqlite::types::Value;

use crate::DatabaseError;
use crate::sqlite::codec::{DbValueRef, FromSqlValue, ToSqlValue};

// ROW
// =================================================================================================

/// A single result row. Wraps `rusqlite::Row` so callers read columns through the codec via
/// [`Row::get`] without naming `rusqlite`.
pub struct Row<'a>(&'a rusqlite::Row<'a>);

impl<'a> Row<'a> {
    fn new(row: &'a rusqlite::Row<'a>) -> Self {
        Self(row)
    }

    /// Reads column `idx` (zero-based) decoded through [`FromSqlValue`], e.g.
    /// `row.get::<BlockHeader>(0)`.
    pub fn get<T: FromSqlValue>(&self, idx: usize) -> Result<T, DatabaseError> {
        let value = self.0.get_ref(idx)?;
        T::from_sql_value(DbValueRef::new(value))
    }
}

// TRANSACTION WRAPPERS
// =================================================================================================

/// A read-only transaction. Opened `DEFERRED` and never committed (changes roll back on drop).
pub struct ReadTx<'t>(&'t Transaction<'t>);

/// A read-write transaction. Opened `IMMEDIATE` and committed by the pool when the closure returns
/// `Ok`.
pub struct WriteTx<'t>(&'t Transaction<'t>);

impl<'t> ReadTx<'t> {
    pub(crate) fn new(tx: &'t Transaction<'t>) -> Self {
        Self(tx)
    }

    /// Runs a query and maps every row.
    pub fn query_rows<T>(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
        map: impl FnMut(&Row<'_>) -> Result<T, DatabaseError>,
    ) -> Result<Vec<T>, DatabaseError> {
        query_rows(self.0, sql, params, map)
    }

    /// Runs a query expected to return zero or one row.
    pub fn query_opt<T>(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
        map: impl FnOnce(&Row<'_>) -> Result<T, DatabaseError>,
    ) -> Result<Option<T>, DatabaseError> {
        query_opt(self.0, sql, params, map)
    }

    /// Runs a query expected to return exactly one row.
    pub fn query_one<T>(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
        map: impl FnOnce(&Row<'_>) -> Result<T, DatabaseError>,
    ) -> Result<T, DatabaseError> {
        query_one(self.0, sql, params, map)
    }

    /// Runs `SELECT EXISTS(...)` and returns the boolean result.
    pub fn exists(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
    ) -> Result<bool, DatabaseError> {
        exists(self.0, sql, params)
    }

    /// Runs a `SELECT COUNT(...)` and returns the count.
    pub fn count(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
    ) -> Result<i64, DatabaseError> {
        count(self.0, sql, params)
    }
}

impl<'t> WriteTx<'t> {
    pub(crate) fn new(tx: &'t Transaction<'t>) -> Self {
        Self(tx)
    }

    /// Executes an `INSERT`/`UPDATE`/`DELETE`/`REPLACE` and returns the affected row count.
    pub fn execute(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
    ) -> Result<usize, DatabaseError> {
        debug_assert_no_dynamic_in(sql);
        let values = to_values(params);
        let mut stmt = self.0.prepare_cached(sql)?;
        Ok(stmt.execute(rusqlite::params_from_iter(values))?)
    }

    /// Runs a query and maps every row.
    pub fn query_rows<T>(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
        map: impl FnMut(&Row<'_>) -> Result<T, DatabaseError>,
    ) -> Result<Vec<T>, DatabaseError> {
        query_rows(self.0, sql, params, map)
    }

    /// Runs a query expected to return zero or one row.
    pub fn query_opt<T>(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
        map: impl FnOnce(&Row<'_>) -> Result<T, DatabaseError>,
    ) -> Result<Option<T>, DatabaseError> {
        query_opt(self.0, sql, params, map)
    }

    /// Runs a query expected to return exactly one row.
    pub fn query_one<T>(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
        map: impl FnOnce(&Row<'_>) -> Result<T, DatabaseError>,
    ) -> Result<T, DatabaseError> {
        query_one(self.0, sql, params, map)
    }

    /// Runs `SELECT EXISTS(...)` and returns the boolean result.
    pub fn exists(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
    ) -> Result<bool, DatabaseError> {
        exists(self.0, sql, params)
    }

    /// Runs a `SELECT COUNT(...)` and returns the count.
    pub fn count(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
    ) -> Result<i64, DatabaseError> {
        count(self.0, sql, params)
    }
}

// SHARED QUERY HELPERS
// =================================================================================================

fn to_values(params: &[&dyn ToSqlValue]) -> Vec<Value> {
    params.iter().map(|param| param.to_sql_value().into_inner()).collect()
}

fn debug_assert_no_dynamic_in(sql: &str) {
    debug_assert!(
        !(sql.contains(" IN (?") || sql.contains(" IN (:")),
        "use in_list() instead of a variable-length `IN (?, ...)` placeholder list to keep the \
         statement cacheable: {sql}"
    );
}

fn query_rows<T>(
    tx: &Transaction<'_>,
    sql: &'static str,
    params: &[&dyn ToSqlValue],
    mut map: impl FnMut(&Row<'_>) -> Result<T, DatabaseError>,
) -> Result<Vec<T>, DatabaseError> {
    debug_assert_no_dynamic_in(sql);
    let values = to_values(params);
    let mut stmt = tx.prepare_cached(sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(values))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(map(&Row::new(row))?);
    }
    Ok(out)
}

fn query_opt<T>(
    tx: &Transaction<'_>,
    sql: &'static str,
    params: &[&dyn ToSqlValue],
    map: impl FnOnce(&Row<'_>) -> Result<T, DatabaseError>,
) -> Result<Option<T>, DatabaseError> {
    debug_assert_no_dynamic_in(sql);
    let values = to_values(params);
    let mut stmt = tx.prepare_cached(sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(values))?;
    match rows.next()? {
        Some(row) => Ok(Some(map(&Row::new(row))?)),
        None => Ok(None),
    }
}

fn query_one<T>(
    tx: &Transaction<'_>,
    sql: &'static str,
    params: &[&dyn ToSqlValue],
    map: impl FnOnce(&Row<'_>) -> Result<T, DatabaseError>,
) -> Result<T, DatabaseError> {
    query_opt(tx, sql, params, map)?
        .ok_or_else(|| DatabaseError::from(rusqlite::Error::QueryReturnedNoRows))
}

fn exists(
    tx: &Transaction<'_>,
    sql: &'static str,
    params: &[&dyn ToSqlValue],
) -> Result<bool, DatabaseError> {
    query_one(tx, sql, params, |row| row.get::<i64>(0)).map(|value| value != 0)
}

fn count(
    tx: &Transaction<'_>,
    sql: &'static str,
    params: &[&dyn ToSqlValue],
) -> Result<i64, DatabaseError> {
    query_one(tx, sql, params, |row| row.get::<i64>(0))
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::sqlite::{in_list_hex, in_list_i64};

    fn in_memory() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, payload BLOB, label TEXT);",
        )
        .expect("create table");
        conn
    }

    #[test]
    fn write_then_read_roundtrips_through_the_codec() {
        let mut conn = in_memory();
        let tx = conn.transaction().unwrap();
        let w = WriteTx::new(&tx);

        let payload = vec![1u8, 2, 3];
        let inserted = w
            .execute(
                "INSERT INTO items (id, payload, label) VALUES (?1, ?2, ?3)",
                &[&1i64, &payload, &"hello".to_string()],
            )
            .unwrap();
        assert_eq!(inserted, 1);

        let got: (i64, Vec<u8>, String) = w
            .query_one("SELECT id, payload, label FROM items WHERE id = ?1", &[&1i64], |row| {
                Ok((row.get::<i64>(0)?, row.get::<Vec<u8>>(1)?, row.get::<String>(2)?))
            })
            .unwrap();
        assert_eq!(got, (1, vec![1, 2, 3], "hello".to_string()));
    }

    #[test]
    fn null_column_reads_as_none() {
        let mut conn = in_memory();
        let tx = conn.transaction().unwrap();
        let w = WriteTx::new(&tx);

        w.execute("INSERT INTO items (id, payload) VALUES (?1, NULL)", &[&1i64])
            .unwrap();
        let payload: Option<Vec<u8>> = w
            .query_one("SELECT payload FROM items WHERE id = ?1", &[&1i64], |row| {
                row.get::<Option<Vec<u8>>>(0)
            })
            .unwrap();
        assert_eq!(payload, None);
    }

    #[test]
    fn query_opt_returns_none_for_missing_row() {
        let mut conn = in_memory();
        let tx = conn.transaction().unwrap();
        let r = ReadTx::new(&tx);

        let got = r
            .query_opt("SELECT id FROM items WHERE id = ?1", &[&404i64], |row| row.get::<i64>(0))
            .unwrap();
        assert_eq!(got, None);
    }

    // Regression guard for the cacheable IN-list idiom: the json_each form must run through the
    // verbs without tripping `debug_assert_no_dynamic_in` (tests run with debug assertions on).
    #[test]
    fn in_list_i64_json_each_runs_and_matches() {
        let mut conn = in_memory();
        let tx = conn.transaction().unwrap();
        let w = WriteTx::new(&tx);
        for id in [1i64, 2, 3, 4] {
            w.execute("INSERT INTO items (id) VALUES (?1)", &[&id]).unwrap();
        }

        let wanted = in_list_i64([1, 3]);
        let mut ids = w
            .query_rows(
                "SELECT id FROM items WHERE id IN (SELECT value FROM json_each(?1))",
                &[&wanted],
                |row| row.get::<i64>(0),
            )
            .unwrap();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 3]);
    }

    #[test]
    fn in_list_hex_matches_blob_column() {
        let mut conn = in_memory();
        let tx = conn.transaction().unwrap();
        let w = WriteTx::new(&tx);
        let a = vec![0xAAu8, 0xBB];
        let b = vec![0x01u8];
        w.execute("INSERT INTO items (id, payload) VALUES (1, ?1)", &[&a]).unwrap();
        w.execute("INSERT INTO items (id, payload) VALUES (2, ?1)", &[&b]).unwrap();

        let wanted = in_list_hex([a.as_slice()]);
        let ids = w
            .query_rows(
                "SELECT id FROM items WHERE hex(payload) IN (SELECT value FROM json_each(?1))",
                &[&wanted],
                |row| row.get::<i64>(0),
            )
            .unwrap();
        assert_eq!(ids, vec![1]);
    }
}
