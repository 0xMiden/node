//! Read/write transaction wrappers and the [`Row`] accessor.
//!
//! [`ReadTx`] and [`WriteTx`] are the only handles callers ever touch; the underlying
//! `rusqlite::Connection` is private. They borrow a connection on which a transaction has already
//! been opened (by the pool's `read`/`write` or by a held transaction handle) — they do not begin
//! or end the transaction themselves.
//!
//! A write transaction is a read transaction with the extra ability to mutate: [`WriteTx`] wraps a
//! [`ReadTx`] and derefs to it, so it inherits [`query`](ReadTx::query) and only adds
//! [`execute`](WriteTx::execute). A function that receives `&ReadTx` therefore cannot compile a
//! mutation. Both prepare statements with `prepare_cached`, so prepared statements are always
//! cached.

use std::ops::Deref;

use rusqlite::Connection;

use crate::DatabaseError;
use crate::sqlite::codec::{DbValue, DbValueRef, FromSqlValue, ToSqlValue};

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

/// A read-only transaction. Borrows a connection on which a `DEFERRED` transaction is open; the
/// transaction is never committed (changes roll back when it ends).
pub struct ReadTx<'t>(&'t Connection);

impl<'t> ReadTx<'t> {
    pub(crate) fn new(conn: &'t Connection) -> Self {
        Self(conn)
    }

    /// Runs a query and maps every row, collecting the results.
    ///
    /// This is the single read primitive: a caller expecting at most one row takes
    /// `.into_iter().next()`, and `SELECT EXISTS(...)` / `SELECT COUNT(*)` map the single row's
    /// first column.
    pub fn query<T>(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
        mut map: impl FnMut(&Row<'_>) -> Result<T, DatabaseError>,
    ) -> Result<Vec<T>, DatabaseError> {
        debug_assert_no_dynamic_in(sql);
        let values = to_values(params);
        let mut stmt = self.0.prepare_cached(sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(values))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(map(&Row::new(row))?);
        }
        Ok(out)
    }
}

/// A read-write transaction. Borrows a connection on which an `IMMEDIATE` transaction is open; the
/// transaction is committed by the owner when the work returns `Ok`. Derefs to [`ReadTx`] for all
/// read queries and adds [`execute`](Self::execute).
pub struct WriteTx<'t>(ReadTx<'t>);

impl<'t> WriteTx<'t> {
    pub(crate) fn new(conn: &'t Connection) -> Self {
        Self(ReadTx::new(conn))
    }

    /// Executes an `INSERT`/`UPDATE`/`DELETE`/`REPLACE` and returns the affected row count.
    pub fn execute(
        &self,
        sql: &'static str,
        params: &[&dyn ToSqlValue],
    ) -> Result<usize, DatabaseError> {
        debug_assert_no_dynamic_in(sql);
        let values = to_values(params);
        let mut stmt = self.0.0.prepare_cached(sql)?;
        Ok(stmt.execute(rusqlite::params_from_iter(values))?)
    }
}

impl<'t> Deref for WriteTx<'t> {
    type Target = ReadTx<'t>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// SHARED HELPERS
// =================================================================================================

fn to_values(params: &[&dyn ToSqlValue]) -> Vec<DbValue> {
    params.iter().map(ToSqlValue::to_sql_value).collect()
}

fn debug_assert_no_dynamic_in(sql: &str) {
    debug_assert!(
        !(sql.contains(" IN (?") || sql.contains(" IN (:")),
        "use in_list() instead of a variable-length `IN (?, ...)` placeholder list to keep the \
         statement cacheable: {sql}"
    );
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::sqlite::{in_list_blob, in_list_i64};

    fn in_memory() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        // `rarray()` is provided by rusqlite's `array` extension, which must be loaded per
        // connection (the pool does this in `configure_connection`).
        rusqlite::vtab::array::load_module(&conn).expect("load array module");
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
            .query("SELECT id, payload, label FROM items WHERE id = ?1", &[&1i64], |row| {
                Ok((row.get::<i64>(0)?, row.get::<Vec<u8>>(1)?, row.get::<String>(2)?))
            })
            .unwrap()
            .into_iter()
            .next()
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
            .query("SELECT payload FROM items WHERE id = ?1", &[&1i64], |row| {
                row.get::<Option<Vec<u8>>>(0)
            })
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(payload, None);
    }

    #[test]
    fn query_returns_empty_for_missing_row() {
        let mut conn = in_memory();
        let tx = conn.transaction().unwrap();
        let r = ReadTx::new(&tx);

        let got = r
            .query("SELECT id FROM items WHERE id = ?1", &[&404i64], |row| row.get::<i64>(0))
            .unwrap();
        assert!(got.is_empty());
    }

    // Regression guard for the cacheable IN-list idiom: the rarray form must run through `query`
    // without tripping `debug_assert_no_dynamic_in` (tests run with debug assertions on).
    #[test]
    fn in_list_i64_rarray_runs_and_matches() {
        let mut conn = in_memory();
        let tx = conn.transaction().unwrap();
        let w = WriteTx::new(&tx);
        for id in [1i64, 2, 3, 4] {
            w.execute("INSERT INTO items (id) VALUES (?1)", &[&id]).unwrap();
        }

        let wanted = in_list_i64([1, 3]);
        let mut ids = w
            .query(
                "SELECT id FROM items WHERE id IN (SELECT value FROM rarray(?1))",
                &[&wanted],
                |row| row.get::<i64>(0),
            )
            .unwrap();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 3]);
    }

    #[test]
    fn in_list_blob_matches_blob_column() {
        let mut conn = in_memory();
        let tx = conn.transaction().unwrap();
        let w = WriteTx::new(&tx);
        let a = vec![0xAAu8, 0xBB];
        let b = vec![0x01u8];
        w.execute("INSERT INTO items (id, payload) VALUES (1, ?1)", &[&a]).unwrap();
        w.execute("INSERT INTO items (id, payload) VALUES (2, ?1)", &[&b]).unwrap();

        let wanted = in_list_blob([a.as_slice()]);
        let ids = w
            .query(
                "SELECT id FROM items WHERE payload IN (SELECT value FROM rarray(?1))",
                &[&wanted],
                |row| row.get::<i64>(0),
            )
            .unwrap();
        assert_eq!(ids, vec![1]);
    }
}
