//! Variable-length `IN (...)` lists that keep the SQL text constant.
//!
//! Binding a list as `IN (?, ?, ...)` produces a different SQL string per list length, so SQLite
//! cannot cache the prepared statement. Instead, bind the list as a single array parameter via
//! rusqlite's [`array`](https://docs.rs/rusqlite/latest/rusqlite/vtab/array/index.html) extension
//! and expand it with `rarray`, keeping the SQL text constant and the comparison on the raw column
//! (so an index on the column can be used):
//!
//! ```sql
//! ... WHERE col IN (SELECT value FROM rarray(?1))
//! ```
//!
//! The same idiom works for both integer and BLOB keys: the values are bound natively, so there is
//! no per-row `hex()`/`unhex()` conversion and no JSON serialization.

use rusqlite::types::Value;

use crate::sqlite::codec::{DbValue, ToSqlValue};

/// A list bound as an array parameter for use with `rarray`.
#[derive(Debug, Clone, PartialEq)]
pub struct InList(Vec<Value>);

impl ToSqlValue for InList {
    fn to_sql_value(&self) -> DbValue {
        DbValue::array(self.0.clone())
    }
}

/// Builds an integer-keyed `IN` list. Pair with `... IN (SELECT value FROM rarray(?))`.
pub fn in_list_i64(items: impl IntoIterator<Item = i64>) -> InList {
    InList(items.into_iter().map(Value::Integer).collect())
}

/// Builds a BLOB-keyed `IN` list. Pair with `... IN (SELECT value FROM rarray(?))`; the column is
/// compared directly against the bound blobs, with no hex conversion.
pub fn in_list_blob<'a>(items: impl IntoIterator<Item = &'a [u8]>) -> InList {
    InList(items.into_iter().map(|bytes| Value::Blob(bytes.to_vec())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_list_i64_collects_integer_values() {
        // Different list lengths produce the same SQL template (`rarray(?1)`); only the bound
        // parameter contents differ.
        assert_eq!(in_list_i64([1]).0, vec![Value::Integer(1)]);
        assert_eq!(
            in_list_i64([1, 2, 3]).0,
            vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)]
        );
        assert_eq!(in_list_i64(std::iter::empty()).0, Vec::<Value>::new());
    }

    #[test]
    fn in_list_blob_collects_blob_values() {
        assert_eq!(in_list_blob([[0x0a, 0xff].as_slice()]).0, vec![Value::Blob(vec![0x0a, 0xff])]);
        assert_eq!(
            in_list_blob([[0x01].as_slice(), [0x02].as_slice()]).0,
            vec![Value::Blob(vec![0x01]), Value::Blob(vec![0x02])]
        );
    }
}
