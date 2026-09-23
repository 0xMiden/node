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

impl InList {
    /// Builds an integer-keyed `IN` list. Pair with `... IN (SELECT value FROM rarray(?))`.
    pub fn from_i64s(items: impl IntoIterator<Item = i64>) -> Self {
        Self(items.into_iter().map(Value::Integer).collect())
    }

    /// Builds a BLOB-keyed `IN` list. Pair with `... IN (SELECT value FROM rarray(?))`; the column
    /// is compared directly against the bound blobs, with no hex conversion.
    pub fn from_blobs<'a>(items: impl IntoIterator<Item = &'a [u8]>) -> Self {
        Self(items.into_iter().map(|bytes| Value::Blob(bytes.to_vec())).collect())
    }

    /// Builds an `IN` list from typed keys, binding each through its column codec. Pair with
    /// `... IN (SELECT value FROM rarray(?))`.
    ///
    /// Prefer this over [`Self::from_i64s`] and [`Self::from_blobs`] whenever the keys are typed.
    /// Going through [`ToSqlValue`] binds exactly what the column stores - a BLOB for the types
    /// carrying a blob codec, an `INTEGER` for the scalar ones - so the list cannot disagree with
    /// the column it is compared against. Serializing every key to bytes instead would bind blobs
    /// against an `INTEGER` column and silently match nothing.
    ///
    /// The codec also produces the bound value directly, so the caller does not have to
    /// materialize a `Vec<Vec<u8>>` to keep borrowed slices alive across the query. A blanket impl
    /// covers references, so a `&[T]` slice of keys can be passed as-is.
    pub fn from_values<T: ToSqlValue>(items: impl IntoIterator<Item = T>) -> Self {
        let mut values = Vec::new();
        for item in items {
            match item.to_sql_value() {
                DbValue::Single(value) => values.push(value),
                // Only an `InList` binds an array value. SQLite has no nested arrays, so splicing
                // is the only reading `rarray` can express.
                DbValue::Array(nested) => values.extend(nested.iter().cloned()),
            }
        }
        Self(values)
    }
}

impl ToSqlValue for InList {
    fn to_sql_value(&self) -> DbValue {
        DbValue::array(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_list_i64_collects_integer_values() {
        // Different list lengths produce the same SQL template (`rarray(?1)`); only the bound
        // parameter contents differ.
        assert_eq!(InList::from_i64s([1]).0, vec![Value::Integer(1)]);
        assert_eq!(
            InList::from_i64s([1, 2, 3]).0,
            vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)]
        );
        assert_eq!(InList::from_i64s(std::iter::empty()).0, Vec::<Value>::new());
    }

    #[test]
    fn in_list_values_bind_each_key_through_its_codec() {
        use miden_protocol::Word;
        use miden_protocol::block::BlockNumber;
        use miden_protocol::utils::serde::Serializable;

        // A blob-backed key binds a BLOB holding exactly what the column stores.
        let word = Word::from([1_u32, 2, 3, 4]);
        assert_eq!(InList::from_values([word]).0, vec![Value::Blob(word.to_bytes())]);

        // A key whose codec maps onto an `INTEGER` column binds an integer, not its serialization.
        assert_eq!(InList::from_values([BlockNumber::from(7_u32)]).0, vec![Value::Integer(7)]);

        assert_eq!(InList::from_values(std::iter::empty::<u32>()).0, Vec::<Value>::new());
    }

    #[test]
    fn in_list_blob_collects_blob_values() {
        assert_eq!(
            InList::from_blobs([[0x0a, 0xff].as_slice()]).0,
            vec![Value::Blob(vec![0x0a, 0xff])]
        );
        assert_eq!(
            InList::from_blobs([[0x01].as_slice(), [0x02].as_slice()]).0,
            vec![Value::Blob(vec![0x01]), Value::Blob(vec![0x02])]
        );
    }
}
