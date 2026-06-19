//! Variable-length `IN (...)` lists that keep the SQL text constant.
//!
//! Binding a list as `IN (?, ?, ...)` produces a different SQL string per list length, so SQLite
//! cannot cache the prepared statement. Instead, serialize the list into a single JSON-array text
//! parameter and expand it with `json_each`, keeping the SQL text constant:
//!
//! - integer keys: `... WHERE col IN (SELECT value FROM json_each(?1))`
//! - BLOB keys:    `... WHERE hex(col) IN (SELECT value FROM json_each(?1))`
//!
//! `json_each` yields TEXT, so BLOB key columns must be compared as uppercase hex (see
//! [`in_list_hex`]); [`hex()`](https://sqlite.org/lang_corefunc.html#hex) produces uppercase too.

use std::fmt::Write;

use crate::sqlite::codec::{DbValue, ToSqlValue};

/// A list serialized as a JSON-array text parameter for use with `json_each`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InList(String);

impl InList {
    /// The JSON array text, e.g. `[1,2,3]`.
    pub fn as_json(&self) -> &str {
        &self.0
    }
}

impl ToSqlValue for InList {
    fn to_sql_value(&self) -> DbValue {
        DbValue::text(self.0.clone())
    }
}

/// Builds a JSON array of integers for an integer-keyed `IN` list.
pub fn in_list_i64(items: impl IntoIterator<Item = i64>) -> InList {
    let mut json = String::from("[");
    for (i, value) in items.into_iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        // `i64` always renders as valid JSON, so writing to a String cannot fail.
        let _ = write!(json, "{value}");
    }
    json.push(']');
    InList(json)
}

/// Builds a JSON array of uppercase hex strings for a BLOB-keyed `IN` list. Pair with `hex(col)` in
/// the query so the TEXT values from `json_each` compare against the column.
pub fn in_list_hex<'a>(items: impl IntoIterator<Item = &'a [u8]>) -> InList {
    let mut json = String::from("[");
    for (i, bytes) in items.into_iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('"');
        for byte in bytes {
            // Hex of a byte is always valid JSON string content, so this cannot fail.
            let _ = write!(json, "{byte:02X}");
        }
        json.push('"');
    }
    json.push(']');
    InList(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_list_i64_renders_constant_shape() {
        // Different list lengths produce the same SQL template (`json_each(?1)`); only the bound
        // parameter text differs.
        assert_eq!(in_list_i64([1]).as_json(), "[1]");
        assert_eq!(in_list_i64([1, 2, 3]).as_json(), "[1,2,3]");
        assert_eq!(in_list_i64(std::iter::empty()).as_json(), "[]");
    }

    #[test]
    fn in_list_hex_uppercases_bytes() {
        assert_eq!(in_list_hex([[0x0a, 0xff].as_slice()]).as_json(), r#"["0AFF"]"#);
        assert_eq!(in_list_hex([[0x01].as_slice(), [0x02].as_slice()]).as_json(), r#"["01","02"]"#);
    }
}
