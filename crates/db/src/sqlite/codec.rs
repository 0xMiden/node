//! Column codec for the rusqlite-based SQLite framework.
//!
//! [`ToSqlValue`] and [`FromSqlValue`] are the per-column write/read codec for our domain types.
//! They operate on [`DbValue`]/[`DbValueRef`], thin wrappers over rusqlite's value types, so that
//! crates implementing a codec for their own types never have to name `rusqlite` directly.
//!
//! Most node types are stored as a BLOB via their `Serializable`/`Deserializable` impls; the
//! [`impl_blob_codec!`](crate::impl_blob_codec) macro generates both traits for such a type. Scalar
//! types map onto an SQLite `INTEGER`/`TEXT` and implement the traits directly (see the impls ported
//! from the legacy `SqlTypeConvert` below).

use std::rc::Rc;

use rusqlite::ToSql;
use rusqlite::types::{ToSqlOutput, Value, ValueRef};

use crate::DatabaseError;

// DB VALUE WRAPPERS
// =================================================================================================

/// An owned SQL value produced when binding a Rust value as a query parameter.
///
/// Wraps `rusqlite`'s value types so codec implementors never name `rusqlite`. A value is either a
/// single column value or a list bound for a `rarray(?)` table-valued parameter (used by the
/// cacheable IN-list helpers in [`in_list`](crate::sqlite::in_list)).
#[derive(Debug, Clone)]
pub enum DbValue {
    /// A single SQL column value.
    Single(Value),
    /// A list of values bound via rusqlite's `array` extension for use with `rarray(?)`.
    Array(Rc<Vec<Value>>),
}

impl DbValue {
    /// Builds an `INTEGER` value.
    pub fn integer(value: i64) -> Self {
        Self::Single(Value::Integer(value))
    }

    /// Builds a `REAL` value.
    pub fn real(value: f64) -> Self {
        Self::Single(Value::Real(value))
    }

    /// Builds a `TEXT` value.
    pub fn text(value: String) -> Self {
        Self::Single(Value::Text(value))
    }

    /// Builds a `BLOB` value.
    pub fn blob(value: Vec<u8>) -> Self {
        Self::Single(Value::Blob(value))
    }

    /// Builds a `NULL` value.
    pub fn null() -> Self {
        Self::Single(Value::Null)
    }

    /// Builds a list value bound for a `rarray(?)` table-valued parameter.
    pub(crate) fn array(values: Vec<Value>) -> Self {
        Self::Array(Rc::new(values))
    }
}

impl ToSql for DbValue {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self {
            Self::Single(value) => value.to_sql(),
            Self::Array(values) => values.to_sql(),
        }
    }
}

/// A borrowed SQL value handed to [`FromSqlValue`] when reading a column.
///
/// Wraps `rusqlite::types::ValueRef` so codec implementors never name `rusqlite`.
#[derive(Debug, Clone, Copy)]
pub struct DbValueRef<'a>(ValueRef<'a>);

impl<'a> DbValueRef<'a> {
    pub(crate) fn new(value: ValueRef<'a>) -> Self {
        Self(value)
    }

    /// Reads the value as an `i64`.
    pub fn as_i64(self) -> Result<i64, DatabaseError> {
        self.0.as_i64().map_err(|err| DatabaseError::deserialization("i64", err))
    }

    /// Reads the value as a borrowed BLOB.
    pub fn as_blob(self) -> Result<&'a [u8], DatabaseError> {
        self.0.as_blob().map_err(|err| DatabaseError::deserialization("blob", err))
    }

    /// Reads the value as a borrowed string.
    pub fn as_str(self) -> Result<&'a str, DatabaseError> {
        self.0.as_str().map_err(|err| DatabaseError::deserialization("str", err))
    }

    /// Returns `true` if the value is SQL `NULL`.
    pub fn is_null(self) -> bool {
        matches!(self.0, ValueRef::Null)
    }
}

// CODEC TRAITS
// =================================================================================================

/// Converts a Rust value into its SQL parameter representation (the write side of the codec).
pub trait ToSqlValue {
    /// Returns the SQL value bound for this Rust value.
    fn to_sql_value(&self) -> DbValue;
}

/// Builds a Rust value from a SQL column value (the read side of the codec).
pub trait FromSqlValue: Sized {
    /// Reads `Self` from a SQL column value.
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError>;
}

// Forward `ToSqlValue` through references so callers can pass `&value` in a parameter slice.
impl<T: ToSqlValue + ?Sized> ToSqlValue for &T {
    fn to_sql_value(&self) -> DbValue {
        (**self).to_sql_value()
    }
}

// PRIMITIVE IMPLS
// =================================================================================================

impl ToSqlValue for i64 {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(*self)
    }
}

impl FromSqlValue for i64 {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        value.as_i64()
    }
}

impl ToSqlValue for bool {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(i64::from(*self))
    }
}

impl FromSqlValue for bool {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        Ok(value.as_i64()? != 0)
    }
}

impl ToSqlValue for Vec<u8> {
    fn to_sql_value(&self) -> DbValue {
        DbValue::blob(self.clone())
    }
}

impl FromSqlValue for Vec<u8> {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        Ok(value.as_blob()?.to_vec())
    }
}

impl ToSqlValue for str {
    fn to_sql_value(&self) -> DbValue {
        DbValue::text(self.to_owned())
    }
}

impl ToSqlValue for String {
    fn to_sql_value(&self) -> DbValue {
        DbValue::text(self.clone())
    }
}

impl FromSqlValue for String {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        Ok(value.as_str()?.to_owned())
    }
}

impl<T: ToSqlValue> ToSqlValue for Option<T> {
    fn to_sql_value(&self) -> DbValue {
        match self {
            Some(value) => value.to_sql_value(),
            None => DbValue::null(),
        }
    }
}

impl<T: FromSqlValue> FromSqlValue for Option<T> {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        if value.is_null() {
            Ok(None)
        } else {
            Ok(Some(T::from_sql_value(value)?))
        }
    }
}

// BLOB CODEC MACRO
// =================================================================================================

/// Generates [`ToSqlValue`](crate::sqlite::ToSqlValue) and
/// [`FromSqlValue`](crate::sqlite::FromSqlValue) for types stored as a BLOB via their
/// `Serializable`/`Deserializable` impls.
///
/// The generated impls call the exact same `to_bytes()`/`read_from_bytes()` used elsewhere, so the
/// on-disk byte layout is unchanged.
#[macro_export]
macro_rules! impl_blob_codec {
    ($($t:ty),+ $(,)?) => {
        $(
            impl $crate::sqlite::ToSqlValue for $t {
                fn to_sql_value(&self) -> $crate::sqlite::DbValue {
                    $crate::sqlite::DbValue::blob(
                        ::miden_protocol::utils::serde::Serializable::to_bytes(self),
                    )
                }
            }

            impl $crate::sqlite::FromSqlValue for $t {
                fn from_sql_value(
                    value: $crate::sqlite::DbValueRef<'_>,
                ) -> ::core::result::Result<Self, $crate::DatabaseError> {
                    let bytes = value.as_blob()?;
                    <$t as ::miden_protocol::utils::serde::Deserializable>::read_from_bytes(bytes)
                        .map_err(|err| {
                            $crate::DatabaseError::deserialization(::core::stringify!($t), err)
                        })
                }
            }
        )+
    };
}

// Codec for the common protocol types stored as BLOBs. Shared by all node crates so that the orphan
// rule does not force each consumer to redeclare them.
impl_blob_codec!(
    miden_protocol::block::BlockHeader,
    miden_protocol::account::AccountId,
    miden_protocol::transaction::TransactionId,
    miden_protocol::note::Nullifier,
    miden_protocol::Word,
);
