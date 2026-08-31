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
//!
//! Integer primitives read back range-checked rather than cast, so a column holding a value outside
//! the target type's range errors instead of silently truncating. The one place a lossy conversion
//! is deliberate is `Felt`.

use std::rc::Rc;

use miden_protocol::Felt;
use miden_protocol::account::StorageSlotName;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteTag;
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

// The unsigned integers widen losslessly on the write side and are range-checked on the read side,
// so a column holding a value outside the type's range errors instead of silently truncating.

impl ToSqlValue for u8 {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(i64::from(*self))
    }
}

impl FromSqlValue for u8 {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        Self::try_from(value.as_i64()?).map_err(|err| DatabaseError::deserialization("u8", err))
    }
}

impl ToSqlValue for u16 {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(i64::from(*self))
    }
}

impl FromSqlValue for u16 {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        Self::try_from(value.as_i64()?).map_err(|err| DatabaseError::deserialization("u16", err))
    }
}

impl ToSqlValue for u32 {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(i64::from(*self))
    }
}

impl FromSqlValue for u32 {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        Self::try_from(value.as_i64()?).map_err(|err| DatabaseError::deserialization("u32", err))
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

// DOMAIN SCALAR IMPLS
// =================================================================================================
//
// Domain types stored in an `INTEGER`/`TEXT` column rather than as a BLOB.

impl ToSqlValue for BlockNumber {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(i64::from(self.as_u32()))
    }
}

impl FromSqlValue for BlockNumber {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        u32::from_sql_value(value).map(BlockNumber::from)
    }
}

impl ToSqlValue for NoteTag {
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(i64::from(self.as_u32()))
    }
}

impl FromSqlValue for NoteTag {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        u32::from_sql_value(value).map(NoteTag::new)
    }
}

impl ToSqlValue for StorageSlotName {
    fn to_sql_value(&self) -> DbValue {
        DbValue::text(self.as_str().to_owned())
    }
}

impl FromSqlValue for StorageSlotName {
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        StorageSlotName::new(value.as_str()?)
            .map_err(|err| DatabaseError::deserialization("StorageSlotName", err))
    }
}

/// A field element is stored as the bit reinterpretation of its canonical `u64`.
impl ToSqlValue for Felt {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "canonical field elements are stored as the wrapped i64 bit pattern"
    )]
    fn to_sql_value(&self) -> DbValue {
        DbValue::integer(self.as_canonical_u64() as i64)
    }
}

impl FromSqlValue for Felt {
    #[expect(clippy::cast_sign_loss, reason = "reverses the u64 -> i64 wrap applied on write")]
    fn from_sql_value(value: DbValueRef<'_>) -> Result<Self, DatabaseError> {
        Felt::new(value.as_i64()? as u64).map_err(|err| DatabaseError::deserialization("Felt", err))
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
    miden_protocol::block::BlockSignatures,
    miden_protocol::account::Account,
    miden_protocol::account::AccountCode,
    miden_protocol::account::AccountId,
    miden_protocol::account::AccountStorageHeader,
    miden_protocol::account::StorageMapKey,
    miden_protocol::asset::Asset,
    miden_protocol::transaction::TransactionId,
    miden_protocol::note::Note,
    miden_protocol::note::NoteAssets,
    miden_protocol::note::NoteAttachments,
    miden_protocol::note::NoteId,
    miden_protocol::note::NoteScript,
    miden_protocol::note::NoteStorage,
    miden_protocol::note::Nullifier,
    miden_protocol::crypto::merkle::SparseMerklePath,
    miden_protocol::crypto::merkle::mmr::PartialMmr,
    miden_protocol::Word,
);

// TESTS
// =================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::block::BlockNumber;
    use rusqlite::types::{Value, ValueRef};

    use super::*;
    use crate::SqlTypeConvert;

    /// Returns the `i64` a value binds to, failing the test for non-integer values.
    fn bound_integer(value: &impl ToSqlValue) -> i64 {
        match value.to_sql_value() {
            DbValue::Single(Value::Integer(raw)) => raw,
            other => panic!("expected an INTEGER binding, got {other:?}"),
        }
    }

    /// Reads a value back from the `i64` a column holds.
    fn read_integer<T: FromSqlValue>(raw: i64) -> Result<T, DatabaseError> {
        T::from_sql_value(DbValueRef::new(ValueRef::Integer(raw)))
    }

    // ENCODING PARITY WITH `SqlTypeConvert`
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn block_number_roundtrip() {
        for block_num in [
            BlockNumber::GENESIS,
            BlockNumber::from(1),
            BlockNumber::from(u32::MAX - 1),
            BlockNumber::from(u32::MAX),
        ] {
            let raw = bound_integer(&block_num);
            assert_eq!(raw, block_num.to_raw_sql(), "write side diverged for {block_num}");
            assert_eq!(
                read_integer::<BlockNumber>(raw).unwrap(),
                BlockNumber::from_raw_sql(raw).unwrap(),
                "read side diverged for {block_num}",
            );
        }
    }

    #[test]
    fn note_tag_roundtrip() {
        for tag in [
            NoteTag::new(0),
            NoteTag::new(1),
            NoteTag::new((1 << 31) - 1),
            NoteTag::new(1 << 31),
            NoteTag::new(u32::MAX),
        ] {
            let raw = bound_integer(&tag);
            assert_eq!(raw, i64::from(tag.as_u32()), "tags are stored unsigned: {tag:?}");
            assert_eq!(
                read_integer::<NoteTag>(raw).unwrap(),
                tag,
                "read side diverged for {tag:?}"
            );
        }
    }

    #[test]
    fn felt_roundtrip() {
        // `Felt::MAX` is the largest canonical element; it exceeds `i64::MAX` and is therefore
        // stored as a negative integer.
        for felt in [Felt::ZERO, Felt::ONE, Felt::from_u32(u32::MAX), Felt::MAX] {
            let raw = bound_integer(&felt);
            #[expect(clippy::cast_possible_wrap, reason = "mirrors the legacy nonce encoding")]
            let legacy = felt.as_canonical_u64() as i64;
            assert_eq!(raw, legacy, "write side diverged for {felt}");
            assert_eq!(read_integer::<Felt>(raw).unwrap(), felt, "read side diverged for {felt}");
        }
    }

    #[test]
    fn storage_slot_name_roundtrip() {
        let name = StorageSlotName::new("some_component::some_slot").unwrap();
        let DbValue::Single(Value::Text(text)) = name.to_sql_value() else {
            panic!("storage slot names are stored as TEXT");
        };
        assert_eq!(text, String::from(name.clone()));
        assert_eq!(
            StorageSlotName::from_sql_value(DbValueRef::new(ValueRef::Text(text.as_bytes())))
                .unwrap(),
            name,
        );
    }

    // RANGE CHECKING
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn unsigned_int_roundtrip() {
        assert_eq!(read_integer::<u8>(bound_integer(&u8::MAX)).unwrap(), u8::MAX);
        assert_eq!(read_integer::<u16>(bound_integer(&u16::MAX)).unwrap(), u16::MAX);
        assert_eq!(read_integer::<u32>(bound_integer(&u32::MAX)).unwrap(), u32::MAX);
        assert_eq!(read_integer::<u8>(0).unwrap(), 0);
    }

    #[test]
    fn out_of_range_ints_error_instead_of_truncating() {
        // A cast would have yielded 0, 0, and `u32::MAX` respectively.
        assert_matches::assert_matches!(
            read_integer::<u8>(256),
            Err(DatabaseError::ConversionSqlToRust { to: "u8", .. })
        );
        assert_matches::assert_matches!(
            read_integer::<u16>(65_536),
            Err(DatabaseError::ConversionSqlToRust { to: "u16", .. })
        );
        assert_matches::assert_matches!(
            read_integer::<u32>(-1),
            Err(DatabaseError::ConversionSqlToRust { to: "u32", .. })
        );
    }

    #[test]
    fn out_of_range_block_number_errors() {
        // `BlockNumber` is a u32 on the wire; a wider column value is corruption, not a wrap.
        assert_matches::assert_matches!(
            read_integer::<BlockNumber>(i64::from(u32::MAX) + 1),
            Err(DatabaseError::ConversionSqlToRust { to: "u32", .. })
        );
        assert_matches::assert_matches!(
            read_integer::<BlockNumber>(-1),
            Err(DatabaseError::ConversionSqlToRust { to: "u32", .. })
        );
    }

    // BLOB CODEC
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn blob_roundtrip() {
        let word = Word::from([1u32, 2, 3, 4]);
        let DbValue::Single(Value::Blob(bytes)) = word.to_sql_value() else {
            panic!("words are stored as BLOBs");
        };
        assert_eq!(Word::from_sql_value(DbValueRef::new(ValueRef::Blob(&bytes))).unwrap(), word);
    }

    #[test]
    fn blob_deserialization_error_names_the_type() {
        assert_matches::assert_matches!(
            Word::from_sql_value(DbValueRef::new(ValueRef::Blob(&[0xff]))),
            Err(DatabaseError::ConversionSqlToRust { to: "miden_protocol::Word", .. })
        );
    }
}
