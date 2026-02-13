use diesel::{Connection, RunQueryDsl, SqliteConnection};
use miden_protocol::note::Nullifier;
use miden_protocol::utils::{Deserializable, DeserializationError, Serializable};

use crate::errors::DatabaseError;

/// Utility to convert an iterable container of containing `R`-typed values
/// to a `Vec<D>` and bail at the first failing conversion
pub(crate) fn vec_raw_try_into<D, R: TryInto<D>>(
    raw: impl IntoIterator<Item = R>,
) -> std::result::Result<Vec<D>, <R as TryInto<D>>::Error> {
    std::result::Result::<Vec<D>, <R as TryInto<D>>::Error>::from_iter(
        raw.into_iter().map(<R as std::convert::TryInto<D>>::try_into),
    )
}

#[expect(dead_code)]
/// Deserialize an iterable container full of byte blobs `B` to types `T`
pub(crate) fn deserialize_raw_vec<B: AsRef<[u8]>, T: Deserializable>(
    raw: impl IntoIterator<Item = B>,
) -> Result<Vec<T>, DeserializationError> {
    Result::<Vec<_>, DeserializationError>::from_iter(
        raw.into_iter().map(|raw| T::read_from_bytes(raw.as_ref())),
    )
}

/// Utility to convert an iterable container to a vector of byte blobs
pub(crate) fn serialize_vec<'a, D: Serializable + 'a>(
    raw: impl IntoIterator<Item = &'a D>,
) -> Vec<Vec<u8>> {
    Vec::<_>::from_iter(raw.into_iter().map(<D as Serializable>::to_bytes))
}

/// Returns the high 16 bits of the provided nullifier.
pub fn get_nullifier_prefix(nullifier: &Nullifier) -> u16 {
    (nullifier.most_significant_felt().as_int() >> 48) as u16
}

/// Converts a slice of length `N` to an array, returns `None` if invariant
/// isn'crates/store/src/db/mod.rs upheld.
#[expect(dead_code)]
pub fn slice_to_array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    if bytes.len() != N {
        return None;
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(bytes);
    Some(arr)
}

#[expect(dead_code)]
#[inline]
pub fn from_be_to_u32(bytes: &[u8]) -> Option<u32> {
    slice_to_array::<4>(bytes).map(u32::from_be_bytes)
}

#[derive(diesel::QueryableByName, Debug)]
#[diesel(table_name = diesel::table)]
pub struct PragmaSchemaVersion {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub schema_version: i32,
}

/// Returns the schema version of the database.
#[expect(dead_code)]
#[expect(
    clippy::cast_sign_loss,
    reason = "schema version is always positive and we will never reach 0xEFFF_..._FFFF"
)]
pub fn schema_version(conn: &mut SqliteConnection) -> Result<u32, DatabaseError> {
    let schema_version = conn.transaction(|conn| {
        let res = diesel::sql_query("SELECT schema_version FROM pragma_schema_version")
            .get_result::<PragmaSchemaVersion>(conn)?;
        Ok::<_, DatabaseError>(res.schema_version as u32)
    })?;
    Ok(schema_version)
}
