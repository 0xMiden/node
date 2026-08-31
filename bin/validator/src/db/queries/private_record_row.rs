//! Row decoding shared by every query that selects encrypted private records.
//!
//! All private-record queries select the same column list in the same order (see the `.sql` files
//! next to them), so they all decode rows through [`private_record_from_row`].

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::Row;

use crate::{
    PrivateRecordChainId,
    PrivateRecordContext,
    PrivateRecordId,
    PrivateRecordStorageFields,
    StorageKeyEpoch,
    StoredPrivateRecord,
};

/// Decodes one row of the private-record column list into a [`StoredPrivateRecord`].
pub fn private_record_from_row(row: &Row<'_>) -> Result<StoredPrivateRecord, DatabaseError> {
    let chain_id = fixed_32(row.get(0)?, "private record chain id")?;
    let key_epoch = fixed_32(row.get(1)?, "private record key epoch")?;
    let transaction_id = row.get(2)?;
    let validator_id = fixed_33(row.get(3)?, "private record validator id")?;
    let setup_context_id = fixed_32(row.get(4)?, "private record setup context id")?;
    let format_version = checked_u32(row.get(5)?, "private record format version")?;
    let nonce = row.get(6)?;
    let encrypted_record = row.get(7)?;
    let encrypted_record_key = row.get(8)?;
    let record_id = PrivateRecordId::from_parts(transaction_id, validator_id)
        .map_err(|source| DatabaseError::deserialization("private record id", source))?;

    StoredPrivateRecord::from_storage_fields(PrivateRecordStorageFields {
        record_id,
        context: PrivateRecordContext::new(
            PrivateRecordChainId::new(chain_id),
            StorageKeyEpoch::new(key_epoch),
            transaction_id,
        ),
        format_version,
        setup_context_id,
        nonce,
        encrypted_record,
        encrypted_record_key,
    })
    .map_err(|source| DatabaseError::deserialization("private record", source))
}

pub(super) fn fixed_32(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 32], DatabaseError> {
    let actual_len = bytes.len();
    bytes.try_into().map_err(|_bytes: Vec<u8>| {
        let source = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected 32 bytes, got {actual_len}"),
        );
        DatabaseError::deserialization(field, source)
    })
}

fn fixed_33(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 33], DatabaseError> {
    let actual_len = bytes.len();
    bytes.try_into().map_err(|_bytes: Vec<u8>| {
        let source = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected 33 bytes, got {actual_len}"),
        );
        DatabaseError::deserialization(field, source)
    })
}

fn checked_u32(value: i64, field: &'static str) -> Result<u32, DatabaseError> {
    u32::try_from(value).map_err(|source| DatabaseError::deserialization(field, source))
}
