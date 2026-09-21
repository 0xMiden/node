//! Records a transaction that this validator has re-executed and validated, together with its
//! encrypted private record.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

use crate::StoredPrivateRecord;

const SQL: &str = include_str!("insert_validated_private_transaction.sql");

/// Inserts a validated transaction and its encrypted private record.
///
/// Returns the number of inserted rows, which is zero if the transaction was already recorded.
pub fn insert_validated_private_transaction(
    tx: &WriteTx<'_>,
    record: &StoredPrivateRecord,
) -> Result<usize, DatabaseError> {
    let context = record.context();
    let transaction_id = context.transaction_id();
    let validator_id = record.record_id().validator_id().to_vec();
    let chain_id = context.chain_id().as_bytes().to_vec();
    let key_epoch = context.key_epoch().as_bytes().to_vec();
    let setup_context_id = record.setup_context_id().to_vec();
    let format_version = i64::from(context.format_version().as_u32());
    let nonce = record.nonce().to_vec();
    let encrypted_record = record.encrypted_record().to_vec();
    let encrypted_record_key = record.encrypted_record_key().to_vec();

    tx.execute(
        SQL,
        &[
            &transaction_id,
            &validator_id,
            &chain_id,
            &key_epoch,
            &setup_context_id,
            &format_version,
            &nonce,
            &encrypted_record,
            &encrypted_record_key,
        ],
    )
}
