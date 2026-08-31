//! Retrieval of one validated transaction's full sealed record by id.

use axum::Json;
use axum::extract::{Path, State};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use serde::{Deserialize, Serialize};

use crate::StoredPrivateRecord;
use crate::server::admin_service::error::ApiError;
use crate::server::admin_service::{ValidatorAdminService, decode_hex};

/// The full record of one validated transaction, returned by the single-transaction endpoint.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct ValidatedPrivateTransaction {
    pub(super) transaction_id: String,
    pub(super) final_ciphertext: String,
    pub(super) cipher_nonce: String,
    pub(super) encrypted_record_key: String,
    pub(super) decryption_context: String,
}

impl From<StoredPrivateRecord> for ValidatedPrivateTransaction {
    fn from(record: StoredPrivateRecord) -> Self {
        Self {
            transaction_id: hex::encode(record.context().transaction_id().to_bytes()),
            final_ciphertext: hex::encode(record.encrypted_record()),
            cipher_nonce: hex::encode(record.nonce()),
            encrypted_record_key: hex::encode(record.encrypted_record_key()),
            decryption_context: hex::encode(record.context().to_bytes()),
        }
    }
}

pub(super) async fn get_validated_private_transaction(
    State(service): State<ValidatorAdminService>,
    Path(transaction_id): Path<String>,
) -> Result<Json<ValidatedPrivateTransaction>, ApiError> {
    let transaction_id = parse_transaction_id(&transaction_id)?;
    let record = service
        .reader
        .load_private_record(transaction_id)
        .await
        .map_err(|_error| ApiError::internal("failed to load the private record"))?
        .ok_or_else(|| ApiError::not_found("transaction not found"))?;
    Ok(Json(record.into()))
}

fn parse_transaction_id(value: &str) -> Result<TransactionId, ApiError> {
    let bytes = decode_hex("transaction_id", value)?;
    TransactionId::read_from_bytes(&bytes).map_err(|_error| {
        ApiError::bad_request("transaction_id must be a canonical transaction id")
    })
}
