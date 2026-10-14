//! Recovery of one locally stored private record using externally collected shares.

use axum::Json;
use axum::extract::{Path, State};

use super::error::ApiError;
use super::get_transaction::parse_transaction_id;
use super::{ValidatorAdminService, decode_hex};
use crate::{PrivateRecordCombiner, PrivateRecordError, PrivateRecordShareRequest};

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(super) struct DecryptTransactionRequest {
    pub(super) decryption_shares: Vec<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(super) struct DecryptTransactionResponse {
    pub(super) plaintext: String,
}

pub(super) async fn decrypt_transaction(
    State(service): State<ValidatorAdminService>,
    Path(transaction_id): Path<String>,
    Json(request): Json<DecryptTransactionRequest>,
) -> Result<Json<DecryptTransactionResponse>, ApiError> {
    let transaction_id = parse_transaction_id(&transaction_id)?;
    let shares = request
        .decryption_shares
        .iter()
        .map(|share| decode_hex("decryption_shares", share))
        .collect::<Result<Vec<_>, _>>()?;
    let record = service
        .reader
        .load_private_record(transaction_id)
        .await
        .map_err(|error| ApiError::internal("failed to load the private record", &error))?
        .ok_or_else(|| ApiError::not_found("transaction not found"))?;
    let combiner = PrivateRecordCombiner::from_operator_key(&service.operator_key)
        .map_err(|error| ApiError::internal("failed to initialize record decryption", &error))?;
    let plaintext = combiner
        .open(&PrivateRecordShareRequest::for_record(&record), &record, &shares)
        .map_err(|error| map_decrypt_error(&error))?;
    Ok(Json(DecryptTransactionResponse {
        plaintext: hex::encode(plaintext.as_slice()),
    }))
}

/// Classifies caller-supplied share failures separately from stored-record and server failures.
fn map_decrypt_error(error: &PrivateRecordError) -> ApiError {
    match error {
        PrivateRecordError::InvalidDecryptionShare(_)
        | PrivateRecordError::ShareCombination(_)
        | PrivateRecordError::KeyEpochMismatch
        | PrivateRecordError::SetupContextMismatch => ApiError::bad_request(error.to_string()),
        PrivateRecordError::RecordIdMismatch
        | PrivateRecordError::InvalidValidatorId(_)
        | PrivateRecordError::DecryptionContextMismatch
        | PrivateRecordError::MalformedDecryptionContext
        | PrivateRecordError::RecordEncryption
        | PrivateRecordError::ContentKeyEncryption(_)
        | PrivateRecordError::InvalidGoldenEncoding(_)
        | PrivateRecordError::InvalidCombinerSetup(_)
        | PrivateRecordError::ShareGeneration(_)
        | PrivateRecordError::InvalidEncryptedRecordKey
        | PrivateRecordError::UnsupportedFormat(_)
        | PrivateRecordError::InvalidNonceLength { .. }
        | PrivateRecordError::InvalidRecordCiphertext
        | PrivateRecordError::RecordDecryption => {
            ApiError::internal("failed to decrypt private record", error)
        },
    }
}
