//! Issuance of Golden decryption shares for threshold recovery.

use axum::Json;
use axum::extract::State;
use rand_core_06::OsRng;
use serde::{Deserialize, Serialize};

use crate::server::admin_service::error::ApiError;
use crate::server::admin_service::{ValidatorAdminService, decode_hex};
use crate::{PrivateRecordContext, PrivateRecordError};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct IssueDecryptionShareRequest {
    pub(super) ciphertext: String,
    pub(super) decryption_context: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct IssueDecryptionShareResponse {
    pub(super) decryption_share: String,
}

pub(super) async fn issue_decryption_share(
    State(service): State<ValidatorAdminService>,
    Json(request): Json<IssueDecryptionShareRequest>,
) -> Result<Json<IssueDecryptionShareResponse>, ApiError> {
    let ciphertext = decode_hex("ciphertext", &request.ciphertext)?;
    let decryption_context = decode_hex("decryption_context", &request.decryption_context)?;

    // Only issue shares over transactions this validator itself validated. The context is
    // cryptographically bound to the ciphertext, so an attacker cannot smuggle an arbitrary
    // ciphertext under a validated transaction's context; and because every validator in the quorum
    // validated the transaction, cross-validator recovery (combining shares over one validator's
    // ciphertext) keeps working.
    let context = PrivateRecordContext::try_from_bytes(&decryption_context)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let validated = service
        .reader
        .transaction_exists(context.transaction_id())
        .await
        .map_err(|_error| ApiError::internal("failed to look up the transaction"))?;
    if !validated {
        return Err(ApiError::not_found(
            "decryption context references a transaction this validator has not validated",
        ));
    }

    let decryption_share = service
        .operator_key
        .issue_decryption_share(&mut OsRng, &ciphertext, &decryption_context)
        .map_err(|error| map_share_error(&error))?;

    Ok(Json(IssueDecryptionShareResponse {
        decryption_share: hex::encode(decryption_share),
    }))
}

/// Maps a share-issuance failure onto a response.
///
/// Matched exhaustively rather than through a wildcard, so that a new [`PrivateRecordError`]
/// variant — or a `golden-ehtdh1` upgrade that introduces a new failure — has to be classified
/// here, instead of silently defaulting to an internal error over what may be a malformed
/// request.
///
/// Only the bad-request arm is reachable today. `issue_decryption_share` rejects, in order, a
/// ciphertext that does not decode, a wrong-sized wrapped content key, and a ciphertext not bound
/// to the supplied context; `MalformedDecryptionContext` comes from this endpoint's own context
/// parsing. Everything in the internal arm belongs to sealing, share combination, or decoding a
/// stored record — none of which this endpoint does — so reaching one is a validator fault rather
/// than the caller's.
fn map_share_error(error: &PrivateRecordError) -> ApiError {
    match error {
        PrivateRecordError::InvalidGoldenEncoding(_)
        | PrivateRecordError::InvalidEncryptedRecordKey
        | PrivateRecordError::MalformedDecryptionContext
        | PrivateRecordError::DecryptionContextMismatch => ApiError::bad_request(error.to_string()),
        PrivateRecordError::KeyEpochMismatch
        | PrivateRecordError::RecordIdMismatch
        | PrivateRecordError::InvalidValidatorId(_)
        | PrivateRecordError::SetupContextMismatch
        | PrivateRecordError::RecordEncryption
        | PrivateRecordError::ContentKeyEncryption(_)
        | PrivateRecordError::InvalidCombinerSetup(_)
        | PrivateRecordError::InvalidDecryptionShare(_)
        | PrivateRecordError::ShareGeneration(_)
        | PrivateRecordError::ShareCombination(_)
        | PrivateRecordError::UnsupportedFormat(_)
        | PrivateRecordError::InvalidNonceLength { .. }
        | PrivateRecordError::InvalidRecordCiphertext
        | PrivateRecordError::RecordDecryption => {
            ApiError::internal("failed to issue Golden decryption share")
        },
    }
}
