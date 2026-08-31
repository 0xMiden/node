//! Issuance of Golden decryption shares for threshold recovery.

use axum::Json;
use axum::extract::State;
use rand_core_06::OsRng;
use serde::{Deserialize, Serialize};

use crate::PrivateRecordError;
use crate::server::admin_service::error::ApiError;
use crate::server::admin_service::{ValidatorAdminService, decode_hex};

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
    let decryption_share = service
        .operator_key
        .issue_decryption_share(&mut OsRng, &ciphertext, &decryption_context)
        .map_err(|error| map_share_error(&error))?;

    Ok(Json(IssueDecryptionShareResponse {
        decryption_share: hex::encode(decryption_share),
    }))
}

fn map_share_error(error: &PrivateRecordError) -> ApiError {
    match error {
        PrivateRecordError::InvalidGoldenEncoding(_)
        | PrivateRecordError::InvalidEncryptedRecordKey
        | PrivateRecordError::DecryptionContextMismatch => ApiError::bad_request(error.to_string()),
        _ => ApiError::internal("failed to issue Golden decryption share"),
    }
}
