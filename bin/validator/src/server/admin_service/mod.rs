//! Private validator administration API.
//!
//! One submodule per endpoint, holding its handler and its request/response types; shared pieces
//! (the service state, the routing table, hex parsing, and the error type) live here and in
//! [`error`].

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::GoldenOperatorKey;
use crate::db::ValidatorDbReader;
use crate::server::admin_service::error::ApiError;

#[cfg(test)]
mod tests;

mod error;
mod get_transaction;
mod issue_decryption_share;
mod list_transactions;

const LIST_TRANSACTIONS_PATH: &str = "/admin/v1/transactions";
const GET_TRANSACTION_PATH: &str = "/admin/v1/transactions/{transaction_id}";
const ISSUE_SHARE_PATH: &str = "/admin/v1/decryption-share";

#[derive(Clone)]
struct ValidatorAdminService {
    operator_key: Arc<GoldenOperatorKey>,
    /// Read-only handle: the administration API lists stored records and issues decryption shares,
    /// and must never mutate validator state.
    reader: ValidatorDbReader,
}

impl ValidatorAdminService {
    fn new(operator_key: GoldenOperatorKey, reader: ValidatorDbReader) -> Self {
        Self {
            operator_key: Arc::new(operator_key),
            reader,
        }
    }
}

pub(super) fn router(operator_key: GoldenOperatorKey, reader: ValidatorDbReader) -> Router {
    Router::new()
        .route(
            LIST_TRANSACTIONS_PATH,
            get(list_transactions::list_validated_private_transactions),
        )
        .route(GET_TRANSACTION_PATH, get(get_transaction::get_validated_private_transaction))
        .route(ISSUE_SHARE_PATH, post(issue_decryption_share::issue_decryption_share))
        .with_state(ValidatorAdminService::new(operator_key, reader))
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(value).map_err(|_error| ApiError::bad_request(format!("{field} must be valid hex")))
}
