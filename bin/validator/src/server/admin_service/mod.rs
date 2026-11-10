//! Private validator administration API.
//!
//! One submodule per endpoint, holding its handler and its request/response types; shared pieces
//! (the service state, the routing table, hex parsing, and the error type) live here and in
//! [`error`].

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::Router;
use axum::routing::{get, post};
use miden_node_tracing::info;
use miden_node_utils::shutdown::CancellationToken;
use tokio::net::TcpListener;

use crate::GoldenOperatorKey;
use crate::db::ValidatorDbReader;
use crate::server::admin_service::error::ApiError;

#[cfg(test)]
mod tests;

mod decrypt_transaction;
mod error;
mod get_transaction;
mod issue_decryption_share;
mod list_transactions;

/// Serves the private validator administration API on a network-isolated listener.
pub struct ValidatorAdminServer {
    /// Address of the private administration listener.
    pub address: SocketAddr,
    /// Golden key material used to issue this validator's decryption shares.
    pub operator_key: GoldenOperatorKey,
    /// Read handle to the shared validator database. Administration routes cannot mutate stored
    /// validator records through this handle.
    pub reader: ValidatorDbReader,
}

impl ValidatorAdminServer {
    /// Serves the private validator administration API.
    pub async fn serve(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let listener =
            TcpListener::bind(self.address).await.context("failed to bind admin address")?;
        self.serve_on(listener, shutdown).await
    }

    async fn serve_on(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        let endpoint =
            listener.local_addr().context("failed to read validator admin listen address")?;
        info!(
            "Validator admin server ready",
            service.name = "miden-validator-admin",
            validator.admin_listen = endpoint.to_string()
        );

        axum::serve(listener, router(self.operator_key, self.reader))
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .context("failed to serve validator admin API")
    }
}

const LIST_TRANSACTIONS_PATH: &str = "/admin/v1/transactions";
const GET_TRANSACTION_PATH: &str = "/admin/v1/transactions/{transaction_id}";
const DECRYPT_TRANSACTION_PATH: &str = "/admin/v1/transactions/{transaction_id}/decrypt";
const ISSUE_SHARE_PATH: &str = "/admin/v1/decryption-share";

#[derive(Clone)]
struct ValidatorAdminService {
    operator_key: Arc<GoldenOperatorKey>,
    /// Read-only handle for retrieving validator records and recovering their contents.
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
        .route(DECRYPT_TRANSACTION_PATH, post(decrypt_transaction::decrypt_transaction))
        .with_state(ValidatorAdminService::new(operator_key, reader))
        .merge(miden_node_tracing::admin::router())
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(value).map_err(|_error| ApiError::bad_request(format!("{field} must be valid hex")))
}
