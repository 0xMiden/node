use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::COMPONENT;
use crate::status::StatusSnapshot;

// STATUS RESPONSE
// ================================================================================================

/// The body of a status response.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct StatusResponse {
    /// The version of the funding service.
    version: String,
    /// The account which sends the notes, in hexadecimal.
    account_id: String,
    /// The balance of the native asset in the funding account, in base units, at `chain_tip`.
    balance: u64,
    /// The block number which the service is synchronized to.
    chain_tip: u32,
    /// The largest amount which one funding request accepts, in base units.
    max_amount: u64,
    /// The base fee for the verification of a transaction, in base units, at `chain_tip`.
    verification_base_fee: u32,
}

// STATUS HANDLER
// ================================================================================================

/// Returns the status of the funding service.
///
/// The status is served while the service is still synchronizing, so an operator can read the
/// funding account it was configured with.
#[miden_node_tracing::miden_instrument(target = COMPONENT, name = "status")]
pub(super) async fn status(State(status): State<StatusSnapshot>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        account_id: status.account_id().to_string(),
        balance: status.balance(),
        chain_tip: status.chain_tip().as_u32(),
        max_amount: status.max_amount(),
        verification_base_fee: status.verification_base_fee(),
    })
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountId;
    use miden_protocol::asset::FungibleAsset;

    use super::*;
    use crate::server::tests::test_status;

    #[tokio::test]
    async fn status_reports_the_configured_account_and_the_published_balance() {
        let snapshot = test_status(500);
        snapshot.update(1_234, 42.into(), 7);

        let Json(response) = status(State(snapshot)).await;

        assert_eq!(
            AccountId::from_hex(&response.account_id).unwrap(),
            FungibleAsset::mock_issuer()
        );
        assert_eq!(response.balance, 1_234);
        assert_eq!(response.chain_tip, 42);
        assert_eq!(response.max_amount, 500);
        assert_eq!(response.verification_base_fee, 7);
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    }
}
