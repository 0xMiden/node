use axum::Json;
use axum::extract::State;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::Note;
use miden_protocol::utils::serde::Serializable;
use serde::{Deserialize, Serialize};

use crate::COMPONENT;
use crate::error::RequestFundsError;
use crate::server::FundingState;
use crate::worker::MAX_FEE_VERIFICATION_CYCLES;

// REQUEST AND RESPONSE
// ================================================================================================

/// The body of a funding request.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct RequestFundsRequest {
    /// The account which the note targets, in hexadecimal.
    account_id: String,

    /// The amount of the native asset, in base units.
    amount: u64,
}

/// The body of a successful funding response.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct RequestFundsResponse {
    /// The serialized note, in hexadecimal.
    note: String,
}

impl From<&Note> for RequestFundsResponse {
    fn from(note: &Note) -> Self {
        Self { note: hex::encode(note.to_bytes()) }
    }
}

// REQUEST FUNDS HANDLER
// ================================================================================================

/// Creates a public P2ID note which holds `amount` base units of the native asset and targets
/// `account_id`, and persists it for the worker to create on chain.
#[miden_node_tracing::miden_instrument(
    target = COMPONENT,
    name = "request_funds",
    fields (
        account.id = request.account_id,
        asset.amount = request.amount,
    ),
    err,
)]
pub(super) async fn request_funds(
    State(state): State<FundingState>,
    Json(request): Json<RequestFundsRequest>,
) -> Result<Json<RequestFundsResponse>, RequestFundsError> {
    let target = AccountId::from_hex(&request.account_id)
        .map_err(|_| RequestFundsError::InvalidAccountId)?;
    validate_target(target, state.status.account_id())?;
    validate_amount(request.amount, state.status.max_amount())?;
    validate_balance(request.amount, state.status.balance(), state.status.verification_base_fee())?;

    // Each request draws its own serial number, so the handler needs no shared generator and takes
    // no lock. Two notes never collide, because the generator is seeded at random.
    let mut rng = RandomCoin::new(Word::from(rand::random::<[u32; 4]>()));
    let stored = state
        .database
        .store_request(target, request.amount, rng.draw_word())
        .await
        .map_err(RequestFundsError::Internal)?;

    miden_node_tracing::miden_span_record!(note.id = stored.note.id());
    Ok(Json(RequestFundsResponse::from(&stored.note)))
}

/// Checks that the note does not target the funding account.
fn validate_target(target: AccountId, funder: AccountId) -> Result<(), RequestFundsError> {
    if target == funder {
        return Err(RequestFundsError::TargetIsFundingAccount);
    }

    Ok(())
}

/// Checks the requested amount against the configured maximum.
fn validate_amount(amount: u64, maximum: u64) -> Result<(), RequestFundsError> {
    if amount == 0 {
        return Err(RequestFundsError::InvalidAmount);
    }

    if amount > maximum {
        return Err(RequestFundsError::AmountExceedsMaximum { requested: amount, maximum });
    }

    Ok(())
}

/// Checks the requested amount against the balance the service last read.
fn validate_balance(
    amount: u64,
    balance: u64,
    verification_base_fee: u32,
) -> Result<(), RequestFundsError> {
    let reserve = u64::from(verification_base_fee) * MAX_FEE_VERIFICATION_CYCLES;
    if amount > balance.saturating_sub(reserve) {
        return Err(RequestFundsError::InsufficientFunds { requested: amount, balance, reserve });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use miden_node_db::DatabaseError;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::utils::serde::Deserializable;
    use miden_standards::note::P2idNoteStorage;
    use tower::ServiceExt;

    use super::*;
    use crate::db::FundingDatabase;
    use crate::lifecycle::DATABASE_FILENAME;
    use crate::server::REQUEST_FUNDS_PATH;
    use crate::server::tests::{test_router, test_state};

    const MAX_AMOUNT: u64 = 1_000;

    #[test]
    fn a_zero_amount_is_rejected() {
        let err = validate_amount(0, MAX_AMOUNT).unwrap_err();

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn an_amount_above_the_maximum_is_rejected() {
        validate_amount(MAX_AMOUNT, MAX_AMOUNT).expect("the maximum itself is allowed");

        let err = validate_amount(MAX_AMOUNT + 1, MAX_AMOUNT).unwrap_err();

        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    /// The balance has to cover the amount on top of the fee one transaction may cost.
    #[test]
    fn an_amount_the_balance_cannot_cover_is_rejected() {
        let reserve = u64::from(10u32) * MAX_FEE_VERIFICATION_CYCLES;

        validate_balance(100, 100 + reserve, 10).expect("the balance covers the amount");

        let err = validate_balance(100, 99 + reserve, 10).unwrap_err();
        assert_eq!(err.status_code(), StatusCode::PRECONDITION_FAILED);
    }

    /// The response waits for persistence of the exact note returned to the caller.
    #[tokio::test]
    async fn the_answer_waits_for_persistence_and_carries_the_stored_note() {
        let (telemetry, _guard) = crate::test_utils::telemetry::Telemetry::capture();
        let (directory, state) = test_state(MAX_AMOUNT).await;
        let path = directory.path().join(DATABASE_FILENAME);
        let identity = state.database.identity();
        let (writer, _reader) = miden_node_db::sqlite::open(&path).unwrap();
        let blocker = writer.begin_write().await.unwrap();
        let funder = state.status.account_id();
        let fee_asset_id = identity.fee_asset_id;
        state.status.update(MAX_AMOUNT, BlockNumber::GENESIS, 0);

        let (target, _) =
            crate::test_utils::genesis_style_wallet(fee_asset_id.faucet_id(), 0, [61; 32])
                .expect("wallet should build");

        let response = test_router(state).oneshot(
            Request::post(REQUEST_FUNDS_PATH)
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"account_id":"{}","amount":500}}"#,
                    target.id().to_hex()
                )))
                .unwrap(),
        );
        tokio::pin!(response);
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut response).await.is_err());

        blocker.commit().await.unwrap();
        let response = response.await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: RequestFundsResponse = serde_json::from_slice(&body).unwrap();
        let answered = Note::read_from_bytes(&hex::decode(&body.note).unwrap()).unwrap();

        assert_eq!(answered.metadata().sender(), funder);
        assert_eq!(
            answered.assets().iter().copied().collect::<Vec<_>>(),
            vec![
                miden_protocol::asset::FungibleAsset::new(fee_asset_id.faucet_id(), 500)
                    .unwrap()
                    .into()
            ]
        );
        let storage =
            P2idNoteStorage::try_from(answered.recipient().storage().to_elements().as_slice())
                .unwrap();
        assert_eq!(storage.target(), target.id());

        let database =
            FundingDatabase::open_and_verify(&path, identity.genesis_commitment, fee_asset_id)
                .await
                .unwrap();
        let stored = database.request(answered.id()).await.unwrap().unwrap();
        assert_eq!(stored.note, answered);
        assert!(stored.delivery.is_none());
        let span = telemetry.span("request_funds");
        assert_eq!(
            crate::test_utils::telemetry::attribute(&span, "note.id"),
            Some(answered.id().to_string().into())
        );
    }

    #[tokio::test]
    async fn a_database_failure_returns_an_error_without_accepting_the_note() {
        let (directory, state) = test_state(MAX_AMOUNT).await;
        state.status.update(MAX_AMOUNT, BlockNumber::GENESIS, 0);
        let (writer, _reader) =
            miden_node_db::sqlite::open(&directory.path().join(DATABASE_FILENAME)).unwrap();
        writer
            .write("reject funding request inserts", |tx| {
                tx.execute(
                    "CREATE TRIGGER reject_funding_request BEFORE INSERT ON requests
                     BEGIN SELECT RAISE(FAIL, 'persistence unavailable'); END",
                    &[],
                )?;
                Ok::<_, DatabaseError>(())
            })
            .await
            .unwrap();
        let database = std::sync::Arc::clone(&state.database);
        let target: AccountId =
            miden_protocol::testing::account_id::ACCOUNT_ID_SENDER.try_into().unwrap();

        let response = test_router(state)
            .oneshot(
                Request::post(REQUEST_FUNDS_PATH)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"account_id":"{}","amount":500}}"#,
                        target.to_hex()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({ "error": "internal error" }),
        );
        assert!(
            database
                .pending_requests(NonZeroUsize::new(1).unwrap())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn requests_are_accepted_without_a_worker_or_an_in_memory_backlog_limit() {
        let (_directory, state) = test_state(MAX_AMOUNT).await;
        state.status.update(MAX_AMOUNT, BlockNumber::GENESIS, 0);
        let database = std::sync::Arc::clone(&state.database);
        let router = test_router(state);
        let target: AccountId =
            miden_protocol::testing::account_id::ACCOUNT_ID_SENDER.try_into().unwrap();
        let mut notes = Vec::new();
        for _ in 0..8 {
            let response = router
                .clone()
                .oneshot(
                    Request::post(REQUEST_FUNDS_PATH)
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"account_id":"{}","amount":1}}"#,
                            target.to_hex()
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body: RequestFundsResponse = serde_json::from_slice(&body).unwrap();
            notes.push(Note::read_from_bytes(&hex::decode(body.note).unwrap()).unwrap());
        }
        let stored = database.pending_requests(8.try_into().unwrap()).await.unwrap();
        assert_eq!(stored.into_iter().map(|request| request.note).collect::<Vec<_>>(), notes);
    }

    /// A request the balance cannot cover must not be persisted.
    #[tokio::test]
    async fn an_unaffordable_request_is_refused_before_persistence() {
        let (_directory, state) = test_state(MAX_AMOUNT).await;
        let database = std::sync::Arc::clone(&state.database);
        state.status.update(10, BlockNumber::GENESIS, 0);
        let (target, _) = crate::test_utils::genesis_style_wallet(
            state.database.identity().fee_asset_id.faucet_id(),
            0,
            [63; 32],
        )
        .expect("wallet should build");

        let response = test_router(state)
            .oneshot(
                Request::post(REQUEST_FUNDS_PATH)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"account_id":"{}","amount":500}}"#,
                        target.id().to_hex()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert!(database.pending_requests(1.try_into().unwrap()).await.unwrap().is_empty());
    }

    /// A note which targets the funding account would return to it as a deposit, so the request
    /// must not be persisted even when the balance covers it.
    #[tokio::test]
    async fn a_request_for_the_funding_account_is_refused_before_persistence() {
        let (_directory, state) = test_state(MAX_AMOUNT).await;
        let database = std::sync::Arc::clone(&state.database);
        state.status.update(MAX_AMOUNT, BlockNumber::GENESIS, 0);
        let funder = state.status.account_id();

        let response = test_router(state)
            .oneshot(
                Request::post(REQUEST_FUNDS_PATH)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"account_id":"{}","amount":500}}"#,
                        funder.to_hex()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(database.pending_requests(1.try_into().unwrap()).await.unwrap().is_empty());
    }
}
