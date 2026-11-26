//! Operator endpoints for reading, registering, and cancelling a validator quorum change.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::error::ApiError;
use crate::db::ValidatorDbWriter;

const ACTIVE_MISMATCH: &str = "`active` does not match the quorum at the confirmed chain tip";
const DIFFERENT_PENDING: &str = "a different validator quorum is pending";

#[derive(Clone)]
struct QuorumService {
    db: ValidatorDbWriter,
    signing_lock: Arc<Mutex<()>>,
}

pub(super) fn router(db: &ValidatorDbWriter, signing_lock: Arc<Mutex<()>>) -> Router {
    Router::new()
        .route("/admin/v1/validator-config", get(status))
        .route("/admin/v1/validator-config/pending", put(register).delete(cancel))
        .with_state(QuorumService { db: db.clone(), signing_lock })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuorumChange {
    active: u16,
    pending: u16,
}

impl QuorumChange {
    fn validate(&self) -> Result<(), ApiError> {
        if self.active == 0 || self.pending == 0 {
            return Err(ApiError::bad_request("the quorum must be greater than zero"));
        }
        if self.active == self.pending {
            return Err(ApiError::bad_request("active and pending quorums are identical"));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct Status {
    active: u16,
    pending: Option<u16>,
}

async fn status(State(admin): State<QuorumService>) -> Result<Json<Status>, ApiError> {
    admin
        .db
        .read("validator_config_status", |tx| {
            let chain = tx.select_chain_state()?.ok_or_else(missing_chain_tip)?;
            let pending = tx.select_pending_validator_quorum()?;
            Ok(Json(Status {
                active: chain.tip.validator_config().quorum(),
                pending,
            }))
        })
        .await
}

async fn register(
    State(admin): State<QuorumService>,
    Json(change): Json<QuorumChange>,
) -> Result<StatusCode, ApiError> {
    change.validate()?;
    let signing_guard = admin.signing_lock.lock_owned().await;
    let _guard_until_commit = admin
        .db
        .write("register_validator_quorum", move |tx| {
            let chain = tx.select_chain_state()?.ok_or_else(missing_chain_tip)?;
            if chain.tip.validator_config().quorum() != change.active {
                return Err(ApiError::conflict(ACTIVE_MISMATCH));
            }
            if usize::from(change.pending) > chain.tip.validator_config().keys().len() {
                return Err(ApiError::bad_request("the quorum exceeds the number of validators"));
            }
            if chain.pending.as_ref().is_some_and(|header| {
                header.validator_config().quorum() != change.active
                    && header.validator_config().quorum() != change.pending
            }) {
                return Err(ApiError::conflict(
                    "a different signed validator quorum change is awaiting confirmation",
                ));
            }
            match tx.select_pending_validator_quorum()? {
                Some(quorum) if quorum != change.pending => {
                    return Err(ApiError::conflict(DIFFERENT_PENDING));
                },
                Some(_) => {},
                None => tx.insert_pending_validator_quorum(change.pending)?,
            }
            Ok(signing_guard)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cancel(
    State(admin): State<QuorumService>,
    Json(change): Json<QuorumChange>,
) -> Result<StatusCode, ApiError> {
    change.validate()?;
    let signing_guard = admin.signing_lock.lock_owned().await;
    let _guard_until_commit = admin
        .db
        .write("cancel_validator_quorum", move |tx| {
            let chain = tx.select_chain_state()?.ok_or_else(missing_chain_tip)?;
            if chain.tip.validator_config().quorum() == change.pending {
                return Err(ApiError::conflict("the requested quorum is already active"));
            }
            if chain.tip.validator_config().quorum() != change.active {
                return Err(ApiError::conflict(ACTIVE_MISMATCH));
            }
            if chain
                .pending
                .as_ref()
                .is_some_and(|header| header.validator_config().quorum() == change.pending)
            {
                return Err(ApiError::conflict(
                    "the validator has already signed the change and is awaiting confirmation",
                ));
            }
            match tx.select_pending_validator_quorum()? {
                Some(quorum) if quorum == change.pending => tx.delete_pending_validator_quorum()?,
                Some(_) => return Err(ApiError::conflict(DIFFERENT_PENDING)),
                None => {
                    return Err(ApiError::conflict("no validator quorum change is pending"));
                },
            }
            Ok(signing_guard)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn missing_chain_tip() -> ApiError {
    ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: "validator database has no chain tip".into(),
    }
}
