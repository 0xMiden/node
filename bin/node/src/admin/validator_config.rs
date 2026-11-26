//! Sequencer endpoints for reading, registering, and cancelling validator configuration changes.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use miden_node_block_producer::validator_config::{PendingValidatorQuorum, ValidatorConfigState};
use miden_node_tracing::{error, info};
use miden_protocol::block::{BlockHeader, ValidatorConfig};
use serde::{Deserialize, Serialize};

const ACTIVE_MISMATCH: &str = "`active` does not match the quorum at the chain tip";
const DIFFERENT_PENDING: &str = "a different validator quorum change is pending";

pub(super) fn router(config: ValidatorConfigState) -> Router {
    Router::new()
        .route("/admin/v1/validator-config", get(status))
        .route("/admin/v1/validator-config/pending", put(register).delete(cancel))
        .with_state(config)
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    activation_height: u32,
}

#[derive(Serialize)]
struct Status {
    active: u16,
    pending: Option<u16>,
    activation_height: Option<u32>,
}

async fn status(State(admin): State<ValidatorConfigState>) -> Result<Json<Status>, ApiError> {
    let registration = admin.pending.lock().await;
    let tip = chain_tip(&admin).await?;
    let pending = *registration;
    Ok(Json(Status {
        active: tip.validator_config().quorum(),
        pending: pending.map(|change| change.quorum),
        activation_height: pending.map(|change| change.activation_height.as_u32()),
    }))
}

async fn register(
    State(admin): State<ValidatorConfigState>,
    Query(schedule): Query<Schedule>,
    Json(change): Json<QuorumChange>,
) -> Result<StatusCode, ApiError> {
    change.validate()?;
    let pending = PendingValidatorQuorum {
        quorum: change.pending,
        activation_height: schedule.activation_height.into(),
    };
    let mut registration = admin.pending.lock().await;
    let tip = chain_tip(&admin).await?;
    let config = tip.validator_config();
    if config.quorum() != change.active {
        return Err(ApiError::conflict(ACTIVE_MISMATCH));
    }
    if pending
        .activation_height
        .parent()
        .is_none_or(|height| height <= tip.block_num())
    {
        return Err(ApiError::conflict("the transition block must be ahead of the chain tip"));
    }
    if usize::from(change.pending) > config.keys().len() {
        return Err(ApiError::bad_request("the quorum exceeds the number of validators"));
    }
    ValidatorConfig::new(config.keys().to_vec(), change.pending).map_err(|err| {
        ApiError::bad_request(format!("the protocol does not support the requested quorum: {err}"))
    })?;
    match *registration {
        Some(registered) if registered != pending => {
            return Err(ApiError::conflict(DIFFERENT_PENDING));
        },
        Some(_) => {},
        None => {
            *registration = Some(pending);
            info!(
                "Validator configuration change registered",
                validator.quorum = pending.quorum #[nonstandard],
                validator.activation_height = pending.activation_height.as_u32() #[nonstandard]
            );
        },
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn cancel(
    State(admin): State<ValidatorConfigState>,
    Query(schedule): Query<Schedule>,
    Json(change): Json<QuorumChange>,
) -> Result<StatusCode, ApiError> {
    change.validate()?;
    let pending = PendingValidatorQuorum {
        quorum: change.pending,
        activation_height: schedule.activation_height.into(),
    };
    let mut registration = admin.pending.lock().await;
    let tip = chain_tip(&admin).await?;
    let active = tip.validator_config().quorum();
    if active == change.pending {
        return Err(ApiError::conflict("the requested quorum is already active"));
    }
    if active != change.active {
        return Err(ApiError::conflict(ACTIVE_MISMATCH));
    }
    match *registration {
        Some(registered) if registered == pending => {
            *registration = None;
            info!(
                "Validator configuration change cancelled",
                validator.quorum = pending.quorum #[nonstandard],
                validator.activation_height = pending.activation_height.as_u32() #[nonstandard]
            );
        },
        Some(_) => return Err(ApiError::conflict(DIFFERENT_PENDING)),
        None => return Err(ApiError::conflict("no validator quorum change is pending")),
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn chain_tip(admin: &ValidatorConfigState) -> Result<BlockHeader, ApiError> {
    let (header, _) = admin.state.view().get_block_header(None, false).await.map_err(|cause| {
        error!(&cause, "sequencer admin chain tip query failed");
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "failed to read the chain tip".into(),
        }
    })?;
    header.ok_or_else(|| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: "sequencer database has no chain tip".into(),
    })
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({"error": self.message}))).into_response()
    }
}

#[cfg(test)]
mod tests;
