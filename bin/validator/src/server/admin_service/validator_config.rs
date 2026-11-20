//! Operator endpoints for reading, registering, and cancelling a validator configuration change.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use miden_protocol::block::ValidatorConfig;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::error::ApiError;
use crate::db::ValidatorDbWriter;

const ACTIVE_MISMATCH: &str = "`active` does not match the configuration at the chain tip";
const DIFFERENT_PENDING: &str = "a different validator configuration is pending";

#[derive(Clone)]
struct ConfigService {
    db: ValidatorDbWriter,
    signing_key: PublicKey,
    signing_lock: Arc<Mutex<()>>,
}

pub(super) fn router(
    db: &ValidatorDbWriter,
    signing_key: PublicKey,
    signing_lock: Arc<Mutex<()>>,
) -> Router {
    Router::new()
        .route("/admin/v1/validator-config", get(status))
        .route("/admin/v1/validator-config/pending", put(register).delete(cancel))
        .with_state(ConfigService {
            db: db.clone(),
            signing_key,
            signing_lock,
        })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorConfigJson {
    keys: Vec<String>,
    quorum: u16,
}

impl From<&ValidatorConfig> for ValidatorConfigJson {
    fn from(config: &ValidatorConfig) -> Self {
        Self {
            keys: config.keys().iter().map(ToString::to_string).collect(),
            quorum: config.quorum(),
        }
    }
}

impl ValidatorConfigJson {
    fn decode(self) -> Result<ValidatorConfig, ApiError> {
        let keys = self
            .keys
            .iter()
            .map(|key| PublicKey::from_hex(key))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ApiError::bad_request(format!("invalid validator key: {err}")))?;
        ValidatorConfig::new(keys, self.quorum)
            .map_err(|err| ApiError::bad_request(err.to_string()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorConfigChange {
    active: ValidatorConfigJson,
    pending: ValidatorConfigJson,
}

impl ValidatorConfigChange {
    fn decode(self) -> Result<(ValidatorConfig, ValidatorConfig), ApiError> {
        let active = self.active.decode()?;
        let pending = self.pending.decode()?;
        if active == pending {
            return Err(ApiError::bad_request("active and pending configurations are identical"));
        }
        Ok((active, pending))
    }
}

#[derive(Serialize)]
struct Status {
    active: ValidatorConfigJson,
    pending: Option<ValidatorConfigJson>,
}

async fn status(State(admin): State<ConfigService>) -> Result<Json<Status>, ApiError> {
    admin
        .db
        .read("validator_config_status", |tx| {
            let tip = tx.select_chain_tip()?.ok_or_else(missing_chain_tip)?;
            let pending = tx.select_pending_validator_config()?;
            Ok(Json(Status {
                active: tip.validator_config().into(),
                pending: pending.as_ref().map(Into::into),
            }))
        })
        .await
}

async fn register(
    State(admin): State<ConfigService>,
    Json(change): Json<ValidatorConfigChange>,
) -> Result<StatusCode, ApiError> {
    let (active, pending) = change.decode()?;
    if !pending.keys().contains(&admin.signing_key) {
        return Err(ApiError::bad_request(
            "the pending configuration must contain the local signing key",
        ));
    }
    if !active.keys().iter().all(|key| pending.keys().contains(key)) {
        return Err(ApiError::bad_request("removing validators is unsupported"));
    }
    let signing_guard = admin.signing_lock.lock_owned().await;
    let _guard_until_commit = admin
        .db
        .write("register_validator_config", move |tx| {
            let tip = tx.select_chain_tip()?.ok_or_else(missing_chain_tip)?;
            if tip.validator_config() != &active {
                return Err(ApiError::conflict(ACTIVE_MISMATCH));
            }
            match tx.select_pending_validator_config()? {
                Some(config) if config != pending => {
                    return Err(ApiError::conflict(DIFFERENT_PENDING));
                },
                Some(_) => {},
                None => tx.insert_pending_validator_config(&pending)?,
            }
            Ok(signing_guard)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cancel(
    State(admin): State<ConfigService>,
    Json(change): Json<ValidatorConfigChange>,
) -> Result<StatusCode, ApiError> {
    let (active, pending) = change.decode()?;
    let signing_guard = admin.signing_lock.lock_owned().await;
    let _guard_until_commit = admin
        .db
        .write("cancel_validator_config", move |tx| {
            let tip = tx.select_chain_tip()?.ok_or_else(missing_chain_tip)?;
            if tip.validator_config() == &pending {
                return Err(ApiError::conflict("the requested configuration is already active"));
            }
            if tip.validator_config() != &active {
                return Err(ApiError::conflict(ACTIVE_MISMATCH));
            }
            match tx.select_pending_validator_config()? {
                Some(config) if config == pending => tx.delete_pending_validator_config()?,
                Some(_) => return Err(ApiError::conflict(DIFFERENT_PENDING)),
                None => {
                    return Err(ApiError::conflict("no validator configuration change is pending"));
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
