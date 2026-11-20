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
struct RegisterConfigRequest {
    current: ValidatorConfigJson,
    proposed: ValidatorConfigJson,
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
    Json(request): Json<RegisterConfigRequest>,
) -> Result<StatusCode, ApiError> {
    let current = request.current.decode()?;
    let proposed = request.proposed.decode()?;
    if !proposed.keys().contains(&admin.signing_key) {
        return Err(ApiError::bad_request(
            "the proposed configuration must contain the local signing key",
        ));
    }
    if proposed == current {
        return Err(ApiError::bad_request("current and proposed configurations are identical"));
    }
    if !current.keys().iter().all(|key| proposed.keys().contains(key)) {
        return Err(ApiError::bad_request("removing validators is unsupported"));
    }
    let signing_guard = admin.signing_lock.lock_owned().await;
    let _guard_until_commit = admin
        .db
        .write("register_validator_config", move |tx| {
            let tip = tx.select_chain_tip()?.ok_or_else(missing_chain_tip)?;
            if tip.validator_config() != &current {
                return Err(ApiError::conflict(
                    "current does not match the configuration at the chain tip",
                ));
            }
            match tx.select_pending_validator_config()? {
                Some(config) if config != proposed => {
                    return Err(ApiError::conflict(
                        "a different validator configuration is pending",
                    ));
                },
                Some(_) => {},
                None => tx.insert_pending_validator_config(&proposed)?,
            }
            Ok(signing_guard)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cancel(State(admin): State<ConfigService>) -> Result<StatusCode, ApiError> {
    let signing_guard = admin.signing_lock.lock_owned().await;
    let _guard_until_commit = admin
        .db
        .write("cancel_validator_config", move |tx| {
            tx.delete_pending_validator_config()?;
            Ok::<_, ApiError>(signing_guard)
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
