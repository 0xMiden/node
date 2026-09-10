use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router, middleware};
use miden_node_store::allowlist::{
    AccountAllowlist,
    AllowlistError,
    InvitationCode,
    InvitationEntry,
};
use miden_node_tracing::info;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::account::AccountId;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[cfg(test)]
mod tests;

/// Serves the private administration API behind external authentication.
pub(crate) struct AdminServer {
    listener: TcpListener,
    allowlist: Arc<AccountAllowlist>,
}

impl AdminServer {
    pub(crate) async fn bind(
        address: SocketAddr,
        allowlist: Arc<AccountAllowlist>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind admin listener to {address}"))?;
        Ok(Self { listener, allowlist })
    }

    pub(crate) async fn serve(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        info!(
            target: crate::LOG_TARGET,
            "Sequencer admin server ready",
            admin.listen = self.listener.local_addr().context("failed to read admin listen address")?.to_string()
        );
        axum::serve(self.listener, router(self.allowlist))
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .context("failed to serve sequencer admin API")
    }
}

fn router(allowlist: Arc<AccountAllowlist>) -> Router {
    Router::new()
        .route(
            "/admin/allowlist/invitations/{invitation_digest}",
            get(invitation_status).put(put_invitation),
        )
        .route("/admin/allowlist/accounts/{account_id}", get(account_status).put(put_account))
        .layer(middleware::map_response(no_store))
        .with_state(allowlist)
}

async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationRequest {
    account_id: Option<String>,
}

async fn put_invitation(
    State(allowlist): State<Arc<AccountAllowlist>>,
    Path(digest): Path<String>,
    Json(request): Json<InvitationRequest>,
) -> Result<StatusCode, ApiError> {
    let entry = InvitationEntry {
        invitation_code: InvitationCode::from_hex_digest(&digest)
            .map_err(|_| ApiError::InvalidInvitationDigest)?,
        account_id: request
            .account_id
            .as_deref()
            .map(AccountId::from_hex)
            .transpose()
            .map_err(|_| ApiError::InvalidAccountId)?,
    };
    let inserted = allowlist.import_invitation(entry).await.map_err(ApiError::Allowlist)?;
    Ok(if inserted {
        StatusCode::CREATED
    } else {
        StatusCode::NO_CONTENT
    })
}

async fn put_account(
    State(allowlist): State<Arc<AccountAllowlist>>,
    Path(account): Path<String>,
) -> Result<StatusCode, ApiError> {
    let account = AccountId::from_hex(&account).map_err(|_| ApiError::InvalidAccountId)?;
    let added = allowlist.add_account(account).await.map_err(ApiError::Database)?;
    Ok(if added {
        StatusCode::CREATED
    } else {
        StatusCode::NO_CONTENT
    })
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum InvitationState {
    Unknown,
    Unused,
    Registered,
}

#[derive(Serialize)]
struct InvitationStatusResponse {
    status: InvitationState,
    account_id: Option<String>,
    allowlisted_at: Option<i64>,
}

async fn invitation_status(
    State(allowlist): State<Arc<AccountAllowlist>>,
    Path(digest): Path<String>,
) -> Result<Json<InvitationStatusResponse>, ApiError> {
    let invitation =
        InvitationCode::from_hex_digest(&digest).map_err(|_| ApiError::InvalidInvitationDigest)?;
    let info = allowlist.invitation_info(invitation).await.map_err(ApiError::Database)?;
    let response = match info {
        Some(info) => InvitationStatusResponse {
            status: if info.account_id.is_some() {
                InvitationState::Registered
            } else {
                InvitationState::Unused
            },
            account_id: info.account_id.map(|account| account.to_string()),
            allowlisted_at: Some(info.allowlisted_at),
        },
        None => InvitationStatusResponse {
            status: InvitationState::Unknown,
            account_id: None,
            allowlisted_at: None,
        },
    };
    Ok(Json(response))
}

#[derive(Serialize)]
struct AccountStatusResponse {
    account_id: String,
    allowlisted_at: i64,
}

async fn account_status(
    State(allowlist): State<Arc<AccountAllowlist>>,
    Path(account): Path<String>,
) -> Result<Json<AccountStatusResponse>, ApiError> {
    let account = AccountId::from_hex(&account).map_err(|_| ApiError::InvalidAccountId)?;
    let allowlisted_at = allowlist
        .allowlisted_at(account)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::AccountNotFound)?;
    Ok(Json(AccountStatusResponse {
        account_id: account.to_string(),
        allowlisted_at,
    }))
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("allowlist database operation failed")]
    Database(#[source] miden_node_store::DatabaseError),
    #[error(transparent)]
    Allowlist(AllowlistError),
    #[error("account_id must be a valid hex account ID")]
    InvalidAccountId,
    #[error("invitation_digest must be a 64-character SHA-256 hex digest")]
    InvalidInvitationDigest,
    #[error("account is not registered")]
    AccountNotFound,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Database(_) | Self::Allowlist(AllowlistError::Database(_)) => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            Self::Allowlist(AllowlistError::InvitationNotFound) | Self::AccountNotFound => {
                StatusCode::NOT_FOUND
            },
            Self::Allowlist(
                AllowlistError::InvitationAlreadyUsed | AllowlistError::AccountAlreadyRegistered(_),
            ) => StatusCode::CONFLICT,
            Self::InvalidAccountId | Self::InvalidInvitationDigest => StatusCode::BAD_REQUEST,
        };
        (status, Json(serde_json::json!({"error": self.to_string()}))).into_response()
    }
}
