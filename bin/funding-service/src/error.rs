use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use miden_node_tracing::ErrorReport;
use miden_protocol::block::BlockNumber;
use serde::{Deserialize, Serialize};

/// The reason a funding request failed.
#[derive(Debug, thiserror::Error)]
pub enum RequestFundsError {
    /// The service could not complete the request for a reason the client cannot act on.
    #[error("internal error")]
    Internal(#[source] anyhow::Error),

    /// The account ID is not valid hexadecimal, or does not encode an account.
    #[error("the account ID is malformed")]
    InvalidAccountId,

    /// A note must hold a non-zero amount.
    #[error("the requested amount must not be zero")]
    InvalidAmount,

    /// The request asked for more than the configured maximum.
    #[error("the requested amount {requested} exceeds the maximum of {maximum}")]
    AmountExceedsMaximum { requested: u64, maximum: u64 },

    /// The funding account cannot cover the request and the fee of one transaction.
    #[error(
        "the funding account holds {balance} base units, which does not cover the requested \
         {requested} plus a fee reserve of {reserve}"
    )]
    InsufficientFunds {
        requested: u64,
        balance: u64,
        reserve: u64,
    },

    /// The service cannot serve requests at the moment.
    #[error("the funding service is not ready: {0}")]
    NotReady(&'static str),

    /// The funding transaction did not commit before it expired.
    #[error("the funding transaction did not commit before block {expiration_block}")]
    TransactionExpired { expiration_block: BlockNumber },

    /// The node rejected the funding transaction.
    #[error("the node rejected the funding transaction")]
    TransactionRejected(#[source] anyhow::Error),

    /// Too many requests are queued.
    #[error("too many funding requests are queued")]
    Busy,
}

impl RequestFundsError {
    /// The HTTP status code for this error.
    ///
    /// The codes tell a client whether to change the request, wait, or retry it unchanged.
    pub(crate) fn status_code(&self) -> StatusCode {
        match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidAccountId | Self::InvalidAmount | Self::AmountExceedsMaximum { .. } => {
                StatusCode::BAD_REQUEST
            },
            Self::InsufficientFunds { .. } => StatusCode::PRECONDITION_FAILED,
            Self::NotReady(_) => StatusCode::SERVICE_UNAVAILABLE,
            // The request may be sent again as it is: no note was created.
            Self::TransactionExpired { .. } | Self::TransactionRejected(_) => StatusCode::CONFLICT,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

/// The body of a failed funding request.
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    /// The reason the request failed.
    pub error: String,
}

impl IntoResponse for RequestFundsError {
    fn into_response(self) -> Response {
        // An internal error may hold details about the service's own state, so the client only
        // receives a fixed message. The full report is logged by the worker.
        let error = match &self {
            Self::Internal(_) => "internal error".to_owned(),
            other => other.as_report(),
        };

        (self.status_code(), Json(ErrorResponse { error })).into_response()
    }
}
