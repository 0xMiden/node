//! Paginated listing of committed validated transactions.

use axum::Json;
use axum::extract::{Query, State};
use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::Serializable;
use serde::{Deserialize, Serialize};

use crate::StoredPrivateRecord;
use crate::db::{ListTransactionsParams, ListedTransaction};
use crate::server::admin_service::ValidatorAdminService;
use crate::server::admin_service::error::ApiError;

/// Page size used when a listing request does not specify one.
pub(super) const DEFAULT_PAGE_LIMIT: usize = 100;
/// Maximum page size for metadata-only listing pages.
pub(super) const MAX_PAGE_LIMIT: usize = 1000;
/// Maximum page size when full sealed records are included; records carry the encrypted transaction
/// inputs, so record pages are kept small.
pub(super) const MAX_RECORD_PAGE_LIMIT: usize = 100;

/// Query parameters of the listing endpoint.
///
/// `block_from`/`block_to` restrict results to the inclusive block range, and
/// `(block_from, tx_index_from)` is the pagination cursor: a response reports the position of the
/// last row it included, and the next page is the same request resumed one position past it. Only
/// committed transactions are listed; ones that are still in flight, that were never included in a
/// signed block, or that predate block linkage have no place in the committed order and are
/// reachable by transaction id instead.
#[derive(Debug, Default, Deserialize)]
pub(super) struct ListTransactionsQuery {
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) include_records: bool,
    pub(super) block_from: Option<u32>,
    /// Index within `block_from` to resume at; requires `block_from`.
    pub(super) tx_index_from: Option<u32>,
    pub(super) block_to: Option<u32>,
}

/// Metadata identifying one validated transaction. The full sealed record is attached only when the
/// request opts in with `include_records=true`.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct ListedValidatedTransaction {
    pub(super) transaction_id: String,
    /// Block that includes this transaction.
    pub(super) block_num: u32,
    /// Index of this transaction within its block. Together with `block_num` this is the
    /// transaction's position in the committed order.
    pub(super) block_tx_index: u32,
    pub(super) key_epoch: String,
    pub(super) setup_context_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record: Option<PrivateRecordPayload>,
}

impl From<ListedTransaction> for ListedValidatedTransaction {
    fn from(item: ListedTransaction) -> Self {
        Self {
            transaction_id: hex::encode(item.transaction_id.to_bytes()),
            block_num: item.block_num.as_u32(),
            block_tx_index: item.block_tx_index,
            key_epoch: hex::encode(item.key_epoch.as_bytes()),
            setup_context_id: hex::encode(item.setup_context_id),
            record: None,
        }
    }
}

/// The sealed private record of one validated transaction.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct PrivateRecordPayload {
    pub(super) final_ciphertext: String,
    pub(super) cipher_nonce: String,
    pub(super) encrypted_record_key: String,
    pub(super) decryption_context: String,
}

impl From<StoredPrivateRecord> for PrivateRecordPayload {
    fn from(record: StoredPrivateRecord) -> Self {
        Self {
            final_ciphertext: hex::encode(record.encrypted_record()),
            cipher_nonce: hex::encode(record.nonce()),
            encrypted_record_key: hex::encode(record.encrypted_record_key()),
            decryption_context: hex::encode(record.context().to_bytes()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct ListValidatedPrivateTransactionsResponse {
    pub(super) transactions: Vec<ListedValidatedTransaction>,
    pub(super) pagination: PaginationInfo,
}

/// How far the sweep got, mirroring the `PaginationInfo` message the node's sync RPCs return.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct PaginationInfo {
    /// Highest block this validator has signed, so a caller can tell whether it has caught up.
    pub(super) chain_tip: u32,
    /// Block of the last transaction in this response. To request the next page, repeat the request
    /// with `block_from` set to this and `tx_index_from` set to `block_tx_index + 1`. `null` when
    /// the page is empty, which is how a sweep ends.
    pub(super) block_num: Option<u32>,
    /// Index within `block_num` of the last transaction in this response. `null` when the page is
    /// empty.
    pub(super) block_tx_index: Option<u32>,
}

pub(super) async fn list_validated_private_transactions(
    State(service): State<ValidatorAdminService>,
    Query(query): Query<ListTransactionsQuery>,
) -> Result<Json<ListValidatedPrivateTransactionsResponse>, ApiError> {
    let max_limit = if query.include_records {
        MAX_RECORD_PAGE_LIMIT
    } else {
        MAX_PAGE_LIMIT
    };
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit == 0 || limit > max_limit {
        return Err(ApiError::bad_request(format!("limit must be between 1 and {max_limit}")));
    }
    if query.tx_index_from.is_some() && query.block_from.is_none() {
        return Err(ApiError::bad_request("tx_index_from requires block_from"));
    }
    if let (Some(from), Some(to)) = (query.block_from, query.block_to)
        && from > to
    {
        return Err(ApiError::bad_request("block_from must not exceed block_to"));
    }

    let start = query
        .block_from
        .map(|from| (BlockNumber::from(from), query.tx_index_from.unwrap_or(0)));
    let transactions = service
        .reader
        .list_validated_transactions(ListTransactionsParams {
            start,
            block_to: query.block_to.map(BlockNumber::from),
            limit,
        })
        .await
        .map_err(|_error| ApiError::internal("failed to list validated private transactions"))?;

    // Read the tip after the page, so it can never come back older than a block the page lists. A
    // validator that has signed nothing reports 0, matching how `load_initial_metrics` treats it.
    let chain_tip = service
        .reader
        .load_chain_tip()
        .await
        .map_err(|_error| ApiError::internal("failed to load the chain tip"))?
        .map_or(0, |header| header.block_num().as_u32());
    // The position of the last row is exactly what the next page resumes one past.
    let block_num = transactions.last().map(|item| item.block_num.as_u32());
    let block_tx_index = transactions.last().map(|item| item.block_tx_index);

    let mut listed = Vec::with_capacity(transactions.len());
    for item in transactions {
        let transaction_id = item.transaction_id;
        let mut listed_item = ListedValidatedTransaction::from(item);
        if query.include_records {
            // Every listed transaction references a validated record via a foreign key and records
            // are never deleted, so a missing record is an internal inconsistency.
            let record = service
                .reader
                .load_private_record(transaction_id)
                .await
                .map_err(|_error| ApiError::internal("failed to load a private record"))?
                .ok_or_else(|| {
                    ApiError::internal("a listed transaction's private record is missing")
                })?;
            listed_item.record = Some(record.into());
        }
        listed.push(listed_item);
    }

    Ok(Json(ListValidatedPrivateTransactionsResponse {
        transactions: listed,
        pagination: PaginationInfo { chain_tip, block_num, block_tx_index },
    }))
}
