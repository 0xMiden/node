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
///
/// The block at the chain tip can still be replaced. A replacement gives the positions in that
/// block to its own transactions, so the rows of the tip block are provisional. A sweep that needs
/// final rows must set `block_to` below the reported `chain_tip`, or must read the tip block again
/// from its first position after the tip advances.
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
            record: item.record.map(Into::into),
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
    /// Highest block this validator has signed, so a caller can tell whether it has caught up. This
    /// block can still be replaced, so its rows are provisional.
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
    let page = service
        .reader
        .list_validated_transactions(ListTransactionsParams {
            start,
            block_to: query.block_to.map(BlockNumber::from),
            limit,
            include_records: query.include_records,
        })
        .await
        .map_err(|error| {
            ApiError::internal("failed to list validated private transactions", &error)
        })?;

    let chain_tip = page.chain_tip.as_u32();
    let block_num = page.transactions.last().map(|item| item.block_num.as_u32());
    let block_tx_index = page.transactions.last().map(|item| item.block_tx_index);

    Ok(Json(ListValidatedPrivateTransactionsResponse {
        transactions: page.transactions.into_iter().map(Into::into).collect(),
        pagination: PaginationInfo { chain_tip, block_num, block_tx_index },
    }))
}
