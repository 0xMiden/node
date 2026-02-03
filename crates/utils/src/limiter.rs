//! Limits for RPC and store parameters and payload sizes.
//!
//! # Rationale
//! - Parameter limits are kept across all multi-value RPC parameters. This caps worst-case SQL `IN`
//!   clauses and keeps responses comfortably under the 4 MiB payload budget enforced in the store.
//! - Limits are enforced both at the RPC boundary and inside the store to prevent bypasses and to
//!   avoid expensive queries even if validation is skipped earlier in the stack.
//! - `MAX_PAGINATED_PAYLOAD_BYTES` is set to 4 MiB (e.g. 1000 nullifier rows at ~36 B each, 1000
//!   transactions summaries streamed in chunks).
//!
//! Add new limits here so callers share the same values and rationale.

/// Basic request limit.
pub const GENERAL_REQUEST_LIMIT: usize = 1000;

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
#[error("parameter {which} exceeded limit {limit}: {size}")]
pub struct QueryLimitError {
    which: &'static str,
    size: usize,
    limit: usize,
}

/// Checks limits against the desired query parameters, per query parameter and
/// bails if they exceed a defined value.
pub trait QueryParamLimiter {
    /// Name of the parameter to mention in the error.
    const PARAM_NAME: &'static str;
    /// Limit that causes a bail if exceeded.
    const LIMIT: usize;
    /// Do the actual check.
    fn check(size: usize) -> Result<(), QueryLimitError> {
        if size > Self::LIMIT {
            Err(QueryLimitError {
                which: Self::PARAM_NAME,
                size,
                limit: Self::LIMIT,
            })?;
        }
        Ok(())
    }
}

/// Maximum payload size (in bytes) for paginated responses returned by the
/// store.
pub const MAX_RESPONSE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Used for the following RPC endpoints
/// * `state_sync`
///
/// Capped at 1000 account IDs to keep SQL `IN` clauses bounded and response payloads under the
/// 4 MB budget.
pub struct QueryParamAccountIdLimit;
impl QueryParamLimiter for QueryParamAccountIdLimit {
    const PARAM_NAME: &str = "account_id";
    const LIMIT: usize = GENERAL_REQUEST_LIMIT;
}

/// Used for the following RPC endpoints
/// * `select_nullifiers_by_prefix`
///
/// Capped at 1000 prefixes to keep queries and responses comfortably within the 4 MB payload
/// budget and to avoid unbounded prefix scans.
pub struct QueryParamNullifierPrefixLimit;
impl QueryParamLimiter for QueryParamNullifierPrefixLimit {
    const PARAM_NAME: &str = "nullifier_prefix";
    const LIMIT: usize = GENERAL_REQUEST_LIMIT;
}

/// Used for the following RPC endpoints
/// * `select_nullifiers_by_prefix`
/// * `sync_nullifiers`
/// * `sync_state`
///
/// Capped at 1000 nullifiers to bound `IN` clauses and keep response sizes under the 4 MB budget.
pub struct QueryParamNullifierLimit;
impl QueryParamLimiter for QueryParamNullifierLimit {
    const PARAM_NAME: &str = "nullifier";
    const LIMIT: usize = GENERAL_REQUEST_LIMIT;
}

/// Used for the following RPC endpoints
/// * `get_note_sync`
///
/// Capped at 1000 tags so note sync responses remain within the 4 MB payload budget.
pub struct QueryParamNoteTagLimit;
impl QueryParamLimiter for QueryParamNoteTagLimit {
    const PARAM_NAME: &str = "note_tag";
    const LIMIT: usize = GENERAL_REQUEST_LIMIT;
}

/// Used for the following RPC endpoints
/// `select_notes_by_id`
///
/// The limit is set to 100 notes to keep responses within the 4 MiB payload cap because individual
/// notes are bounded to roughly 32 KiB.
pub struct QueryParamNoteIdLimit;
impl QueryParamLimiter for QueryParamNoteIdLimit {
    const PARAM_NAME: &str = "note_id";
    const LIMIT: usize = 100;
}

/// Used for internal queries retrieving note inclusion proofs by commitment.
///
/// Capped at 1000 commitments to keep internal proof lookups bounded and responses under the 4 MB
/// payload cap.
pub struct QueryParamNoteCommitmentLimit;
impl QueryParamLimiter for QueryParamNoteCommitmentLimit {
    const PARAM_NAME: &str = "note_commitment";
    const LIMIT: usize = GENERAL_REQUEST_LIMIT;
}

/// Only used internally, not exposed via public RPC.
///
/// Capped at 1000 block headers to bound internal batch operations and keep payloads below the
/// 4 MB limit.
pub struct QueryParamBlockLimit;
impl QueryParamLimiter for QueryParamBlockLimit {
    const PARAM_NAME: &str = "block_header";
    const LIMIT: usize = GENERAL_REQUEST_LIMIT;
}

/// Used for the following RPC endpoints
/// * `get_account`
///
/// Capped at 64 total storage map keys across all slots to limit the number of SMT proofs
/// returned.
pub struct QueryParamStorageMapKeyTotalLimit;
impl QueryParamLimiter for QueryParamStorageMapKeyTotalLimit {
    const PARAM_NAME: &str = "storage_map_key";
    const LIMIT: usize = 64;
}
