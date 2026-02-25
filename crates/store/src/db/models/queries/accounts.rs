use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use diesel::prelude::{Queryable, QueryableByName};
use diesel::query_dsl::methods::SelectDsl;
use diesel::sqlite::Sqlite;
use diesel::{
    AsChangeset,
    BoolExpressionMethods,
    ExpressionMethods,
    Insertable,
    OptionalExtension,
    QueryDsl,
    RunQueryDsl,
    Selectable,
    SelectableHelper,
    SqliteConnection,
};
use miden_node_proto::domain::account::{AccountInfo, AccountSummary};
use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountId,
    AccountStorage,
    AccountStorageHeader,
    NonFungibleDeltaAction,
    StorageMap,
    StorageSlot,
    StorageSlotContent,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{Asset, AssetVault, AssetVaultKey, FungibleAsset};
use miden_protocol::block::{BlockAccountUpdate, BlockNumber};
use miden_protocol::utils::{Deserializable, Serializable};
use miden_protocol::{Felt, Word};

use crate::COMPONENT;
use crate::db::models::conv::{SqlTypeConvert, nonce_to_raw_sql, raw_sql_to_nonce};
#[cfg(test)]
use crate::db::models::vec_raw_try_into;
use crate::db::{AccountVaultValue, schema};
use crate::errors::DatabaseError;

mod at_block;
pub(crate) use at_block::{
    select_account_header_with_storage_header_at_block,
    select_account_vault_at_block,
};

mod delta;
use delta::{
    AccountStateForInsert,
    PartialAccountState,
    apply_storage_delta,
    select_minimal_account_state_headers,
    select_vault_balances_by_faucet_ids,
};

#[cfg(test)]
mod tests;

type StorageMapValueRow = (i64, String, Vec<u8>, Vec<u8>);
type StorageHeaderWithEntries =
    (AccountStorageHeader, BTreeMap<StorageSlotName, BTreeMap<Word, Word>>);

// NETWORK ACCOUNT TYPE
// ================================================================================================

/// Classifies accounts for database storage based on whether they are network accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkAccountType {
    /// Not a network account.
    None,
    /// A network account.
    Network,
}

// ACCOUNT CODE
// ================================================================================================

/// Select account code by its commitment hash from the `account_codes` table.
///
/// # Returns
///
/// The account code bytes if found, or `None` if no code exists with that commitment.
///
/// # Raw SQL
///
/// ```sql
/// SELECT code FROM account_codes WHERE code_commitment = ?1
/// ```
pub(crate) fn select_account_code_by_commitment(
    conn: &mut SqliteConnection,
    code_commitment: Word,
) -> Result<Option<Vec<u8>>, DatabaseError> {
    use schema::account_codes;

    let code_commitment_bytes = code_commitment.to_bytes();

    let result: Option<Vec<u8>> = SelectDsl::select(
        account_codes::table.filter(account_codes::code_commitment.eq(&code_commitment_bytes)),
        account_codes::code,
    )
    .first(conn)
    .optional()?;

    Ok(result)
}

// ACCOUNT RETRIEVAL
// ================================================================================================

/// Select account by ID from the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// The latest account info, or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     accounts.account_id,
///     accounts.account_commitment,
///     accounts.block_num
/// FROM
///     accounts
/// WHERE
///     account_id = ?1
///     AND is_latest = 1
/// ```
pub(crate) fn select_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<AccountInfo, DatabaseError> {
    let raw = SelectDsl::select(schema::accounts::table, AccountSummaryRaw::as_select())
        .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
        .filter(schema::accounts::is_latest.eq(true))
        .get_result::<AccountSummaryRaw>(conn)
        .optional()?
        .ok_or(DatabaseError::AccountNotFoundInDb(account_id))?;

    let summary: AccountSummary = raw.try_into()?;

    // Backfill account details from database
    // For private accounts, we don't store full details in the database
    let details = if account_id.has_public_state() {
        Some(select_full_account(conn, account_id)?)
    } else {
        None
    };

    Ok(AccountInfo { summary, details })
}

/// Reconstruct full Account from database tables for the latest account state
///
/// This function queries the database tables to reconstruct a complete Account object:
/// - Code from `account_codes` table
/// - Nonce and storage header from `accounts` table
/// - Storage map entries from `account_storage_map_values` table
/// - Vault from `account_vault_assets` table
///
/// # Note
///
/// A stop-gap solution to retain store API and construct `AccountInfo` types.
/// The function should ultimately be removed, and any queries be served from the
/// `State` which contains an `SmtForest` to serve the latest and most recent
/// historical data.
// TODO: remove eventually once refactoring is complete
pub(crate) fn select_full_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Account, DatabaseError> {
    // Get account metadata (nonce, code_commitment) and code in a single join query
    let (nonce, code_bytes): (Option<i64>, Vec<u8>) = SelectDsl::select(
        schema::accounts::table.inner_join(schema::account_codes::table),
        (schema::accounts::nonce, schema::account_codes::code),
    )
    .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
    .filter(schema::accounts::is_latest.eq(true))
    .get_result(conn)
    .optional()?
    .ok_or(DatabaseError::AccountNotFoundInDb(account_id))?;

    let nonce = raw_sql_to_nonce(nonce.ok_or_else(|| {
        DatabaseError::DataCorrupted(format!("No nonce found for account {account_id}"))
    })?);

    let code = AccountCode::read_from_bytes(&code_bytes)?;

    // Reconstruct storage using existing helper function
    let storage = select_latest_account_storage(conn, account_id)?;

    // Reconstruct vault from account_vault_assets table
    let vault_entries: Vec<(Vec<u8>, Option<Vec<u8>>)> = SelectDsl::select(
        schema::account_vault_assets::table,
        (schema::account_vault_assets::vault_key, schema::account_vault_assets::asset),
    )
    .filter(schema::account_vault_assets::account_id.eq(account_id.to_bytes()))
    .filter(schema::account_vault_assets::is_latest.eq(true))
    .load(conn)?;

    let mut assets = Vec::new();
    for (_key_bytes, maybe_asset_bytes) in vault_entries {
        if let Some(asset_bytes) = maybe_asset_bytes {
            let asset = Asset::read_from_bytes(&asset_bytes)?;
            assets.push(asset);
        }
    }

    let vault = AssetVault::new(&assets)?;

    Ok(Account::new(account_id, vault, storage, code, nonce, None)?)
}

/// Select the latest account info for a network account by its full account ID.
///
/// # Returns
///
/// The latest account info, `None` if the account was not found, or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     accounts.account_id,
///     accounts.account_commitment,
///     accounts.block_num
/// FROM
///     accounts
/// WHERE
///     account_id = ?1
///     AND network_account_type = 1
///     AND is_latest = 1
/// ```
pub(crate) fn select_network_account_by_id(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Option<AccountInfo>, DatabaseError> {
    let maybe_summary = SelectDsl::select(schema::accounts::table, AccountSummaryRaw::as_select())
        .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
        .filter(schema::accounts::network_account_type.eq(NetworkAccountType::Network.to_raw_sql()))
        .filter(schema::accounts::is_latest.eq(true))
        .get_result::<AccountSummaryRaw>(conn)
        .optional()
        .map_err(DatabaseError::Diesel)?;

    match maybe_summary {
        None => Ok(None),
        Some(raw) => {
            let summary: AccountSummary = raw.try_into()?;
            let account_id = summary.account_id;
            // Backfill account details from database
            let details = select_full_account(conn, account_id).ok();
            Ok(Some(AccountInfo { summary, details }))
        },
    }
}

/// Page of account commitments returned by [`select_account_commitments_paged`].
#[derive(Debug)]
pub struct AccountCommitmentsPage {
    /// The account commitments in this page.
    pub commitments: Vec<(AccountId, Word)>,
    /// If `Some`, there are more results. Use this as the `after_account_id` for the next page.
    pub next_cursor: Option<AccountId>,
}

/// Selects account commitments with pagination.
///
/// Returns up to `page_size` account commitments, starting after `after_account_id` if provided.
/// Results are ordered by `account_id` for stable pagination.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     account_id,
///     account_commitment
/// FROM
///     accounts
/// WHERE
///     is_latest = 1
///     AND (account_id > :after_account_id OR :after_account_id IS NULL)
/// ORDER BY
///     account_id ASC
/// LIMIT :page_size + 1
/// ```
pub(crate) fn select_account_commitments_paged(
    conn: &mut SqliteConnection,
    page_size: NonZeroUsize,
    after_account_id: Option<AccountId>,
) -> Result<AccountCommitmentsPage, DatabaseError> {
    use miden_protocol::utils::Serializable;

    // Fetch one extra to determine if there are more results
    #[expect(clippy::cast_possible_wrap)]
    let limit = (page_size.get() + 1) as i64;

    let mut query = SelectDsl::select(
        schema::accounts::table,
        (schema::accounts::account_id, schema::accounts::account_commitment),
    )
    .filter(schema::accounts::is_latest.eq(true))
    .order_by(schema::accounts::account_id.asc())
    .limit(limit)
    .into_boxed();

    if let Some(cursor) = after_account_id {
        query = query.filter(schema::accounts::account_id.gt(cursor.to_bytes()));
    }

    let raw = query.load::<(Vec<u8>, Vec<u8>)>(conn)?;

    let mut commitments = Result::<Vec<_>, DatabaseError>::from_iter(raw.into_iter().map(
        |(ref account, ref commitment)| {
            Ok((AccountId::read_from_bytes(account)?, Word::read_from_bytes(commitment)?))
        },
    ))?;

    // If we got more than page_size, there are more results
    let next_cursor = if commitments.len() > page_size.get() {
        commitments.pop(); // Remove the extra element
        commitments.last().map(|(id, _)| *id)
    } else {
        None
    };

    Ok(AccountCommitmentsPage { commitments, next_cursor })
}

/// Page of public account IDs returned by [`select_public_account_ids_paged`].
#[derive(Debug)]
pub struct PublicAccountIdsPage {
    /// The public account IDs in this page.
    pub account_ids: Vec<AccountId>,
    /// If `Some`, there are more results. Use this as the `after_account_id` for the next page.
    pub next_cursor: Option<AccountId>,
}

/// Selects public account IDs with pagination.
///
/// Returns up to `page_size` public account IDs, starting after `after_account_id` if provided.
/// Results are ordered by `account_id` for stable pagination.
///
/// Public accounts are those with `AccountStorageMode::Public` or `AccountStorageMode::Network`.
/// We identify them by checking `code_commitment IS NOT NULL` - public accounts store their full
/// state (including `code_commitment`), while private accounts only store the `account_commitment`.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     account_id
/// FROM
///     accounts
/// WHERE
///     is_latest = 1
///     AND code_commitment IS NOT NULL
///     AND (account_id > :after_account_id OR :after_account_id IS NULL)
/// ORDER BY
///     account_id ASC
/// LIMIT :page_size + 1
/// ```
pub(crate) fn select_public_account_ids_paged(
    conn: &mut SqliteConnection,
    page_size: NonZeroUsize,
    after_account_id: Option<AccountId>,
) -> Result<PublicAccountIdsPage, DatabaseError> {
    use miden_protocol::utils::Serializable;

    #[expect(clippy::cast_possible_wrap)]
    let limit = (page_size.get() + 1) as i64;

    let mut query = SelectDsl::select(schema::accounts::table, schema::accounts::account_id)
        .filter(schema::accounts::is_latest.eq(true))
        .filter(schema::accounts::code_commitment.is_not_null())
        .order_by(schema::accounts::account_id.asc())
        .limit(limit)
        .into_boxed();

    if let Some(cursor) = after_account_id {
        query = query.filter(schema::accounts::account_id.gt(cursor.to_bytes()));
    }

    let raw = query.load::<Vec<u8>>(conn)?;

    let mut account_ids: Vec<AccountId> = Result::from_iter(raw.into_iter().map(|bytes| {
        AccountId::read_from_bytes(&bytes).map_err(DatabaseError::DeserializationError)
    }))?;

    // If we got more than page_size, there are more results
    let next_cursor = if account_ids.len() > page_size.get() {
        account_ids.pop(); // Remove the extra element
        account_ids.last().copied()
    } else {
        None
    };

    Ok(PublicAccountIdsPage { account_ids, next_cursor })
}

/// Select account vault assets within a block range (inclusive).
///
/// # Parameters
/// * `account_id`: Account ID to query
/// * `block_from`: Starting block number
/// * `block_to`: Ending block number
/// * Response payload size: 0 <= size <= 2MB
/// * Vault assets per response: 0 <= count <= (2MB / (2*Word + u32)) + 1
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     block_num,
///     vault_key,
///     asset
/// FROM
///     account_vault_assets
/// WHERE
///     account_id = ?1
///     AND block_num >= ?2
///     AND block_num <= ?3
/// ORDER BY
///     block_num ASC
/// LIMIT
///     ?4
/// ```
pub(crate) fn select_account_vault_assets(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
) -> Result<(BlockNumber, Vec<AccountVaultValue>), DatabaseError> {
    use schema::account_vault_assets as t;
    // TODO: These limits should be given by the protocol.
    // See miden-base/issues/1770 for more details
    const ROW_OVERHEAD_BYTES: usize = 2 * size_of::<Word>() + size_of::<u32>(); // key + asset + block_num
    const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

    if !account_id.is_public() {
        return Err(DatabaseError::AccountNotPublic(account_id));
    }

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    let raw: Vec<(i64, Vec<u8>, Option<Vec<u8>>)> =
        SelectDsl::select(t::table, (t::block_num, t::vault_key, t::asset))
            .filter(
                t::account_id
                    .eq(account_id.to_bytes())
                    .and(t::block_num.ge(block_range.start().to_raw_sql()))
                    .and(t::block_num.le(block_range.end().to_raw_sql())),
            )
            .order(t::block_num.asc())
            .limit(i64::try_from(MAX_ROWS + 1).expect("should fit within i64"))
            .load::<(i64, Vec<u8>, Option<Vec<u8>>)>(conn)?;

    // Discard the last block in the response (assumes more than one block may be present)
    let (last_block_included, values) = if let Some(&(last_block_num, ..)) = raw.last()
        && raw.len() > MAX_ROWS
    {
        // NOTE: If the query contains at least one more row than the amount of storage map updates
        // allowed in a single block for an account, then the response is guaranteed to have at
        // least two blocks

        let values = raw
            .into_iter()
            .take_while(|(bn, ..)| *bn != last_block_num)
            .map(AccountVaultValue::from_raw_row)
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        (BlockNumber::from_raw_sql(last_block_num.saturating_sub(1))?, values)
    } else {
        (
            *block_range.end(),
            raw.into_iter().map(AccountVaultValue::from_raw_row).collect::<Result<_, _>>()?,
        )
    };

    Ok((last_block_included, values))
}

/// Select all accounts from the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// A vector with accounts, or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     accounts.account_id,
///     accounts.account_commitment,
///     accounts.block_num
/// FROM
///     accounts
/// WHERE
///     is_latest = 1
/// ORDER BY
///     block_num ASC
/// ```
#[cfg(test)]
pub(crate) fn select_all_accounts(
    conn: &mut SqliteConnection,
) -> Result<Vec<AccountInfo>, DatabaseError> {
    let raw = SelectDsl::select(schema::accounts::table, AccountSummaryRaw::as_select())
        .filter(schema::accounts::is_latest.eq(true))
        .order_by(schema::accounts::block_num.asc())
        .load::<AccountSummaryRaw>(conn)?;

    let summaries: Vec<AccountSummary> = vec_raw_try_into(raw)?;

    // Backfill account details from database
    let account_infos = summaries
        .into_iter()
        .map(|summary| {
            let account_id = summary.account_id;
            let details = select_full_account(conn, account_id).ok();
            AccountInfo { summary, details }
        })
        .collect();

    Ok(account_infos)
}

/// Returns network account IDs within the specified block range (based on account creation
/// block).
///
/// The function may return fewer accounts than exist in the range if the result would exceed
/// `MAX_RESPONSE_PAYLOAD_BYTES / AccountId::SERIALIZED_SIZE` rows. In this case, the result is
/// truncated at a block boundary to ensure all accounts from included blocks are returned.
///
/// # Returns
///
/// A tuple containing:
/// - A vector of network account IDs.
/// - The last block number that was fully included in the result. When truncated, this will be less
///   than the requested range end.
pub(crate) fn select_all_network_account_ids(
    conn: &mut SqliteConnection,
    block_range: RangeInclusive<BlockNumber>,
) -> Result<(Vec<AccountId>, BlockNumber), DatabaseError> {
    const ROW_OVERHEAD_BYTES: usize = AccountId::SERIALIZED_SIZE;
    const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

    const _: () = assert!(
        MAX_ROWS > miden_protocol::MAX_ACCOUNTS_PER_BLOCK,
        "Block pagination limit must exceed maximum block capacity to uphold assumed logic invariant"
    );

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    let account_ids_raw: Vec<(Vec<u8>, i64)> = Box::new(
        QueryDsl::select(
            schema::accounts::table
                .filter(
                    schema::accounts::network_account_type
                        .eq(NetworkAccountType::Network.to_raw_sql()),
                )
                .filter(schema::accounts::is_latest.eq(true)),
            (schema::accounts::account_id, schema::accounts::created_at_block),
        )
        .filter(
            schema::accounts::block_num
                .between(block_range.start().to_raw_sql(), block_range.end().to_raw_sql()),
        )
        .order(schema::accounts::created_at_block.asc())
        .limit(i64::try_from(MAX_ROWS + 1).expect("limit fits within i64")),
    )
    .load::<(Vec<u8>, i64)>(conn)?;

    if account_ids_raw.len() > MAX_ROWS {
        // SAFETY: We just checked that len > MAX_ROWS, so the vec is not empty.
        let last_created_at_block = account_ids_raw.last().expect("vec is not empty").1;

        let account_ids = account_ids_raw
            .into_iter()
            .take_while(|(_, created_at_block)| *created_at_block != last_created_at_block)
            .map(|(id_bytes, _)| {
                AccountId::read_from_bytes(&id_bytes).map_err(DatabaseError::DeserializationError)
            })
            .collect::<Result<Vec<AccountId>, DatabaseError>>()?;

        let last_block_included =
            BlockNumber::from_raw_sql(last_created_at_block.saturating_sub(1))?;

        Ok((account_ids, last_block_included))
    } else {
        let account_ids = account_ids_raw
            .into_iter()
            .map(|(id_bytes, _)| {
                AccountId::read_from_bytes(&id_bytes).map_err(DatabaseError::DeserializationError)
            })
            .collect::<Result<Vec<AccountId>, DatabaseError>>()?;

        Ok((account_ids, *block_range.end()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValue {
    pub block_num: BlockNumber,
    pub slot_name: StorageSlotName,
    pub key: Word,
    pub value: Word,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValuesPage {
    /// Highest block number included in `rows`. If the page is empty, this will be `block_from`.
    pub last_block_included: BlockNumber,
    /// Storage map values
    pub values: Vec<StorageMapValue>,
}

impl StorageMapValue {
    pub fn from_raw_row(row: StorageMapValueRow) -> Result<Self, DatabaseError> {
        let (block_num, slot_name, key, value) = row;
        Ok(Self {
            block_num: BlockNumber::from_raw_sql(block_num)?,
            slot_name: StorageSlotName::from_raw_sql(slot_name)?,
            key: Word::read_from_bytes(&key)?,
            value: Word::read_from_bytes(&value)?,
        })
    }
}

/// Select account storage map values from the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// A vector of tuples containing `(slot, key, value, is_latest)` for the given account.
/// Each row contains one of:
///
/// - the historical value for a slot and key specifically on block `block_to`
/// - the latest updated value for the slot and key combination, alongside the block number in which
///   it was updated
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     block_num,
///     slot,
///     key,
///     value
/// FROM
///     account_storage_map_values
/// WHERE
///     account_id = ?1
///     AND block_num >= ?2
///     AND block_num <= ?3
/// ORDER BY
///     block_num ASC
/// LIMIT
///     ?4
/// ```
/// Select account storage map values within a block range (inclusive).
///
/// ## Parameters
///
/// * `account_id`: Account ID to query
/// * `block_range`: Range of block numbers (inclusive)
///
/// ## Response
///
/// * Response payload size: 0 <= size <= 2MB
/// * Storage map values per response: 0 <= count <= (2MB / (2*Word + u32 + u8)) + 1
pub(crate) fn select_account_storage_map_values(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
) -> Result<StorageMapValuesPage, DatabaseError> {
    use schema::account_storage_map_values as t;

    // TODO: These limits should be given by the protocol.
    // See miden-base/issues/1770 for more details
    pub const ROW_OVERHEAD_BYTES: usize =
        2 * size_of::<Word>() + size_of::<u32>() + size_of::<u8>(); // key + value + block_num + slot_idx
    pub const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

    if !account_id.is_public() {
        return Err(DatabaseError::AccountNotPublic(account_id));
    }

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    let raw: Vec<StorageMapValueRow> =
        SelectDsl::select(t::table, (t::block_num, t::slot_name, t::key, t::value))
            .filter(
                t::account_id
                    .eq(account_id.to_bytes())
                    .and(t::block_num.ge(block_range.start().to_raw_sql()))
                    .and(t::block_num.le(block_range.end().to_raw_sql())),
            )
            .order(t::block_num.asc())
            .limit(i64::try_from(MAX_ROWS + 1).expect("limit fits within i64"))
            .load(conn)?;

    // Discard the last block in the response (assumes more than one block may be present)

    let (last_block_included, values) = if let Some(&(last_block_num, ..)) = raw.last()
        && raw.len() > MAX_ROWS
    {
        // NOTE: If the query contains at least one more row than the amount of storage map updates
        // allowed in a single block for an account, then the response is guaranteed to have at
        // least two blocks

        let values = raw
            .into_iter()
            .take_while(|(bn, ..)| *bn != last_block_num)
            .map(StorageMapValue::from_raw_row)
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        (BlockNumber::from_raw_sql(last_block_num.saturating_sub(1))?, values)
    } else {
        (
            *block_range.end(),
            raw.into_iter().map(StorageMapValue::from_raw_row).collect::<Result<_, _>>()?,
        )
    };

    Ok(StorageMapValuesPage { last_block_included, values })
}

/// Select latest account storage by querying `accounts.storage_header` where `is_latest=true`
/// and reconstructing full storage from the header plus map values from
/// `account_storage_map_values`.
pub(crate) fn select_latest_account_storage(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<AccountStorage, DatabaseError> {
    let (storage_header, map_entries_by_slot) =
        select_latest_account_storage_components(conn, account_id)?;
    // Reconstruct StorageSlots from header slots + map entries
    let slots =
        Result::<Vec<_>, DatabaseError>::from_iter(storage_header.slots().map(|slot_header| {
            let slot = match slot_header.slot_type() {
                StorageSlotType::Value => {
                    // For value slots, the header value IS the slot value
                    StorageSlot::with_value(slot_header.name().clone(), slot_header.value())
                },
                StorageSlotType::Map => {
                    // For map slots, reconstruct from map entries
                    let entries =
                        map_entries_by_slot.get(slot_header.name()).cloned().unwrap_or_default();
                    let storage_map = StorageMap::with_entries(entries.into_iter())?;
                    StorageSlot::with_map(slot_header.name().clone(), storage_map)
                },
            };
            Ok(slot)
        }))?;

    Ok(AccountStorage::new(slots)?)
}

pub(crate) fn select_latest_account_storage_components(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<StorageHeaderWithEntries, DatabaseError> {
    let account_id_bytes = account_id.to_bytes();

    // Query storage header blob for this account where is_latest = true
    let storage_blob: Option<Vec<u8>> =
        SelectDsl::select(schema::accounts::table, schema::accounts::storage_header)
            .filter(schema::accounts::account_id.eq(&account_id_bytes))
            .filter(schema::accounts::is_latest.eq(true))
            .first(conn)
            .optional()?
            .flatten();

    let header = match storage_blob {
        Some(blob) => AccountStorageHeader::read_from_bytes(&blob)?,
        None => AccountStorageHeader::new(Vec::new())?,
    };

    let entries = select_latest_storage_map_entries_all(conn, &account_id)?;
    Ok((header, entries))
}

// TODO this is expensive and should only be called from tests
fn select_latest_storage_map_entries_all(
    conn: &mut SqliteConnection,
    account_id: &AccountId,
) -> Result<BTreeMap<StorageSlotName, BTreeMap<Word, Word>>, DatabaseError> {
    use schema::account_storage_map_values as t;

    let map_values: Vec<(String, Vec<u8>, Vec<u8>)> =
        SelectDsl::select(t::table, (t::slot_name, t::key, t::value))
            .filter(t::account_id.eq(&account_id.to_bytes()))
            .filter(t::is_latest.eq(true))
            .load(conn)?;

    group_storage_map_entries(map_values)
}

fn select_latest_storage_map_entries_for_slots(
    conn: &mut SqliteConnection,
    account_id: &AccountId,
    slot_names: &[StorageSlotName],
) -> Result<BTreeMap<StorageSlotName, BTreeMap<Word, Word>>, DatabaseError> {
    use schema::account_storage_map_values as t;

    if slot_names.is_empty() {
        return Ok(BTreeMap::new());
    }

    if let [slot_name] = slot_names {
        let entries = select_latest_storage_map_entries_for_slot(conn, account_id, slot_name)?;
        if entries.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut map_entries = BTreeMap::new();
        map_entries.insert(slot_name.clone(), entries);
        return Ok(map_entries);
    }

    let slot_names = Vec::from_iter(slot_names.iter().cloned().map(StorageSlotName::to_raw_sql));
    let map_values: Vec<(String, Vec<u8>, Vec<u8>)> =
        SelectDsl::select(t::table, (t::slot_name, t::key, t::value))
            .filter(t::account_id.eq(&account_id.to_bytes()))
            .filter(t::is_latest.eq(true))
            .filter(t::slot_name.eq_any(slot_names))
            .load(conn)?;

    group_storage_map_entries(map_values)
}

fn select_latest_storage_map_entries_for_slot(
    conn: &mut SqliteConnection,
    account_id: &AccountId,
    slot_name: &StorageSlotName,
) -> Result<BTreeMap<Word, Word>, DatabaseError> {
    use schema::account_storage_map_values as t;

    let map_values: Vec<(String, Vec<u8>, Vec<u8>)> =
        SelectDsl::select(t::table, (t::slot_name, t::key, t::value))
            .filter(t::account_id.eq(&account_id.to_bytes()))
            .filter(t::is_latest.eq(true))
            .filter(t::slot_name.eq(slot_name.clone().to_raw_sql()))
            .load(conn)?;

    Ok(group_storage_map_entries(map_values)?.remove(slot_name).unwrap_or_default())
}

fn group_storage_map_entries(
    map_values: Vec<(String, Vec<u8>, Vec<u8>)>,
) -> Result<BTreeMap<StorageSlotName, BTreeMap<Word, Word>>, DatabaseError> {
    let mut map_entries_by_slot: BTreeMap<StorageSlotName, BTreeMap<Word, Word>> = BTreeMap::new();
    for (slot_name_str, key_bytes, value_bytes) in map_values {
        let slot_name: StorageSlotName = slot_name_str.parse().map_err(|_| {
            DatabaseError::DataCorrupted(format!("Invalid slot name: {slot_name_str}"))
        })?;
        let key = Word::read_from_bytes(&key_bytes)?;
        let value = Word::read_from_bytes(&value_bytes)?;
        map_entries_by_slot.entry(slot_name).or_default().insert(key, value);
    }

    Ok(map_entries_by_slot)
}

// ACCOUNT MUTATION
// ================================================================================================

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::db::schema::account_vault_assets)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccountVaultUpdateRaw {
    pub vault_key: Vec<u8>,
    pub asset: Option<Vec<u8>>,
    pub block_num: i64,
}

impl TryFrom<AccountVaultUpdateRaw> for AccountVaultValue {
    type Error = DatabaseError;

    fn try_from(raw: AccountVaultUpdateRaw) -> Result<Self, Self::Error> {
        let vault_key = AssetVaultKey::new_unchecked(Word::read_from_bytes(&raw.vault_key)?);
        let asset = raw.asset.map(|bytes| Asset::read_from_bytes(&bytes)).transpose()?;
        let block_num = BlockNumber::from_raw_sql(raw.block_num)?;

        Ok(AccountVaultValue { block_num, vault_key, asset })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Selectable, Queryable, QueryableByName)]
#[diesel(table_name = schema::accounts)]
#[diesel(check_for_backend(Sqlite))]
pub struct AccountSummaryRaw {
    account_id: Vec<u8>,         // AccountId,
    account_commitment: Vec<u8>, //RpoDigest,
    block_num: i64,              //BlockNumber,
}

impl TryInto<AccountSummary> for AccountSummaryRaw {
    type Error = DatabaseError;
    fn try_into(self) -> Result<AccountSummary, Self::Error> {
        let account_id = AccountId::read_from_bytes(&self.account_id[..])?;
        let account_commitment = Word::read_from_bytes(&self.account_commitment[..])?;
        let block_num = BlockNumber::from_raw_sql(self.block_num)?;

        Ok(AccountSummary {
            account_id,
            account_commitment,
            block_num,
        })
    }
}

/// Insert an account vault asset row into the DB using the given [`SqliteConnection`].
///
/// Sets `is_latest=true` for the new row and updates any existing
/// row with the same `(account_id, vault_key)` tuple to `is_latest=false`.
///
/// # Returns
///
/// The number of affected rows.
pub(crate) fn insert_account_vault_asset(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    vault_key: AssetVaultKey,
    asset: Option<Asset>,
) -> Result<usize, DatabaseError> {
    let record = AccountAssetRowInsert::new(&account_id, &vault_key, block_num, asset, true);

    diesel::Connection::transaction(conn, |conn| {
        // First, update any existing rows with the same (account_id, vault_key) to set
        // is_latest=false
        let vault_key: Word = vault_key.into();
        let vault_key_bytes = vault_key.to_bytes();
        let account_id_bytes = account_id.to_bytes();
        let update_count = diesel::update(schema::account_vault_assets::table)
            .filter(
                schema::account_vault_assets::account_id
                    .eq(account_id_bytes)
                    .and(schema::account_vault_assets::vault_key.eq(vault_key_bytes))
                    .and(schema::account_vault_assets::is_latest.eq(true)),
            )
            .set(schema::account_vault_assets::is_latest.eq(false))
            .execute(conn)?;

        // Insert the new latest row
        let insert_count = diesel::insert_into(schema::account_vault_assets::table)
            .values(record)
            .execute(conn)?;

        Ok(update_count + insert_count)
    })
}

/// Insert an account storage map value into the DB using the given [`SqliteConnection`].
///
/// Sets `is_latest=true` for the new row and updates any existing
/// row with the same `(account_id, slot_index, key)` tuple to `is_latest=false`.
///
/// # Returns
///
/// The number of affected rows.
pub(crate) fn insert_account_storage_map_value(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    slot_name: StorageSlotName,
    key: Word,
    value: Word,
) -> Result<usize, DatabaseError> {
    let account_id = account_id.to_bytes();
    let key = key.to_bytes();
    let value = value.to_bytes();
    let slot_name = slot_name.to_raw_sql();
    let block_num = block_num.to_raw_sql();

    let update_count = diesel::update(schema::account_storage_map_values::table)
        .filter(
            schema::account_storage_map_values::account_id
                .eq(&account_id)
                .and(schema::account_storage_map_values::slot_name.eq(&slot_name))
                .and(schema::account_storage_map_values::key.eq(&key))
                .and(schema::account_storage_map_values::is_latest.eq(true)),
        )
        .set(schema::account_storage_map_values::is_latest.eq(false))
        .execute(conn)?;

    let record = AccountStorageMapRowInsert {
        account_id,
        key,
        value,
        slot_name,
        block_num,
        is_latest: true,
    };
    let insert_count = diesel::insert_into(schema::account_storage_map_values::table)
        .values(record)
        .execute(conn)?;

    Ok(update_count + insert_count)
}

/// Attention: Assumes the account details are NOT null! The schema explicitly allows this though!
#[expect(clippy::too_many_lines)]
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
)]
pub(crate) fn upsert_accounts(
    conn: &mut SqliteConnection,
    accounts: &[BlockAccountUpdate],
    block_num: BlockNumber,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    for update in accounts {
        let account_id = update.account_id();
        let account_id_bytes = account_id.to_bytes();
        let block_num_raw = block_num.to_raw_sql();

        let network_account_type = if account_id.is_network() {
            NetworkAccountType::Network
        } else {
            NetworkAccountType::None
        };

        // Preserve the original creation block when updating existing accounts.
        let created_at_block_raw = QueryDsl::select(
            schema::accounts::table.filter(
                schema::accounts::account_id
                    .eq(&account_id_bytes)
                    .and(schema::accounts::is_latest.eq(true)),
            ),
            schema::accounts::created_at_block,
        )
        .first::<i64>(conn)
        .optional()
        .map_err(DatabaseError::Diesel)?
        .unwrap_or(block_num_raw);
        let created_at_block = BlockNumber::from_raw_sql(created_at_block_raw)?;

        // NOTE: we collect storage / asset inserts to apply them only after the  account row is
        // written. The storage and vault tables have FKs pointing to `accounts (account_id,
        // block_num)`, so inserting them earlier would violate those constraints when inserting a
        // brand-new account.
        let (account_state, pending_storage_inserts, pending_asset_inserts) = match update.details()
        {
            AccountUpdateDetails::Private => (AccountStateForInsert::Private, vec![], vec![]),

            // New account is always a full account, but also comes as an update
            AccountUpdateDetails::Delta(delta) if delta.is_full_state() => {
                let account = Account::try_from(delta)?;
                debug_assert_eq!(account_id, account.id());

                if account.commitment() != update.final_state_commitment() {
                    return Err(DatabaseError::AccountCommitmentsMismatch {
                        calculated: account.commitment(),
                        expected: update.final_state_commitment(),
                    });
                }

                // collect storage-map inserts to apply after account upsert
                let mut storage = Vec::new();
                for slot in account.storage().slots() {
                    if let StorageSlotContent::Map(storage_map) = slot.content() {
                        for (key, value) in storage_map.entries() {
                            storage.push((account_id, slot.name().clone(), *key, *value));
                        }
                    }
                }

                // collect vault-asset inserts to apply after account upsert
                let mut assets = Vec::new();
                for asset in account.vault().assets() {
                    // Only insert assets with non-zero values for fungible assets
                    let should_insert = match asset {
                        Asset::Fungible(fungible) => fungible.amount() > 0,
                        Asset::NonFungible(_) => true,
                    };
                    if should_insert {
                        assets.push((account_id, asset.vault_key(), Some(asset)));
                    }
                }

                (AccountStateForInsert::FullAccount(account), storage, assets)
            },

            // Update of an existing account
            AccountUpdateDetails::Delta(delta) => {
                // Load only the minimal data needed. Only load those storage map entries and vault
                // entries that will receive updates.
                // The next line fetches the header, which will always change with the exception of
                // an empty delta.
                let state_headers = select_minimal_account_state_headers(conn, account_id)?;

                // --- process asset updates ----------------------------------
                // Only query balances for faucet_ids that are being updated
                let faucet_ids = Vec::from_iter(delta.vault().fungible().iter().map(|(id, _)| *id));
                let prev_balances =
                    select_vault_balances_by_faucet_ids(conn, account_id, &faucet_ids)?;

                let mut assets = Vec::new();

                // update fungible assets
                for (faucet_id, amount_delta) in delta.vault().fungible().iter() {
                    let prev_balance = prev_balances.get(faucet_id).copied().unwrap_or(0);
                    let new_balance = amount_delta
                        .checked_abs()
                        .and_then(|abs_delta| u64::try_from(abs_delta).ok())
                        .and_then(|abs_delta| match amount_delta.cmp(&0) {
                            std::cmp::Ordering::Greater => prev_balance.checked_add(abs_delta),
                            std::cmp::Ordering::Less => prev_balance.checked_sub(abs_delta),
                            std::cmp::Ordering::Equal => Some(prev_balance),
                        })
                        .ok_or_else(|| {
                            DatabaseError::DataCorrupted(format!(
                                "Balance underflow for account {account_id}, faucet {faucet_id}"
                            ))
                        })?;

                    let asset: Asset = FungibleAsset::new(*faucet_id, new_balance)?.into();
                    let update_or_remove = if new_balance == 0 { None } else { Some(asset) };
                    assets.push((account_id, asset.vault_key(), update_or_remove));
                }

                // update non-fungible assets
                for (asset, delta_action) in delta.vault().non_fungible().iter() {
                    let asset_update = match delta_action {
                        NonFungibleDeltaAction::Add => Some(Asset::NonFungible(*asset)),
                        NonFungibleDeltaAction::Remove => None,
                    };
                    assets.push((account_id, asset.vault_key(), asset_update));
                }

                // --- collect storage map updates ----------------------------

                let mut storage = Vec::new();
                for (slot_name, map_delta) in delta.storage().maps() {
                    for (key, value) in map_delta.entries() {
                        storage.push((account_id, slot_name.clone(), (*key).into(), *value));
                    }
                }

                let slot_names: Vec<StorageSlotName> = delta
                    .storage()
                    .maps()
                    .filter_map(|(slot_name, map_delta)| {
                        if map_delta.is_empty() {
                            None
                        } else {
                            Some(slot_name.clone())
                        }
                    })
                    .collect();

                let map_entries =
                    select_latest_storage_map_entries_for_slots(conn, &account_id, &slot_names)?;

                let new_storage_header = apply_storage_delta(
                    &state_headers.storage_header,
                    delta.storage(),
                    &map_entries,
                )?;

                let new_vault_root = {
                    let (_last_block, assets) = select_account_vault_assets(
                        conn,
                        account_id,
                        BlockNumber::GENESIS..=block_num,
                    )?;
                    let assets: Vec<Asset> =
                        assets.into_iter().filter_map(|entry| entry.asset).collect();
                    let mut vault = AssetVault::new(&assets)?;
                    vault.apply_delta(delta.vault())?;
                    vault.root()
                };

                // --- compute updated account state for the accounts row ---
                // Apply nonce delta
                let new_nonce_value = state_headers
                    .nonce
                    .as_int()
                    .checked_add(delta.nonce_delta().as_int())
                    .ok_or_else(|| {
                        DatabaseError::DataCorrupted(format!(
                            "Nonce overflow for account {account_id}"
                        ))
                    })?;
                let new_nonce = Felt::new(new_nonce_value);

                // Create minimal account state data for the row insert
                let account_state = PartialAccountState {
                    nonce: new_nonce,
                    code_commitment: state_headers.code_commitment,
                    storage_header: new_storage_header,
                    vault_root: new_vault_root,
                };

                let account_header = miden_protocol::account::AccountHeader::new(
                    account_id,
                    account_state.nonce,
                    account_state.vault_root,
                    account_state.storage_header.to_commitment(),
                    account_state.code_commitment,
                );

                if account_header.commitment() != update.final_state_commitment() {
                    return Err(DatabaseError::AccountCommitmentsMismatch {
                        calculated: account_header.commitment(),
                        expected: update.final_state_commitment(),
                    });
                }

                (AccountStateForInsert::PartialState(account_state), storage, assets)
            },
        };

        // Insert account code for full accounts (new account creation)
        if let AccountStateForInsert::FullAccount(ref account) = account_state {
            let code = account.code();
            let code_value = AccountCodeRowInsert {
                code_commitment: code.commitment().to_bytes(),
                code: code.to_bytes(),
            };
            diesel::insert_into(schema::account_codes::table)
                .values(&code_value)
                .on_conflict(schema::account_codes::code_commitment)
                .do_nothing()
                .execute(conn)?;
        }

        // mark previous rows as non-latest and insert NEW account row
        diesel::update(schema::accounts::table)
            .filter(
                schema::accounts::account_id
                    .eq(&account_id_bytes)
                    .and(schema::accounts::is_latest.eq(true)),
            )
            .set(schema::accounts::is_latest.eq(false))
            .execute(conn)?;

        let account_value = match &account_state {
            AccountStateForInsert::Private => AccountRowInsert::new_private(
                account_id,
                network_account_type,
                update.final_state_commitment(),
                block_num,
                created_at_block,
            ),
            AccountStateForInsert::FullAccount(account) => AccountRowInsert::new_from_account(
                account_id,
                network_account_type,
                update.final_state_commitment(),
                block_num,
                created_at_block,
                account,
            ),
            AccountStateForInsert::PartialState(state) => AccountRowInsert::new_from_partial(
                account_id,
                network_account_type,
                update.final_state_commitment(),
                block_num,
                created_at_block,
                state,
            ),
        };

        diesel::insert_into(schema::accounts::table)
            .values(&account_value)
            .on_conflict((schema::accounts::account_id, schema::accounts::block_num))
            .do_update()
            .set(&account_value)
            .execute(conn)?;

        // insert pending storage map entries
        for (acc_id, slot_name, key, value) in pending_storage_inserts {
            insert_account_storage_map_value(conn, acc_id, block_num, slot_name, key, value)?;
        }

        for (acc_id, vault_key, update) in pending_asset_inserts {
            insert_account_vault_asset(conn, acc_id, block_num, vault_key, update)?;
        }

        count += 1;
    }

    Ok(count)
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = schema::account_codes)]
pub(crate) struct AccountCodeRowInsert {
    pub(crate) code_commitment: Vec<u8>,
    pub(crate) code: Vec<u8>,
}

#[derive(Insertable, AsChangeset, Debug, Clone)]
#[diesel(table_name = schema::accounts)]
pub(crate) struct AccountRowInsert {
    pub(crate) account_id: Vec<u8>,
    pub(crate) network_account_type: i32,
    pub(crate) block_num: i64,
    pub(crate) account_commitment: Vec<u8>,
    pub(crate) code_commitment: Option<Vec<u8>>,
    pub(crate) nonce: Option<i64>,
    pub(crate) storage_header: Option<Vec<u8>>,
    pub(crate) vault_root: Option<Vec<u8>>,
    pub(crate) is_latest: bool,
    pub(crate) created_at_block: i64,
}

impl AccountRowInsert {
    /// Creates an insert row for a private account (no public state).
    fn new_private(
        account_id: AccountId,
        network_account_type: NetworkAccountType,
        account_commitment: Word,
        block_num: BlockNumber,
        created_at_block: BlockNumber,
    ) -> Self {
        Self {
            account_id: account_id.to_bytes(),
            network_account_type: network_account_type.to_raw_sql(),
            account_commitment: account_commitment.to_bytes(),
            block_num: block_num.to_raw_sql(),
            nonce: None,
            code_commitment: None,
            storage_header: None,
            vault_root: None,
            is_latest: true,
            created_at_block: created_at_block.to_raw_sql(),
        }
    }

    /// Creates an insert row from a full account (new account creation).
    fn new_from_account(
        account_id: AccountId,
        network_account_type: NetworkAccountType,
        account_commitment: Word,
        block_num: BlockNumber,
        created_at_block: BlockNumber,
        account: &Account,
    ) -> Self {
        Self {
            account_id: account_id.to_bytes(),
            network_account_type: network_account_type.to_raw_sql(),
            account_commitment: account_commitment.to_bytes(),
            block_num: block_num.to_raw_sql(),
            nonce: Some(nonce_to_raw_sql(account.nonce())),
            code_commitment: Some(account.code().commitment().to_bytes()),
            storage_header: Some(account.storage().to_header().to_bytes()),
            vault_root: Some(account.vault().root().to_bytes()),
            is_latest: true,
            created_at_block: created_at_block.to_raw_sql(),
        }
    }

    /// Creates an insert row from a partial account state (delta update).
    fn new_from_partial(
        account_id: AccountId,
        network_account_type: NetworkAccountType,
        account_commitment: Word,
        block_num: BlockNumber,
        created_at_block: BlockNumber,
        state: &PartialAccountState,
    ) -> Self {
        Self {
            account_id: account_id.to_bytes(),
            network_account_type: network_account_type.to_raw_sql(),
            account_commitment: account_commitment.to_bytes(),
            block_num: block_num.to_raw_sql(),
            nonce: Some(nonce_to_raw_sql(state.nonce)),
            code_commitment: Some(state.code_commitment.to_bytes()),
            storage_header: Some(state.storage_header.to_bytes()),
            vault_root: Some(state.vault_root.to_bytes()),
            is_latest: true,
            created_at_block: created_at_block.to_raw_sql(),
        }
    }
}

#[derive(Insertable, AsChangeset, Debug, Clone)]
#[diesel(table_name = schema::account_vault_assets)]
pub(crate) struct AccountAssetRowInsert {
    pub(crate) account_id: Vec<u8>,
    pub(crate) block_num: i64,
    pub(crate) vault_key: Vec<u8>,
    pub(crate) asset: Option<Vec<u8>>,
    pub(crate) is_latest: bool,
}

impl AccountAssetRowInsert {
    pub(crate) fn new(
        account_id: &AccountId,
        vault_key: &AssetVaultKey,
        block_num: BlockNumber,
        asset: Option<Asset>,
        is_latest: bool,
    ) -> Self {
        let account_id = account_id.to_bytes();
        let vault_key: Word = (*vault_key).into();
        let vault_key = vault_key.to_bytes();
        let block_num = block_num.to_raw_sql();
        let asset = asset.map(|asset| asset.to_bytes());
        Self {
            account_id,
            block_num,
            vault_key,
            asset,
            is_latest,
        }
    }
}

#[derive(Insertable, AsChangeset, Debug, Clone)]
#[diesel(table_name = schema::account_storage_map_values)]
pub(crate) struct AccountStorageMapRowInsert {
    pub(crate) account_id: Vec<u8>,
    pub(crate) block_num: i64,
    pub(crate) slot_name: String,
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) is_latest: bool,
}

// CLEANUP FUNCTIONS
// ================================================================================================

/// Number of historical blocks to retain for vault assets and storage map values.
/// Entries older than `chain_tip - HISTORICAL_BLOCK_RETENTION` will be deleted,
/// except for entries marked with `is_latest=true` which are always retained.
pub const HISTORICAL_BLOCK_RETENTION: u32 = 50;

/// Clean up old entries for all accounts, deleting entries older than the retention window.
///
/// Deletes rows where `block_num < chain_tip - HISTORICAL_BLOCK_RETENTION` and `is_latest = false`.
/// This is a simple and efficient approach that doesn't require window functions.
///
/// # Returns
/// A tuple of `(vault_assets_deleted, storage_map_values_deleted)`
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
    fields(cutoff_block),
)]
pub(crate) fn prune_history(
    conn: &mut SqliteConnection,
    chain_tip: BlockNumber,
) -> Result<(usize, usize), DatabaseError> {
    let cutoff_block = i64::from(chain_tip.as_u32().saturating_sub(HISTORICAL_BLOCK_RETENTION));
    tracing::Span::current().record("cutoff_block", cutoff_block);
    let vault_deleted = prune_account_vault_assets(conn, cutoff_block)?;
    let storage_deleted = prune_account_storage_map_values(conn, cutoff_block)?;

    Ok((vault_deleted, storage_deleted))
}

#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
    fields(cutoff_block),
)]
fn prune_account_vault_assets(
    conn: &mut SqliteConnection,
    cutoff_block: i64,
) -> Result<usize, DatabaseError> {
    diesel::delete(
        schema::account_vault_assets::table.filter(
            schema::account_vault_assets::block_num
                .lt(cutoff_block)
                .and(schema::account_vault_assets::is_latest.eq(false)),
        ),
    )
    .execute(conn)
    .map_err(DatabaseError::Diesel)
}

#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
    fields(cutoff_block),
)]
fn prune_account_storage_map_values(
    conn: &mut SqliteConnection,
    cutoff_block: i64,
) -> Result<usize, DatabaseError> {
    diesel::delete(
        schema::account_storage_map_values::table.filter(
            schema::account_storage_map_values::block_num
                .lt(cutoff_block)
                .and(schema::account_storage_map_values::is_latest.eq(false)),
        ),
    )
    .execute(conn)
    .map_err(DatabaseError::Diesel)
}
