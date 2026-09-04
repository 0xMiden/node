use std::collections::{BTreeMap, HashMap, HashSet};
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
    JoinOnDsl,
    NullableExpressionMethods,
    OptionalExtension,
    QueryDsl,
    RunQueryDsl,
    Selectable,
    SelectableHelper,
    SqliteConnection,
};
use miden_node_proto::domain::account::{AccountInfo, AccountSummary, AccountVaultDetails};
use miden_node_tracing::miden_instrument;
use miden_node_utils::limiter::{
    MAX_RESPONSE_PAYLOAD_BYTES,
    QueryParamAccountIdLimit,
    QueryParamLimiter,
};
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountId,
    AccountPatch,
    AccountStorage,
    AccountStorageHeader,
    AccountUpdateDetails,
    StorageMap,
    StorageMapKey,
    StorageMapPatchEntries,
    StorageSlot,
    StorageSlotContent,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{Asset, AssetId, AssetVault};
use miden_protocol::block::{BlockAccountUpdate, BlockNumber};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_standards::account::auth::NetworkAccount;

use crate::COMPONENT;
use crate::db::models::conv::{SqlTypeConvert, nonce_to_raw_sql, raw_sql_to_nonce};
#[cfg(test)]
use crate::db::models::vec_raw_try_into;
use crate::db::{AccountVaultValue, schema};
use crate::errors::DatabaseError;

mod at_block;
pub(crate) use at_block::select_account_header_with_storage_header_at_block;

mod delta;
use delta::{
    AccountStateForInsert,
    LatestAccountStateRow,
    PartialAccountState,
    PrecomputedFullAccountState,
    apply_storage_patch_with_roots,
    select_latest_account_state,
};

#[cfg(test)]
mod tests;

type StorageMapValueRow = (i64, String, Vec<u8>, Vec<u8>);
type StorageHeaderWithEntries =
    (AccountStorageHeader, HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>);

/// Sentinel `valid_until` value marking a row as the current, open-ended version of its key.
///
/// Versioned rows (`accounts`, `account_vault_assets`, `account_storage_map_values`) are
/// applicable for blocks in `[block_num, valid_until)`; updating a key closes the previous row's
/// interval by setting its `valid_until` to the new row's `block_num`. The open end is `i64::MAX`
/// rather than NULL so every validity predicate is a single range comparison that partial indexes
/// can serve.
pub(crate) const VALID_FOREVER: i64 = i64::MAX;

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
///     AND valid_until = {VALID_FOREVER}
/// ```
pub(crate) fn select_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<AccountInfo, DatabaseError> {
    let raw = SelectDsl::select(schema::accounts::table, AccountSummaryRaw::as_select())
        .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
        .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
        .get_result::<AccountSummaryRaw>(conn)
        .optional()?
        .ok_or(DatabaseError::AccountNotFoundInDb(account_id))?;

    let summary: AccountSummary = raw.try_into()?;

    // Public accounts store full details. Private accounts store only the summary.
    let details = if account_id.is_public() {
        Some(select_full_account(conn, account_id)?)
    } else {
        None
    };

    Ok(AccountInfo { summary, details })
}

/// Reconstructs the latest account state from database tables.
///
/// Reads code from `account_codes`, the nonce and storage header from `accounts`, map entries from
/// `account_storage_map_values`, and assets from `account_vault_assets`.
pub(crate) fn select_full_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Account, DatabaseError> {
    // Get account metadata (nonce, code_commitment) and code in a single join query
    let joined = schema::accounts::table.inner_join(schema::account_codes::table.on(
        schema::accounts::code_commitment.eq(schema::account_codes::code_commitment.nullable()),
    ));

    let (nonce, code_bytes): (Option<i64>, Vec<u8>) =
        SelectDsl::select(joined, (schema::accounts::nonce, schema::account_codes::code))
            .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
            .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
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
    .filter(schema::account_vault_assets::valid_until.eq(VALID_FOREVER))
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
///     valid_until = {VALID_FOREVER}
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
    // Fetch one extra to determine if there are more results
    #[expect(clippy::cast_possible_wrap)]
    let limit = (page_size.get() + 1) as i64;

    let mut query = SelectDsl::select(
        schema::accounts::table,
        (schema::accounts::account_id, schema::accounts::account_commitment),
    )
    .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
    .order_by(schema::accounts::account_id.asc())
    .limit(limit)
    .into_boxed();

    if let Some(cursor) = after_account_id {
        query = query.filter(schema::accounts::account_id.gt(cursor.to_bytes()));
    }

    let raw = query.load::<(Vec<u8>, Vec<u8>)>(conn)?;

    let mut commitments = raw
        .into_iter()
        .map(|(ref account, ref commitment)| {
            Ok((AccountId::read_from_bytes(account)?, Word::read_from_bytes(commitment)?))
        })
        .collect::<Result<Vec<_>, DatabaseError>>()?;

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

/// Latest account state forest roots for a public account.
#[derive(Debug)]
pub struct PublicAccountStateRoots {
    pub account_id: AccountId,
    pub vault_root: Word,
    pub storage_header: AccountStorageHeader,
}

/// Page of public account state roots returned by [`select_public_account_state_roots_paged`].
#[derive(Debug)]
pub struct PublicAccountStateRootsPage {
    /// The public account state roots in this page.
    pub accounts: Vec<PublicAccountStateRoots>,
    /// If `Some`, there are more results. Use this as the `after_account_id` for the next page.
    pub next_cursor: Option<AccountId>,
}

/// Public account state commitments computed by the account state forest before SQLite writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrecomputedPublicAccountState {
    pub(crate) vault_root: Word,
    pub(crate) storage_map_roots: BTreeMap<StorageSlotName, Word>,
}

pub(crate) type PrecomputedPublicAccountStates = BTreeMap<AccountId, PrecomputedPublicAccountState>;

/// Selects public account IDs with pagination.
///
/// Returns up to `page_size` public account IDs, starting after `after_account_id` if provided.
/// Results are ordered by `account_id` for stable pagination.
///
/// Public accounts are those with `AccountType::Public`. We identify them by checking
/// against the store. Public accounts store their `code_commitment`, while private accounts only
/// store the `account_commitment`.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     account_id
/// FROM
///     accounts
/// WHERE
///     valid_until = {VALID_FOREVER}
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
    #[expect(clippy::cast_possible_wrap)]
    let limit = (page_size.get() + 1) as i64;

    let mut query = SelectDsl::select(schema::accounts::table, schema::accounts::account_id)
        .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
        .filter(schema::accounts::code_commitment.is_not_null())
        .order_by(schema::accounts::account_id.asc())
        .limit(limit)
        .into_boxed();

    if let Some(cursor) = after_account_id {
        query = query.filter(schema::accounts::account_id.gt(cursor.to_bytes()));
    }

    let raw = query.load::<Vec<u8>>(conn)?;

    let mut account_ids: Vec<AccountId> = raw
        .into_iter()
        .map(|bytes| {
            AccountId::read_from_bytes(&bytes).map_err(DatabaseError::DeserializationError)
        })
        .collect::<Result<_, _>>()?;

    // If we got more than page_size, there are more results
    let next_cursor = if account_ids.len() > page_size.get() {
        account_ids.pop(); // Remove the extra element
        account_ids.last().copied()
    } else {
        None
    };

    Ok(PublicAccountIdsPage { account_ids, next_cursor })
}

/// Selects public account vault roots and storage headers with pagination.
///
/// Returns up to `page_size` public account states, starting after `after_account_id` if provided.
/// Results are ordered by `account_id` for stable pagination.
///
/// Public accounts are those with `AccountType::Public`. We identify them by checking
/// against the store. Public accounts store their `code_commitment`, while private accounts only
/// store the `account_commitment`.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     account_id,
///     vault_root,
///     storage_header
/// FROM
///     accounts
/// WHERE
///     valid_until = {VALID_FOREVER}
///     AND code_commitment IS NOT NULL
///     AND (account_id > :after_account_id OR :after_account_id IS NULL)
/// ORDER BY
///     account_id ASC
/// LIMIT :page_size + 1
/// ```
pub(crate) fn select_public_account_state_roots_paged(
    conn: &mut SqliteConnection,
    page_size: NonZeroUsize,
    after_account_id: Option<AccountId>,
) -> Result<PublicAccountStateRootsPage, DatabaseError> {
    #[expect(clippy::cast_possible_wrap)]
    let limit = (page_size.get() + 1) as i64;

    let mut query = SelectDsl::select(
        schema::accounts::table,
        (
            schema::accounts::account_id,
            schema::accounts::vault_root,
            schema::accounts::storage_header,
        ),
    )
    .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
    .filter(schema::accounts::code_commitment.is_not_null())
    .order_by(schema::accounts::account_id.asc())
    .limit(limit)
    .into_boxed();

    if let Some(cursor) = after_account_id {
        query = query.filter(schema::accounts::account_id.gt(cursor.to_bytes()));
    }

    let raw = query.load::<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)>(conn)?;

    let mut accounts: Vec<PublicAccountStateRoots> = raw
        .into_iter()
        .map(|(account_id_bytes, vault_root_bytes, storage_header_bytes)| {
            let account_id = AccountId::read_from_bytes(&account_id_bytes)
                .map_err(DatabaseError::DeserializationError)?;
            let vault_root_bytes = vault_root_bytes.ok_or_else(|| {
                DatabaseError::DataCorrupted(format!(
                    "public account {account_id} is missing a vault root"
                ))
            })?;
            let storage_header_bytes = storage_header_bytes.ok_or_else(|| {
                DatabaseError::DataCorrupted(format!(
                    "public account {account_id} is missing a storage header"
                ))
            })?;

            Ok::<_, DatabaseError>(PublicAccountStateRoots {
                account_id,
                vault_root: Word::read_from_bytes(&vault_root_bytes)?,
                storage_header: AccountStorageHeader::read_from_bytes(&storage_header_bytes)?,
            })
        })
        .collect::<Result<_, _>>()?;

    // If we got more than page_size, there are more results.
    let next_cursor = if accounts.len() > page_size.get() {
        accounts.pop();
        accounts.last().map(|account| account.account_id)
    } else {
        None
    };

    Ok(PublicAccountStateRootsPage { accounts, next_cursor })
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
    // The protocol does not define these limits. Derive a conservative row limit from the response
    // payload limit.
    const ROW_OVERHEAD_BYTES: usize = 2 * size_of::<Word>() + size_of::<u32>(); // key + asset + block_num
    const MAX_ROWS: usize = MAX_RESPONSE_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

    select_account_vault_assets_with_row_limit(conn, account_id, block_range, MAX_ROWS)
}

/// Like [`select_account_vault_assets`], but with an explicit row cap for pagination tests.
pub(crate) fn select_account_vault_assets_with_row_limit(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
    max_rows: usize,
) -> Result<(BlockNumber, Vec<AccountVaultValue>), DatabaseError> {
    use schema::account_vault_assets as t;

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
            .limit(i64::try_from(max_rows + 1).expect("should fit within i64"))
            .load::<(i64, Vec<u8>, Option<Vec<u8>>)>(conn)?;

    // If we got more rows than the limit, the last block may be incomplete so we drop it entirely
    // and derive last_block_included from the remaining rows.
    let (last_block_included, values) = if let Some(&(last_block_num, ..)) = raw.last()
        && raw.len() > max_rows
    {
        let values = raw
            .into_iter()
            .take_while(|(bn, ..)| *bn != last_block_num)
            .map(AccountVaultValue::from_raw_row)
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        ensure_account_sync_page_made_progress(last_block_num, &values)?;

        let last_block_included = values.last().expect("non-empty after progress check").block_num;

        (last_block_included, values)
    } else {
        (
            *block_range.end(),
            raw.into_iter().map(AccountVaultValue::from_raw_row).collect::<Result<_, _>>()?,
        )
    };

    Ok((last_block_included, values))
}

/// Returns an error when block-based pagination drops every row in the overflow block.
fn ensure_account_sync_page_made_progress<T>(
    truncation_block_num: i64,
    values: &[T],
) -> Result<(), DatabaseError> {
    if values.is_empty() {
        return Err(DatabaseError::AccountSyncPageExceedsPayloadLimit {
            block_num: BlockNumber::from_raw_sql(truncation_block_num)?,
        });
    }

    Ok(())
}

/// Query vault assets at a specific block by finding the most recent update for each `vault_key`.
///
/// Selects, per vault key, the row whose validity interval covers `block_num`:
/// ```sql
/// SELECT asset FROM account_vault_assets
/// WHERE account_id = ?1 AND block_num <= ?2 AND valid_until > ?2
/// LIMIT ?3
/// ```
///
/// The read is bounded to [`AccountVaultDetails::MAX_RETURN_ENTRIES`] + 1 rows so an over-the-limit
/// vault can be detected without materializing the whole set.
pub(crate) fn select_account_vault_at_block(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<Vec<Asset>, DatabaseError> {
    use diesel::sql_types::{BigInt, Binary};

    let account_id_bytes = account_id.to_bytes();
    let block_num_sql = block_num.to_raw_sql();
    let limit_sql =
        i64::try_from(AccountVaultDetails::MAX_RETURN_ENTRIES + 1).expect("should fit within i64");

    let entries: Vec<Option<Vec<u8>>> = diesel::sql_query(
        r"
        SELECT asset FROM account_vault_assets
        WHERE account_id = ?1 AND block_num <= ?2 AND valid_until > ?2
        LIMIT ?3
        ",
    )
    .bind::<Binary, _>(&account_id_bytes)
    .bind::<BigInt, _>(block_num_sql)
    .bind::<BigInt, _>(limit_sql)
    .load::<AssetRow>(conn)?
    .into_iter()
    .map(|row| row.asset)
    .collect();

    // Convert to assets, filtering out deletions (None values)
    let mut assets = Vec::new();
    for asset_bytes in entries.into_iter().flatten() {
        let asset = Asset::read_from_bytes(&asset_bytes)?;
        assets.push(asset);
    }

    Ok(assets)
}

#[derive(QueryableByName)]
struct AssetRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Binary>)]
    asset: Option<Vec<u8>>,
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
///     valid_until = {VALID_FOREVER}
/// ORDER BY
///     block_num ASC
/// ```
#[cfg(test)]
pub(crate) fn select_all_accounts(
    conn: &mut SqliteConnection,
) -> Result<Vec<AccountInfo>, DatabaseError> {
    let raw = SelectDsl::select(schema::accounts::table, AccountSummaryRaw::as_select())
        .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValue {
    pub block_num: BlockNumber,
    pub slot_name: StorageSlotName,
    pub key: StorageMapKey,
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
            key: StorageMapKey::read_from_bytes(&key)?,
            value: Word::read_from_bytes(&value)?,
        })
    }
}

/// Select account storage map values from the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// A vector of tuples containing `(block_num, slot, key, value)` for the given account.
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
pub(crate) fn select_account_storage_map_values_paged(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_range: RangeInclusive<BlockNumber>,
    limit: usize,
) -> Result<StorageMapValuesPage, DatabaseError> {
    use schema::account_storage_map_values as t;

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
            .limit(i64::try_from(limit + 1).expect("limit fits within i64"))
            .load(conn)?;

    // If we got more rows than the limit, the last block may be incomplete so we drop it entirely
    // and derive last_block_included from the remaining rows.
    let (last_block_included, values) = if let Some(&(last_block_num, ..)) = raw.last()
        && raw.len() > limit
    {
        let values = raw
            .into_iter()
            .take_while(|(bn, ..)| *bn != last_block_num)
            .map(StorageMapValue::from_raw_row)
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        ensure_account_sync_page_made_progress(last_block_num, &values)?;

        let last_block_included = values.last().expect("non-empty after progress check").block_num;

        (last_block_included, values)
    } else {
        (
            *block_range.end(),
            raw.into_iter()
                .map(StorageMapValue::from_raw_row)
                .collect::<Result<Vec<_>, _>>()?,
        )
    };

    Ok(StorageMapValuesPage { last_block_included, values })
}

/// Select latest account storage by querying `accounts.storage_header` for the account's
/// open-ended row and reconstructing full storage from the header plus map values from
/// `account_storage_map_values`.
///
/// Attention: For large accounts it is prohibitively expensive!
pub(crate) fn select_latest_account_storage(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<AccountStorage, DatabaseError> {
    let (storage_header, map_entries_by_slot) =
        select_latest_account_storage_components(conn, account_id)?;
    // Reconstruct StorageSlots from header slots + map entries
    let slots = storage_header
        .slots()
        .map(|slot_header| {
            let slot = match slot_header.slot_type() {
                StorageSlotType::Value => {
                    // For value slots, the header value IS the slot value
                    StorageSlot::with_value(slot_header.name().clone(), slot_header.value())
                },
                StorageSlotType::Map => {
                    // For map slots, reconstruct from map entries
                    let entries =
                        map_entries_by_slot.get(slot_header.name()).cloned().unwrap_or_default();
                    let storage_map = StorageMap::with_entries(entries)?;
                    StorageSlot::with_map(slot_header.name().clone(), storage_map)
                },
            };
            Ok(slot)
        })
        .collect::<Result<Vec<_>, DatabaseError>>()?;

    Ok(AccountStorage::new(slots)?)
}

/// Fetch account storage header and all storage maps
pub(crate) fn select_latest_account_storage_components(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<StorageHeaderWithEntries, DatabaseError> {
    let account_id_bytes = account_id.to_bytes();

    // Query storage header blob for this account's current (open-ended) row
    let storage_blob: Option<Vec<u8>> =
        SelectDsl::select(schema::accounts::table, schema::accounts::storage_header)
            .filter(schema::accounts::account_id.eq(&account_id_bytes))
            .filter(schema::accounts::valid_until.eq(VALID_FOREVER))
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

// This query is expensive because it loads every current storage map entry for the account.
fn select_latest_storage_map_entries_all(
    conn: &mut SqliteConnection,
    account_id: &AccountId,
) -> Result<HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>, DatabaseError> {
    use schema::account_storage_map_values as t;

    let map_values: Vec<(String, Vec<u8>, Vec<u8>)> =
        SelectDsl::select(t::table, (t::slot_name, t::key, t::value))
            .filter(t::account_id.eq(&account_id.to_bytes()))
            .filter(t::valid_until.eq(VALID_FOREVER))
            .load(conn)?;

    group_storage_map_entries(map_values)
}

fn group_storage_map_entries(
    map_values: Vec<(String, Vec<u8>, Vec<u8>)>,
) -> Result<HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>, DatabaseError> {
    let mut map_entries_by_slot: HashMap<StorageSlotName, BTreeMap<StorageMapKey, Word>> =
        HashMap::new();
    for (slot_name_str, key_bytes, value_bytes) in map_values {
        let slot_name: StorageSlotName = slot_name_str.parse().map_err(|_| {
            DatabaseError::DataCorrupted(format!("Invalid slot name: {slot_name_str}"))
        })?;
        let key = StorageMapKey::read_from_bytes(&key_bytes)?;
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
        let vault_key = AssetId::try_from(Word::read_from_bytes(&raw.vault_key)?)?;
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
/// The new row is inserted open-ended (`valid_until = VALID_FOREVER`); any existing open row
/// with the same `(account_id, vault_key)` tuple has its validity interval closed at `block_num`.
///
/// # Returns
///
/// The number of affected rows.
pub(crate) fn insert_account_vault_asset(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    vault_key: AssetId,
    asset: Option<Asset>,
) -> Result<usize, DatabaseError> {
    let record = AccountAssetRowInsert::new(&account_id, &vault_key, block_num, asset);

    diesel::Connection::transaction(conn, |conn| {
        // Close the previous version's validity interval at the new row's block.
        let vault_key: Word = vault_key.into();
        let vault_key_bytes = vault_key.to_bytes();
        let account_id_bytes = account_id.to_bytes();
        let update_count = diesel::update(schema::account_vault_assets::table)
            .filter(
                schema::account_vault_assets::account_id
                    .eq(account_id_bytes)
                    .and(schema::account_vault_assets::vault_key.eq(vault_key_bytes))
                    .and(schema::account_vault_assets::valid_until.eq(VALID_FOREVER)),
            )
            .set(schema::account_vault_assets::valid_until.eq(block_num.to_raw_sql()))
            .execute(conn)?;

        // Insert the new open-ended row
        let insert_count = diesel::insert_into(schema::account_vault_assets::table)
            .values(record)
            .execute(conn)?;

        Ok(update_count + insert_count)
    })
}

/// Inserts a versioned account storage-map value using the given [`SqliteConnection`].
///
/// The new row is inserted open-ended, and any previous open row for the same
/// `(account_id, slot_name, key)` tuple has its validity interval closed at `block_num` first.
///
/// # Returns
///
/// The total number of inserted and invalidated rows.
///
/// # Errors
///
/// Returns an error if the previous row cannot be invalidated or the new row cannot be inserted.
pub(crate) fn insert_account_storage_map_value(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    slot_name: StorageSlotName,
    key: StorageMapKey,
    value: Word,
) -> Result<usize, DatabaseError> {
    insert_account_storage_map_value_inner(conn, account_id, block_num, slot_name, key, value, true)
}

/// Inserts a versioned account storage-map value with optional previous-row invalidation.
///
/// `invalidate_previous` may be disabled when inserting state for a new account, for which no
/// previous open row can exist. The inserted row is always open-ended.
///
/// # Returns
///
/// The total number of inserted and invalidated rows.
///
/// # Errors
///
/// Returns an error if the requested invalidation or insertion fails.
fn insert_account_storage_map_value_inner(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    slot_name: StorageSlotName,
    key: StorageMapKey,
    value: Word,
    invalidate_previous: bool,
) -> Result<usize, DatabaseError> {
    let account_id = account_id.to_bytes();
    let key = key.to_bytes();
    let value = value.to_bytes();
    let slot_name = slot_name.to_raw_sql();
    let block_num = block_num.to_raw_sql();

    let update_count = if invalidate_previous {
        diesel::update(schema::account_storage_map_values::table)
            .filter(
                schema::account_storage_map_values::account_id
                    .eq(&account_id)
                    .and(schema::account_storage_map_values::slot_name.eq(&slot_name))
                    .and(schema::account_storage_map_values::key.eq(&key))
                    .and(schema::account_storage_map_values::valid_until.eq(VALID_FOREVER)),
            )
            .set(schema::account_storage_map_values::valid_until.eq(block_num))
            .execute(conn)?
    } else {
        0
    };

    let record = AccountStorageMapRowInsert {
        account_id,
        key,
        value,
        slot_name,
        block_num,
        valid_until: VALID_FOREVER,
    };
    let insert_count = diesel::insert_into(schema::account_storage_map_values::table)
        .values(record)
        .execute(conn)?;

    Ok(update_count + insert_count)
}

type PendingStorageInserts = Vec<(AccountId, StorageSlotName, StorageMapKey, Word)>;
type PendingAssetInserts = Vec<(AccountId, AssetId, Option<Asset>)>;

fn prepare_full_account_update(
    update: &BlockAccountUpdate,
    account: Account,
) -> Result<(AccountStateForInsert, PendingStorageInserts, PendingAssetInserts), DatabaseError> {
    let account_id = account.id();

    // sanity check the commitment of account matches the final state commitment
    if account.to_commitment() != update.final_state_commitment() {
        return Err(DatabaseError::AccountCommitmentsMismatch {
            calculated: account.to_commitment(),
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
            Asset::Fungible(fungible) => fungible.amount().as_u64() > 0,
            Asset::NonFungible(_) => true,
        };
        if should_insert {
            assets.push((account_id, asset.id(), Some(asset)));
        }
    }

    Ok((AccountStateForInsert::FullAccount(account), storage, assets))
}

/// Prepares a full public-account insertion using roots computed by the account-state forest.
///
/// This avoids reconstructing the account's vault and storage maps in SQLite. The returned state
/// contains the account-row fields, while storage-map entries and vault assets are returned
/// separately for insertion after the account row has satisfied their foreign-key dependency.
/// Empty-word map entries and assets are omitted from the pending inserts.
///
/// # Errors
///
/// Returns an error if the full-state patch is missing its code or nonce, a required precomputed
/// storage root is absent, an asset is invalid, or the reconstructed account header does not match
/// the update's final state commitment.
fn prepare_precomputed_full_account_update(
    update: &BlockAccountUpdate,
    patch: &AccountPatch,
    precomputed: &PrecomputedPublicAccountState,
) -> Result<(AccountStateForInsert, PendingStorageInserts, PendingAssetInserts), DatabaseError> {
    let account_id = patch.id();
    let code = patch.code().cloned().ok_or_else(|| {
        DatabaseError::DataCorrupted(format!(
            "full-state patch for account {account_id} is missing account code"
        ))
    })?;
    let nonce = patch.final_nonce().ok_or_else(|| {
        DatabaseError::DataCorrupted(format!(
            "full-state patch for account {account_id} is missing final nonce"
        ))
    })?;

    let storage_header = apply_storage_patch_with_roots(
        &AccountStorageHeader::new(Vec::new())?,
        patch.storage(),
        &precomputed.storage_map_roots,
    )?;
    let account_header = miden_protocol::account::AccountHeader::new(
        account_id,
        nonce,
        precomputed.vault_root,
        storage_header.to_commitment(),
        code.commitment(),
    );
    if account_header.to_commitment() != update.final_state_commitment() {
        return Err(DatabaseError::AccountCommitmentsMismatch {
            calculated: account_header.to_commitment(),
            expected: update.final_state_commitment(),
        });
    }

    let storage = patch
        .storage()
        .maps()
        .flat_map(|(slot_name, map_patch)| {
            map_patch.entries().into_iter().flat_map(move |entries| {
                entries
                    .as_map()
                    .iter()
                    .filter(|(_key, value)| **value != Word::empty())
                    .map(move |(key, value)| (account_id, slot_name.clone(), *key, *value))
            })
        })
        .collect();
    let assets = patch
        .vault()
        .iter()
        .filter(|(_asset_id, value)| **value != Word::empty())
        .map(|(asset_id, value)| {
            Asset::from_id_and_value(*asset_id, *value)
                .map(|asset| (account_id, *asset_id, Some(asset)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // The patch carries full state, so it can be turned back into an account and classified with
    // the canonical check.
    let is_network_account = NetworkAccount::new(Account::try_from(patch)?).is_ok();
    let state = PrecomputedFullAccountState {
        nonce,
        code,
        storage_header,
        vault_root: precomputed.vault_root,
        is_network_account,
    };

    Ok((AccountStateForInsert::PrecomputedFullState(state), storage, assets))
}

/// Prepares a partial public-account update using the latest row and precomputed forest roots.
///
/// Unchanged header fields are carried forward from `existing`. The returned partial state is used
/// for the next account row, while storage-map values and vault asset updates are returned
/// separately for insertion after that row. Empty vault values are represented as removals.
///
/// # Errors
///
/// Returns an error if the existing row is invalid, a required precomputed storage root is absent,
/// a patched asset is invalid, or the reconstructed account header does not match the update's
/// final state commitment.
fn prepare_partial_account_update(
    update: &BlockAccountUpdate,
    account_id: AccountId,
    patch: &AccountPatch,
    precomputed: &PrecomputedPublicAccountState,
    existing: &LatestAccountStateRow,
) -> Result<(AccountStateForInsert, PendingStorageInserts, PendingAssetInserts), DatabaseError> {
    // Build the minimal account state needed for partial patch application from the latest row that
    // was loaded with the account's creation metadata.
    let state_headers = existing.state_headers(account_id)?;

    // --- Process asset updates. --------------------------------- The patch carries absolute final
    // values, so encode `Some` as update and `None` (an empty value word) as removal.
    let mut assets = Vec::new();
    for (vault_key, value) in patch.vault().iter() {
        let update_or_remove = if *value == Word::empty() {
            None
        } else {
            Some(Asset::from_id_and_value(*vault_key, *value)?)
        };
        assets.push((account_id, *vault_key, update_or_remove));
    }

    // --- Collect storage map updates. ---------------------------

    let mut storage = Vec::new();
    for (slot_name, map_patch) in patch.storage().maps() {
        for (key, value) in map_patch.entries().into_iter().flat_map(StorageMapPatchEntries::as_map)
        {
            storage.push((account_id, slot_name.clone(), *key, *value));
        }
    }

    // Apply the patch storage to the given storage header.
    let new_storage_header = apply_storage_patch_with_roots(
        &state_headers.storage_header,
        patch.storage(),
        &precomputed.storage_map_roots,
    )?;

    let new_vault_root = precomputed.vault_root;

    // --- Compute updated account state for the accounts row. --- Use the absolute final nonce.
    let new_nonce = patch.final_nonce().unwrap_or(state_headers.nonce);

    // Create minimal account state data for the row insert.
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

    if account_header.to_commitment() != update.final_state_commitment() {
        return Err(DatabaseError::AccountCommitmentsMismatch {
            calculated: account_header.to_commitment(),
            expected: update.final_state_commitment(),
        });
    }

    Ok((AccountStateForInsert::PartialState(account_state), storage, assets))
}

/// Returns the subset of `account_ids` whose latest committed state is a network account.
///
/// Unknown ids and non-network accounts are silently omitted.
pub(crate) fn select_network_accounts_subset(
    conn: &mut SqliteConnection,
    account_ids: &[AccountId],
) -> Result<HashSet<AccountId>, DatabaseError> {
    QueryParamAccountIdLimit::check(account_ids.len())?;
    let id_bytes: Vec<Vec<u8>> =
        account_ids.iter().map(miden_crypto::utils::Serializable::to_bytes).collect();

    let rows: Vec<Vec<u8>> =
        SelectDsl::select(schema::accounts::table, schema::accounts::account_id)
            .filter(
                schema::accounts::account_id
                    .eq_any(&id_bytes)
                    .and(
                        schema::accounts::network_account_type
                            .eq(NetworkAccountType::Network.to_raw_sql()),
                    )
                    .and(schema::accounts::valid_until.eq(VALID_FOREVER)),
            )
            .load::<Vec<u8>>(conn)
            .map_err(DatabaseError::Diesel)?;

    rows.into_iter()
        .map(|bytes| {
            AccountId::read_from_bytes(&bytes).map_err(DatabaseError::DeserializationError)
        })
        .collect()
}

/// Attention: Assumes the account details are NOT null! The schema explicitly allows this though!
#[miden_instrument(
    target = COMPONENT,
    err,
)]
pub(crate) fn upsert_accounts(
    conn: &mut SqliteConnection,
    accounts: &[BlockAccountUpdate],
    block_num: BlockNumber,
    precomputed_public_states: &PrecomputedPublicAccountStates,
) -> Result<usize, DatabaseError> {
    let mut count = 0;
    for update in accounts {
        let account_id = update.account_id();
        let account_id_bytes = account_id.to_bytes();

        // Pull the latest row once. Partial updates consume the state headers below, while every
        // update carries forward creation metadata.
        let existing = select_latest_account_state(conn, account_id)?;
        let account_is_new = existing.is_none();

        let created_at_block = match &existing {
            Some(row) => row.created_at_block()?,
            None => block_num,
        };

        // NOTE: we collect storage / asset inserts to apply them only after the account row is
        // written. The storage and vault tables have FKs pointing to accounts `(account_id,
        // block_num)`, so inserting them earlier would violate those constraints when inserting a
        // brand-new account.
        let (account_state, pending_storage_inserts, pending_asset_inserts) = match update.details()
        {
            AccountUpdateDetails::Private => (AccountStateForInsert::Private, vec![], vec![]),

            // New account is always a full account, but also comes as an update
            AccountUpdateDetails::Public(patch) if patch.is_full_state() => {
                if block_num == BlockNumber::GENESIS {
                    let account = Account::try_from(patch)
                        .expect("Patch to full account always works for full state patches");
                    debug_assert_eq!(account_id, account.id());
                    prepare_full_account_update(update, account)?
                } else {
                    let precomputed =
                        precomputed_public_states.get(&account_id).ok_or_else(|| {
                            DatabaseError::DataCorrupted(format!(
                                "missing precomputed public account state for account {account_id}"
                            ))
                        })?;
                    prepare_precomputed_full_account_update(update, patch, precomputed)?
                }
            },

            // Update of an existing account
            AccountUpdateDetails::Public(patch) => {
                let precomputed = precomputed_public_states.get(&account_id).ok_or_else(|| {
                    DatabaseError::DataCorrupted(format!(
                        "missing precomputed public account state for account {account_id}"
                    ))
                })?;
                let existing =
                    existing.as_ref().ok_or(DatabaseError::AccountNotFoundInDb(account_id))?;
                prepare_partial_account_update(update, account_id, patch, precomputed, existing)?
            },
        };

        // Inherit the classification when the account already exists; otherwise classify it once at
        // creation based on the new state.
        let network_account_type = match &existing {
            Some(row) => row.network_account_type()?,
            None => match &account_state {
                AccountStateForInsert::FullAccount(account)
                    if NetworkAccount::new(account.clone()).is_ok() =>
                {
                    NetworkAccountType::Network
                },
                AccountStateForInsert::PrecomputedFullState(state) if state.is_network_account => {
                    NetworkAccountType::Network
                },
                _ => NetworkAccountType::None,
            },
        };

        // Insert account _code_ for full accounts (new account creation)
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
        if let AccountStateForInsert::PrecomputedFullState(ref state) = account_state {
            let code_value = AccountCodeRowInsert {
                code_commitment: state.code.commitment().to_bytes(),
                code: state.code.to_bytes(),
            };
            diesel::insert_into(schema::account_codes::table)
                .values(&code_value)
                .on_conflict(schema::account_codes::code_commitment)
                .do_nothing()
                .execute(conn)?;
        }

        // close the previous row's validity interval and insert NEW account row
        diesel::update(schema::accounts::table)
            .filter(
                schema::accounts::account_id
                    .eq(&account_id_bytes)
                    .and(schema::accounts::valid_until.eq(VALID_FOREVER)),
            )
            .set(schema::accounts::valid_until.eq(block_num.to_raw_sql()))
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
            AccountStateForInsert::PrecomputedFullState(state) => {
                AccountRowInsert::new_from_precomputed_full_state(
                    account_id,
                    network_account_type,
                    update.final_state_commitment(),
                    block_num,
                    created_at_block,
                    state,
                )
            },
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

        for (acc_id, slot_name, key, value) in pending_storage_inserts {
            if account_is_new {
                insert_account_storage_map_value_inner(
                    conn, acc_id, block_num, slot_name, key, value, false,
                )?;
            } else {
                insert_account_storage_map_value(conn, acc_id, block_num, slot_name, key, value)?;
            }
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
    pub(crate) created_at_block: i64,
    pub(crate) valid_until: i64,
}

impl AccountRowInsert {
    /// Creates an insert row for a private account (no public state).
    pub(crate) fn new_private(
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
            created_at_block: created_at_block.to_raw_sql(),
            valid_until: VALID_FOREVER,
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
            created_at_block: created_at_block.to_raw_sql(),
            valid_until: VALID_FOREVER,
        }
    }

    fn new_from_precomputed_full_state(
        account_id: AccountId,
        network_account_type: NetworkAccountType,
        account_commitment: Word,
        block_num: BlockNumber,
        created_at_block: BlockNumber,
        state: &PrecomputedFullAccountState,
    ) -> Self {
        Self {
            account_id: account_id.to_bytes(),
            network_account_type: network_account_type.to_raw_sql(),
            block_num: block_num.to_raw_sql(),
            account_commitment: account_commitment.to_bytes(),
            code_commitment: Some(state.code.commitment().to_bytes()),
            nonce: Some(nonce_to_raw_sql(state.nonce)),
            storage_header: Some(state.storage_header.to_bytes()),
            vault_root: Some(state.vault_root.to_bytes()),
            created_at_block: created_at_block.to_raw_sql(),
            valid_until: VALID_FOREVER,
        }
    }

    /// Creates an insert row from a partial account state (patch update).
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
            created_at_block: created_at_block.to_raw_sql(),
            valid_until: VALID_FOREVER,
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
    pub(crate) valid_until: i64,
}

impl AccountAssetRowInsert {
    pub(crate) fn new(
        account_id: &AccountId,
        vault_key: &AssetId,
        block_num: BlockNumber,
        asset: Option<Asset>,
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
            valid_until: VALID_FOREVER,
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
    pub(crate) valid_until: i64,
}

// CLEANUP FUNCTIONS
// ================================================================================================

/// Number of historical blocks to retain for vault assets, storage map values, and account codes.
/// Rows whose validity interval ends at or below `prune_tip - HISTORICAL_BLOCK_RETENTION` will be
/// deleted; rows still valid anywhere inside the retention window (including all open-ended rows)
/// are retained.
pub const HISTORICAL_BLOCK_RETENTION: u32 = 50;

/// Clean up old entries for all accounts, deleting entries that can no longer affect state
/// reconstruction at any block within the retention window.
///
/// A row is applicable for blocks in `[block_num, valid_until)`, so it is deletable exactly when
/// its interval ends at or below the cutoff (`prune_tip - HISTORICAL_BLOCK_RETENTION`): it then
/// cannot cover any block inside the window. `prune_tip` is the effective tip for retention — it
/// lags the chain tip while old snapshot generations are still pinned by readers (see
/// [`crate::db::Db::apply_block`]). Account codes follow the same rule — a code is deleted only
/// when no account row whose interval reaches past the cutoff references it.
///
/// # Returns
/// A tuple of `(vault_assets_deleted, storage_map_values_deleted, account_codes_deleted)`
#[miden_instrument(
    target = COMPONENT,
    err,
    fields(
        cutoff_block,
    ),
)]
pub(crate) fn prune_history(
    conn: &mut SqliteConnection,
    prune_tip: BlockNumber,
) -> Result<(usize, usize, usize), DatabaseError> {
    let cutoff_block = i64::from(prune_tip.as_u32().saturating_sub(HISTORICAL_BLOCK_RETENTION));
    miden_node_tracing::Span::current().record("cutoff_block", cutoff_block);
    let vault_deleted = prune_account_vault_assets(conn, cutoff_block)?;
    let storage_deleted = prune_account_storage_map_values(conn, cutoff_block)?;
    let codes_deleted = prune_account_codes(conn, cutoff_block)?;

    Ok((vault_deleted, storage_deleted, codes_deleted))
}

#[miden_instrument(
    target = COMPONENT,
    err,
    fields(
        cutoff_block,
    ),
)]
fn prune_account_vault_assets(
    conn: &mut SqliteConnection,
    cutoff_block: i64,
) -> Result<usize, DatabaseError> {
    use diesel::sql_types::BigInt;

    // The literal `!= VALID_FOREVER` term (rather than a bound parameter) lets SQLite prove the
    // predicate implies `idx_vault_cleanup`'s partial-index condition.
    diesel::sql_query(format!(
        "DELETE FROM account_vault_assets \
         WHERE valid_until != {VALID_FOREVER} \
           AND valid_until <= ?1"
    ))
    .bind::<BigInt, _>(cutoff_block)
    .execute(conn)
    .map_err(DatabaseError::Diesel)
}

#[miden_instrument(
    target = COMPONENT,
    err,
    fields(
        cutoff_block,
    ),
)]
fn prune_account_storage_map_values(
    conn: &mut SqliteConnection,
    cutoff_block: i64,
) -> Result<usize, DatabaseError> {
    use diesel::sql_types::BigInt;

    // The literal `!= VALID_FOREVER` term (rather than a bound parameter) lets SQLite prove the
    // predicate implies `idx_storage_cleanup`'s partial-index condition.
    diesel::sql_query(format!(
        "DELETE FROM account_storage_map_values \
         WHERE valid_until != {VALID_FOREVER} \
           AND valid_until <= ?1"
    ))
    .bind::<BigInt, _>(cutoff_block)
    .execute(conn)
    .map_err(DatabaseError::Diesel)
}

/// Deletes account codes that are no longer referenced by any account row that can serve a read
/// within the retention window.
///
/// An account code is safe to delete when no `accounts` row whose validity interval reaches past
/// the cutoff (`valid_until > cutoff_block`) references it. That single predicate covers rows
/// inside the window, all open-ended (current) rows, and each account's baseline row — the row
/// still valid at the cutoff even though it was written before it.
///
/// Rather than re-checking every code on every prune, only codes whose deletability could have
/// changed since the previous prune are examined. A code survived the previous prune because at
/// least one `accounts` row with `valid_until > prev_cutoff` referenced it. For it to be
/// deletable now, all such rows must have expired by the new cutoff — including the longest-lived
/// one, whose `valid_until` therefore lands inside `(prev_cutoff, cutoff_block]`. Scanning the
/// rows that expired in that window thus finds every code that could have become deletable. The
/// scan is an `idx_accounts_code_validity` index range, so its cost scales with the number of
/// account updates since the previous prune, not with total history. Each candidate is deleted
/// only if the `idx_accounts_code_probe` existence probe finds no row still referencing it with
/// `valid_until > cutoff_block`. The previous cutoff is persisted in `prune_progress` within the
/// same transaction; when absent (first prune after migration, or a fresh database) a full pass
/// over all rows valid past the cutoff runs instead.
///
/// Correctness of the windowed candidate set rests on two invariants:
/// - Rows are only ever closed to the `block_num` of the block currently being applied, which is
///   always above the cutoff, so every expiry crosses the window of some later prune. A write path
///   that back-dated `valid_until` below the current cutoff would leak the code forever.
/// - Every `account_codes` row is inserted alongside an `accounts` row referencing it (see
///   [`upsert_accounts`]); an orphan code with no referencing row would never become a candidate.
#[miden_instrument(
    target = COMPONENT,
    err,
    fields(
        cutoff_block,
    ),
)]
fn prune_account_codes(
    conn: &mut SqliteConnection,
    cutoff_block: i64,
) -> Result<usize, DatabaseError> {
    use diesel::sql_types::BigInt;

    let prev_cutoff: Option<i64> =
        SelectDsl::select(schema::prune_progress::table, schema::prune_progress::codes_cutoff)
            .first(conn)
            .optional()
            .map_err(DatabaseError::Diesel)?;

    let deleted = match prev_cutoff {
        // Codes are already pruned through this cutoff and nothing can become collectable while the
        // cutoff stands still. Equality is the common case: the cutoff is clamped to zero for the
        // first `HISTORICAL_BLOCK_RETENTION` blocks, and a pinned snapshot freezes the prune tip
        // across consecutive blocks. A strictly greater `prev_cutoff` is unreachable through
        // `apply_block` (the prune tip never regresses) but is guarded against so an out-of-order
        // caller cannot move the marker backwards or run the delete with an inverted window.
        Some(prev_cutoff) if prev_cutoff >= cutoff_block => return Ok(0),
        Some(prev_cutoff) => diesel::sql_query(
            "DELETE FROM account_codes \
             WHERE code_commitment IN ( \
                 SELECT DISTINCT code_commitment \
                 FROM accounts INDEXED BY idx_accounts_code_validity \
                 WHERE code_commitment IS NOT NULL \
                   AND valid_until > ?1 \
                   AND valid_until <= ?2 \
             ) \
             AND NOT EXISTS ( \
                 SELECT 1 \
                 FROM accounts INDEXED BY idx_accounts_code_probe \
                 WHERE accounts.code_commitment = account_codes.code_commitment \
                   AND accounts.valid_until > ?2 \
             )",
        )
        .bind::<BigInt, _>(prev_cutoff)
        .bind::<BigInt, _>(cutoff_block)
        .execute(conn)
        .map_err(DatabaseError::Diesel)?,
        // No recorded cutoff: full pass. The forced `idx_accounts_code_validity` covering index
        // keeps the subquery an index-only range scan, sized by rows valid at or after the cutoff
        // rather than total history.
        None => diesel::sql_query(
            "DELETE FROM account_codes \
             WHERE code_commitment NOT IN ( \
                 SELECT DISTINCT code_commitment \
                 FROM accounts INDEXED BY idx_accounts_code_validity \
                 WHERE code_commitment IS NOT NULL \
                   AND valid_until > ?1 \
             )",
        )
        .bind::<BigInt, _>(cutoff_block)
        .execute(conn)
        .map_err(DatabaseError::Diesel)?,
    };

    diesel::insert_into(schema::prune_progress::table)
        .values((
            schema::prune_progress::id.eq(0),
            schema::prune_progress::codes_cutoff.eq(cutoff_block),
        ))
        .on_conflict(schema::prune_progress::id)
        .do_update()
        .set(schema::prune_progress::codes_cutoff.eq(cutoff_block))
        .execute(conn)
        .map_err(DatabaseError::Diesel)?;

    Ok(deleted)
}
