use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use diesel::prelude::{Queryable, QueryableByName};
use diesel::query_dsl::methods::SelectDsl;
use diesel::sqlite::Sqlite;
use diesel::{
    BoolExpressionMethods,
    ExpressionMethods,
    JoinOnDsl,
    NullableExpressionMethods,
    OptionalExtension,
    QueryDsl,
    RunQueryDsl,
    Selectable,
    SelectableHelper,
    SqliteConnection,
};
use miden_node_proto::domain::account::{AccountInfo, AccountSummary};
use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountId,
    AccountStorage,
    AccountStorageHeader,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{Asset, AssetId, AssetVault};
use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::{Deserializable, Serializable};

use crate::db::models::conv::{SqlTypeConvert, raw_sql_to_nonce};
#[cfg(test)]
use crate::db::models::vec_raw_try_into;
use crate::db::{AccountVaultValue, schema};
use crate::errors::DatabaseError;

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
    use schema::account_vault_assets as t;
    // The protocol does not define these limits. Derive a conservative row limit from the response
    // payload limit.
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

    // If we got more rows than the limit, the last block may be incomplete so we drop it entirely
    // and derive last_block_included from the remaining rows.
    let (last_block_included, values) = if let Some(&(last_block_num, ..)) = raw.last()
        && raw.len() > MAX_ROWS
    {
        let values = raw
            .into_iter()
            .take_while(|(bn, ..)| *bn != last_block_num)
            .map(AccountVaultValue::from_raw_row)
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        let last_block_included = values.last().map_or(*block_range.start(), |v| v.block_num);

        (last_block_included, values)
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

        let last_block_included = values.last().map_or(*block_range.start(), |v| v.block_num);

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
