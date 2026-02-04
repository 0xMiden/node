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
use miden_lib::utils::{Deserializable, Serializable};
use miden_node_proto as proto;
use miden_node_proto::domain::account::{AccountInfo, AccountSummary};
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_objects::account::delta::AccountUpdateDetails;
use miden_objects::account::{
    Account,
    AccountCode,
    AccountDelta,
    AccountId,
    AccountStorage,
    NonFungibleDeltaAction,
    StorageSlot,
};
use miden_objects::asset::{Asset, AssetVault, AssetVaultKey, FungibleAsset};
use miden_objects::block::{BlockAccountUpdate, BlockNumber};
use miden_objects::{Felt, Word};

use crate::COMPONENT;
use crate::db::models::conv::{
    SqlTypeConvert,
    nonce_to_raw_sql,
    raw_sql_to_nonce,
    raw_sql_to_slot,
    slot_to_raw_sql,
};
use crate::db::models::{serialize_vec, vec_raw_try_into};
use crate::db::{AccountVaultValue, schema};
use crate::errors::DatabaseError;

/// Select the latest account details by account id from the DB using the given
/// [`SqliteConnection`].
///
/// # Returns
///
/// The latest account details, or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     accounts.account_id,
///     accounts.account_commitment,
///     accounts.block_num,
///     accounts.storage,
///     accounts.vault,
///     accounts.nonce,
///     accounts.code_commitment,
///     account_codes.code
/// FROM
///     accounts
/// LEFT JOIN
///     account_codes ON accounts.code_commitment = account_codes.code_commitment
/// WHERE
///     account_id = ?1
/// ```
pub(crate) fn select_account(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<AccountInfo, DatabaseError> {
    let raw = SelectDsl::select(
        schema::accounts::table.left_join(schema::account_codes::table.on(
            schema::accounts::code_commitment.eq(schema::account_codes::code_commitment.nullable()),
        )),
        (AccountRaw::as_select(), schema::account_codes::code.nullable()),
    )
    .filter(schema::accounts::account_id.eq(account_id.to_bytes()))
    .get_result::<(AccountRaw, Option<Vec<u8>>)>(conn)
    .optional()?
    .ok_or(DatabaseError::AccountNotFoundInDb(account_id))?;
    let info = AccountWithCodeRawJoined::from(raw).try_into()?;
    Ok(info)
}

/// Select the latest account details by account ID prefix from the DB using the given
/// [`SqliteConnection`] This method is meant to be used by the network transaction builder. Because
/// network notes get matched through accounts through the account's 30-bit prefix, it is possible
/// that multiple accounts match against a single prefix. In this scenario, the first account is
/// returned.
///
/// # Returns
///
/// The latest account details, `None` if the account was not found, or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     accounts.account_id,
///     accounts.account_commitment,
///     accounts.block_num,
///     accounts.storage,
///     accounts.vault,
///     accounts.nonce,
///     accounts.code_commitment,
///     account_codes.code
/// FROM
///     accounts
/// LEFT JOIN
///     account_codes ON accounts.code_commitment = account_codes.code_commitment
/// WHERE
///     network_account_id_prefix = ?1
/// ```
pub(crate) fn select_account_by_id_prefix(
    conn: &mut SqliteConnection,
    id_prefix: u32,
) -> Result<Option<AccountInfo>, DatabaseError> {
    let maybe_info = SelectDsl::select(
        schema::accounts::table.left_join(schema::account_codes::table.on(
            schema::accounts::code_commitment.eq(schema::account_codes::code_commitment.nullable()),
        )),
        (AccountRaw::as_select(), schema::account_codes::code.nullable()),
    )
    .filter(schema::accounts::network_account_id_prefix.eq(Some(i64::from(id_prefix))))
    .get_result::<(AccountRaw, Option<Vec<u8>>)>(conn)
    .optional()
    .map_err(DatabaseError::Diesel)?;

    let result: Result<Option<AccountInfo>, DatabaseError> = maybe_info
        .map(AccountWithCodeRawJoined::from)
        .map(std::convert::TryInto::<AccountInfo>::try_into)
        .transpose();

    result
}

/// Select all account commitments from the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// The vector with the account id and corresponding commitment, or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     account_id,
///     account_commitment
/// FROM
///     accounts
/// ORDER BY
///     block_num ASC
/// ```
pub(crate) fn select_all_account_commitments(
    conn: &mut SqliteConnection,
) -> Result<Vec<(AccountId, Word)>, DatabaseError> {
    let raw = SelectDsl::select(
        schema::accounts::table,
        (schema::accounts::account_id, schema::accounts::account_commitment),
    )
    .order_by(schema::accounts::block_num.asc())
    .load::<(Vec<u8>, Vec<u8>)>(conn)?;

    Result::<Vec<_>, DatabaseError>::from_iter(raw.into_iter().map(
        |(ref account, ref commitment)| {
            Ok((AccountId::read_from_bytes(account)?, Word::read_from_bytes(commitment)?))
        },
    ))
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
    const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024; // 2 MB
    const ROW_OVERHEAD_BYTES: usize = 2 * size_of::<Word>() + size_of::<u32>(); // key + asset + block_num
    const MAX_ROWS: usize = MAX_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

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
        && raw.len() >= MAX_ROWS
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

/// Select [`AccountSummary`] from the DB using the given [`SqliteConnection`], given that the
/// account update was in the given block range (inclusive).
///
/// # Returns
///
/// The vector of [`AccountSummary`] with the matching accounts.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     account_id,
///     account_commitment,
///     block_num
/// FROM
///     accounts
/// WHERE
///     block_num > ?1 AND
///     block_num <= ?2 AND
///     account_id IN (?3)
/// ORDER BY
///     block_num ASC
/// ```
pub fn select_accounts_by_block_range(
    conn: &mut SqliteConnection,
    account_ids: &[AccountId],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<Vec<AccountSummary>, DatabaseError> {
    QueryParamAccountIdLimit::check(account_ids.len())?;

    let desired_account_ids = serialize_vec(account_ids);
    let raw: Vec<AccountSummaryRaw> =
        SelectDsl::select(schema::accounts::table, AccountSummaryRaw::as_select())
            .filter(schema::accounts::block_num.gt(block_range.start().to_raw_sql()))
            .filter(schema::accounts::block_num.le(block_range.end().to_raw_sql()))
            .filter(schema::accounts::account_id.eq_any(desired_account_ids))
            .order(schema::accounts::block_num.asc())
            .load::<AccountSummaryRaw>(conn)?;
    // SAFETY `From` implies `TryFrom<Error=Infallible`, which is the case for `AccountSummaryRaw`
    // -> `AccountSummary`
    Ok(vec_raw_try_into(raw).unwrap())
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
///     accounts.block_num,
///     accounts.storage,
///     accounts.vault,
///     accounts.nonce,
///     accounts.code_commitment,
///     account_codes.code
/// FROM
///     accounts
/// LEFT JOIN
///     account_codes ON accounts.code_commitment = account_codes.code_commitment
/// ORDER BY
///     block_num ASC
/// ```
#[cfg(test)]
pub(crate) fn select_all_accounts(
    conn: &mut SqliteConnection,
) -> Result<Vec<AccountInfo>, DatabaseError> {
    let accounts_raw = QueryDsl::select(
        schema::accounts::table.left_join(schema::account_codes::table.on(
            schema::accounts::code_commitment.eq(schema::account_codes::code_commitment.nullable()),
        )),
        (AccountRaw::as_select(), schema::account_codes::code.nullable()),
    )
    .load::<(AccountRaw, Option<Vec<u8>>)>(conn)?;
    let account_infos = vec_raw_try_into::<AccountInfo, AccountWithCodeRawJoined>(
        accounts_raw.into_iter().map(AccountWithCodeRawJoined::from),
    )?;
    Ok(account_infos)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMapValue {
    pub block_num: BlockNumber,
    pub slot_index: u8,
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
    pub fn from_raw_row(row: (i64, i32, Vec<u8>, Vec<u8>)) -> Result<Self, DatabaseError> {
        let (block_num, slot_index, key, value) = row;
        Ok(Self {
            block_num: BlockNumber::from_raw_sql(block_num)?,
            slot_index: raw_sql_to_slot(slot_index),
            key: Word::read_from_bytes(&key)?,
            value: Word::read_from_bytes(&value)?,
        })
    }
}

/// Select account storage map values from the DB using the given [`SqliteConnection`].
///
/// # Returns
///
/// A vector of tuples containing `(slot, key, value, is_latest_update)` for the given account.
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
    pub const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024; // 2 MB
    pub const ROW_OVERHEAD_BYTES: usize =
        2 * size_of::<Word>() + size_of::<u32>() + size_of::<u8>(); // key + value + block_num + slot_idx
    pub const MAX_ROWS: usize = MAX_PAYLOAD_BYTES / ROW_OVERHEAD_BYTES;

    if !account_id.is_public() {
        return Err(DatabaseError::AccountNotPublic(account_id));
    }

    if block_range.is_empty() {
        return Err(DatabaseError::InvalidBlockRange {
            from: *block_range.start(),
            to: *block_range.end(),
        });
    }

    let raw: Vec<(i64, i32, Vec<u8>, Vec<u8>)> =
        SelectDsl::select(t::table, (t::block_num, t::slot, t::key, t::value))
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
        && raw.len() >= MAX_ROWS
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

#[derive(Debug, Clone, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = schema::accounts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccountRaw {
    pub account_id: Vec<u8>,
    pub account_commitment: Vec<u8>,
    pub block_num: i64,
    pub storage: Option<Vec<u8>>,
    pub vault: Option<Vec<u8>>,
    pub nonce: Option<i64>,
}

#[derive(Debug, Clone, QueryableByName)]
pub struct AccountWithCodeRawJoined {
    #[diesel(embed)]
    pub account: AccountRaw,
    #[diesel(embed)]
    pub code: Option<Vec<u8>>,
}

impl From<(AccountRaw, Option<Vec<u8>>)> for AccountWithCodeRawJoined {
    fn from((account, code): (AccountRaw, Option<Vec<u8>>)) -> Self {
        Self { account, code }
    }
}

impl TryInto<proto::domain::account::AccountInfo> for AccountWithCodeRawJoined {
    type Error = DatabaseError;
    fn try_into(self) -> Result<proto::domain::account::AccountInfo, Self::Error> {
        use proto::domain::account::{AccountInfo, AccountSummary};

        let account_id = AccountId::read_from_bytes(&self.account.account_id[..])?;
        let account_commitment = Word::read_from_bytes(&self.account.account_commitment[..])?;
        let block_num = BlockNumber::from_raw_sql(self.account.block_num)?;
        let summary = AccountSummary {
            account_id,
            account_commitment,
            block_num,
        };
        let maybe_account = self.try_into()?;
        Ok(AccountInfo { summary, details: maybe_account })
    }
}

impl TryInto<Option<Account>> for AccountWithCodeRawJoined {
    type Error = DatabaseError;
    fn try_into(self) -> Result<Option<Account>, Self::Error> {
        let account_id = AccountId::read_from_bytes(&self.account.account_id[..])?;

        let details = if let (Some(vault), Some(storage), Some(nonce), Some(code)) =
            (self.account.vault, self.account.storage, self.account.nonce, self.code)
        {
            let vault = AssetVault::read_from_bytes(&vault)?;
            let storage = AccountStorage::read_from_bytes(&storage)?;
            let code = AccountCode::read_from_bytes(&code)?;
            let nonce = raw_sql_to_nonce(nonce);
            let nonce = Felt::new(nonce);
            let account = Account::new_unchecked(account_id, vault, storage, code, nonce, None);
            Some(account)
        } else {
            // a private account
            None
        };
        Ok(details)
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
/// This function will set `is_latest_update=true` for the new row and update any existing
/// row with the same `(account_id, vault_key)` tuple to `is_latest_update=false`.
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
        // is_latest_update=false
        let vault_key: Word = vault_key.into();
        let update_count = diesel::update(schema::account_vault_assets::table)
            .filter(
                schema::account_vault_assets::account_id
                    .eq(&account_id.to_bytes())
                    .and(schema::account_vault_assets::vault_key.eq(&vault_key.to_bytes()))
                    .and(schema::account_vault_assets::is_latest_update.eq(true)),
            )
            .set(schema::account_vault_assets::is_latest_update.eq(false))
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
/// This function will set `is_latest_update=true` for the new row and update any existing
/// row with the same `(account_id, slot, key)` tuple to `is_latest_update=false`.
///
/// # Returns
///
/// The number of affected rows.
pub(crate) fn insert_account_storage_map_value(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    slot: u8,
    key: Word,
    value: Word,
) -> Result<usize, DatabaseError> {
    let account_id = account_id.to_bytes();
    let key = key.to_bytes();
    let value = value.to_bytes();
    let slot = slot_to_raw_sql(slot);
    let block_num = block_num.to_raw_sql();

    let update_count = diesel::update(schema::account_storage_map_values::table)
        .filter(
            schema::account_storage_map_values::account_id
                .eq(&account_id)
                .and(schema::account_storage_map_values::slot.eq(slot))
                .and(schema::account_storage_map_values::key.eq(&key))
                .and(schema::account_storage_map_values::is_latest_update.eq(true)),
        )
        .set(schema::account_storage_map_values::is_latest_update.eq(false))
        .execute(conn)?;

    let record = AccountStorageMapRowInsert {
        account_id,
        key,
        value,
        slot,
        block_num,
        is_latest_update: true,
    };
    let insert_count = diesel::insert_into(schema::account_storage_map_values::table)
        .values(record)
        .execute(conn)?;

    Ok(update_count + insert_count)
}

/// Attention: Assumes the account details are NOT null! The schema explicitly allows this though!
#[allow(clippy::too_many_lines)]
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
    use proto::domain::account::NetworkAccountPrefix;

    fn select_details_stmt(
        conn: &mut SqliteConnection,
        account_id: AccountId,
    ) -> Result<Vec<Account>, DatabaseError> {
        let account_id = account_id.to_bytes();
        let accounts = SelectDsl::select(
            schema::accounts::table.left_join(
                schema::account_codes::table.on(schema::accounts::code_commitment
                    .eq(schema::account_codes::code_commitment.nullable())),
            ),
            (AccountRaw::as_select(), schema::account_codes::code.nullable()),
        )
        .filter(schema::accounts::account_id.eq(account_id))
        .get_results::<(AccountRaw, Option<Vec<u8>>)>(conn)?;

        // SELECT .. FROM accounts LEFT JOIN account_codes
        // ON accounts.code_commitment == account_codes.code_commitment

        let accounts = Result::from_iter(accounts.into_iter().filter_map(|x| {
            let account_with_code = AccountWithCodeRawJoined::from(x);
            account_with_code.try_into().transpose()
        }))?;
        Ok(accounts)
    }

    let mut count = 0;
    for update in accounts {
        let account_id = update.account_id();
        // Extract the 30-bit prefix to provide easy look ups for NTB
        // Do not store prefix for accounts that are not network
        let network_account_id_prefix = if account_id.is_network() {
            Some(NetworkAccountPrefix::try_from(account_id)?)
        } else {
            None
        };

        let full_account: Option<Account> = match update.details() {
            AccountUpdateDetails::Private => None,
            AccountUpdateDetails::Delta(delta) if delta.is_full_state() => {
                let account = Account::try_from(delta)?;
                debug_assert_eq!(account_id, account.id());

                if account.commitment() != update.final_state_commitment() {
                    return Err(DatabaseError::AccountCommitmentsMismatch {
                        calculated: account.commitment(),
                        expected: update.final_state_commitment(),
                    });
                }

                for (slot_idx, slot) in account.storage().slots().iter().enumerate() {
                    match slot {
                        StorageSlot::Value(_) => {},
                        StorageSlot::Map(storage_map) => {
                            for (key, value) in storage_map.entries() {
                                // SAFETY: We can safely unwrap the conversion to u8 because
                                // accounts have a limit of 255 storage elements
                                insert_account_storage_map_value(
                                    conn,
                                    account_id,
                                    block_num,
                                    u8::try_from(slot_idx).unwrap(),
                                    *key,
                                    *value,
                                )?;
                            }
                        },
                    }
                }

                Some(account)
            },
            AccountUpdateDetails::Delta(delta) => {
                let mut rows = select_details_stmt(conn, account_id)?.into_iter();
                let Some(account) = rows.next() else {
                    return Err(DatabaseError::AccountNotFoundInDb(account_id));
                };

                // --- process storage map updates ----------------------------

                for (&slot, map_delta) in delta.storage().maps() {
                    for (key, value) in map_delta.entries() {
                        insert_account_storage_map_value(
                            conn,
                            account_id,
                            block_num,
                            slot,
                            (*key).into(),
                            *value,
                        )?;
                    }
                }

                // apply delta to the account; we need to do this before we process asset updates
                // because we currently need to get the current value of fungible assets from the
                // account
                let account = apply_delta(account, delta, &update.final_state_commitment())?;

                // --- process asset updates ----------------------------------

                for (faucet_id, _) in delta.vault().fungible().iter() {
                    let current_amount = account.vault().get_balance(*faucet_id).unwrap();
                    let asset: Asset = FungibleAsset::new(*faucet_id, current_amount)?.into();
                    let asset_update_or_removal =
                        if current_amount == 0 { None } else { Some(asset) };

                    insert_account_vault_asset(
                        conn,
                        account.id(),
                        block_num,
                        asset.vault_key(),
                        asset_update_or_removal,
                    )?;
                }

                for (asset, delta_action) in delta.vault().non_fungible().iter() {
                    let asset_update = match delta_action {
                        NonFungibleDeltaAction::Add => Some(Asset::NonFungible(*asset)),
                        NonFungibleDeltaAction::Remove => None,
                    };
                    insert_account_vault_asset(
                        conn,
                        account.id(),
                        block_num,
                        asset.vault_key(),
                        asset_update,
                    )?;
                }

                Some(account)
            },
        };

        if let Some(code) = full_account.as_ref().map(Account::code) {
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

        let account_value = AccountRowInsert {
            account_id: account_id.to_bytes(),
            network_account_id_prefix: network_account_id_prefix
                .map(NetworkAccountPrefix::to_raw_sql),
            account_commitment: update.final_state_commitment().to_bytes(),
            block_num: block_num.to_raw_sql(),
            nonce: full_account.as_ref().map(|account| nonce_to_raw_sql(account.nonce())),
            storage: full_account.as_ref().map(|account| account.storage().to_bytes()),
            vault: full_account.as_ref().map(|account| account.vault().to_bytes()),
            code_commitment: full_account
                .as_ref()
                .map(|account| account.code().commitment().to_bytes()),
        };

        let v = account_value.clone();
        let inserted = diesel::insert_into(schema::accounts::table)
            .values(&v)
            .on_conflict(schema::accounts::account_id)
            .do_update()
            .set(account_value)
            .execute(conn)?;

        debug_assert_eq!(inserted, 1);

        count += inserted;
    }

    Ok(count)
}

/// Deserializes account and applies account delta.
pub(crate) fn apply_delta(
    mut account: Account,
    delta: &AccountDelta,
    final_state_commitment: &Word,
) -> crate::db::Result<Account, DatabaseError> {
    account.apply_delta(delta)?;

    let actual_commitment = account.commitment();
    if &actual_commitment != final_state_commitment {
        return Err(DatabaseError::AccountCommitmentsMismatch {
            calculated: actual_commitment,
            expected: *final_state_commitment,
        });
    }

    Ok(account)
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
    pub(crate) network_account_id_prefix: Option<i64>,
    pub(crate) block_num: i64,
    pub(crate) account_commitment: Vec<u8>,
    pub(crate) code_commitment: Option<Vec<u8>>,
    pub(crate) storage: Option<Vec<u8>>,
    pub(crate) vault: Option<Vec<u8>>,
    pub(crate) nonce: Option<i64>,
}

#[derive(Insertable, AsChangeset, Debug, Clone)]
#[diesel(table_name = schema::account_vault_assets)]
pub(crate) struct AccountAssetRowInsert {
    pub(crate) account_id: Vec<u8>,
    pub(crate) block_num: i64,
    pub(crate) vault_key: Vec<u8>,
    pub(crate) asset: Option<Vec<u8>>,
    pub(crate) is_latest_update: bool,
}

impl AccountAssetRowInsert {
    pub(crate) fn new(
        account_id: &AccountId,
        vault_key: &AssetVaultKey,
        block_num: BlockNumber,
        asset: Option<Asset>,
        is_latest_update: bool,
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
            is_latest_update,
        }
    }
}

#[derive(Insertable, AsChangeset, Debug, Clone)]
#[diesel(table_name = schema::account_storage_map_values)]
pub(crate) struct AccountStorageMapRowInsert {
    pub(crate) account_id: Vec<u8>,
    pub(crate) block_num: i64,
    pub(crate) slot: i32,
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) is_latest_update: bool,
}
