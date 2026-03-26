use diesel::prelude::{Queryable, QueryableByName};
use diesel::query_dsl::methods::SelectDsl;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl, SqliteConnection};
use miden_protocol::account::{AccountHeader, AccountId, AccountStorageHeader};
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Felt, Word};

use crate::db::models::conv::{SqlTypeConvert, raw_sql_to_nonce};
use crate::db::schema;
use crate::errors::DatabaseError;

// ACCOUNT HEADER
// ================================================================================================

#[derive(Debug, Clone, Queryable)]
struct AccountHeaderDataRaw {
    code_commitment: Option<Vec<u8>>,
    nonce: Option<i64>,
    storage_header: Option<Vec<u8>>,
    vault_root: Option<Vec<u8>>,
}

/// Queries the account header for a specific account at a specific block number.
///
/// This reconstructs the `AccountHeader` by reading from the `accounts` table:
/// - `account_id`, `nonce`, `code_commitment`, `storage_header`, `vault_root`
///
/// Returns `None` if the account doesn't exist at that block.
///
/// # Arguments
///
/// * `conn` - Database connection
/// * `account_id` - The account ID to query
/// * `block_num` - The block number at which to query the account header
///
/// # Returns
///
/// * `Ok(Some((AccountHeader, AccountStorageHeader)))` - The headers if found
/// * `Ok(None)` - If account doesn't exist at that block
/// * `Err(DatabaseError)` - If there's a database error
pub(crate) fn select_account_header_with_storage_header_at_block(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<Option<(AccountHeader, AccountStorageHeader)>, DatabaseError> {
    use schema::accounts;

    let account_id_bytes = account_id.to_bytes();
    let block_num_sql = block_num.to_raw_sql();

    let account_data: Option<AccountHeaderDataRaw> = SelectDsl::select(
        accounts::table
            .filter(accounts::account_id.eq(&account_id_bytes))
            .filter(accounts::block_num.le(block_num_sql))
            .order(accounts::block_num.desc())
            .limit(1),
        (
            accounts::code_commitment,
            accounts::nonce,
            accounts::storage_header,
            accounts::vault_root,
        ),
    )
    .first(conn)
    .optional()?;

    let Some(AccountHeaderDataRaw {
        code_commitment: code_commitment_bytes,
        nonce: nonce_raw,
        storage_header: storage_header_blob,
        vault_root: vault_root_bytes,
    }) = account_data
    else {
        return Ok(None);
    };

    let storage_header = match &storage_header_blob {
        Some(blob) => AccountStorageHeader::read_from_bytes(blob)?,
        None => AccountStorageHeader::new(Vec::new())?,
    };

    let storage_commitment = storage_header.to_commitment();

    let code_commitment = code_commitment_bytes
        .map(|bytes| Word::read_from_bytes(&bytes))
        .transpose()?
        .unwrap_or(Word::default());

    let nonce = nonce_raw.map_or(Felt::ZERO, raw_sql_to_nonce);

    let vault_root = vault_root_bytes
        .map(|bytes| Word::read_from_bytes(&bytes))
        .transpose()?
        .unwrap_or(Word::default());

    let account_header =
        AccountHeader::new(account_id, nonce, vault_root, storage_commitment, code_commitment);

    Ok(Some((account_header, storage_header)))
}

// ACCOUNT VAULT
// ================================================================================================

/// Query vault assets at a specific block by finding the most recent update for each `vault_key`.
///
/// Uses a single raw SQL query with a subquery join:
/// ```sql
/// SELECT a.asset FROM account_vault_assets a
/// INNER JOIN (
///     SELECT vault_key, MAX(block_num) as max_block
///     FROM account_vault_assets
///     WHERE account_id = ? AND block_num <= ?
///     GROUP BY vault_key
/// ) latest ON a.vault_key = latest.vault_key AND a.block_num = latest.max_block
/// WHERE a.account_id = ?
/// ```
pub(crate) fn select_account_vault_at_block(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<Vec<Asset>, DatabaseError> {
    use diesel::sql_types::{BigInt, Binary};

    let account_id_bytes = account_id.to_bytes();
    let block_num_sql = block_num.to_raw_sql();

    let entries: Vec<Option<Vec<u8>>> = diesel::sql_query(
        r"
        SELECT a.asset FROM account_vault_assets a
        INNER JOIN (
            SELECT vault_key, MAX(block_num) as max_block
            FROM account_vault_assets
            WHERE account_id = ? AND block_num <= ?
            GROUP BY vault_key
        ) latest ON a.vault_key = latest.vault_key AND a.block_num = latest.max_block
        WHERE a.account_id = ?
        ",
    )
    .bind::<Binary, _>(&account_id_bytes)
    .bind::<BigInt, _>(block_num_sql)
    .bind::<Binary, _>(&account_id_bytes)
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
