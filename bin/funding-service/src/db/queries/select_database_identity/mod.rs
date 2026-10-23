use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;
use miden_protocol::asset::AssetId;

use crate::db::DatabaseIdentity;

/// Reads the database's chain, funding account, and native asset binding.
pub fn select_database_identity(
    tx: &ReadTx<'_>,
) -> Result<Option<DatabaseIdentity>, DatabaseError> {
    Ok(tx
        .query(include_str!("select_database_identity.sql"), &[], |row| {
            Ok(DatabaseIdentity {
                genesis_commitment: row.get(0)?,
                funding_account_id: row.get(1)?,
                fee_asset_id: AssetId::new_fungible(row.get(2)?),
            })
        })?
        .into_iter()
        .next())
}
