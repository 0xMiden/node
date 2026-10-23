use miden_node_db::DatabaseError;
use miden_node_db::sqlite::WriteTx;

use crate::db::DatabaseIdentity;

/// Binds a new database to its chain, funding account, and native asset.
pub fn insert_database_identity(
    tx: &WriteTx<'_>,
    identity: &DatabaseIdentity,
) -> Result<(), DatabaseError> {
    tx.execute(
        include_str!("insert_database_identity.sql"),
        &[
            &identity.genesis_commitment,
            &identity.funding_account_id,
            &identity.fee_asset_id.faucet_id(),
        ],
    )?;
    Ok(())
}
