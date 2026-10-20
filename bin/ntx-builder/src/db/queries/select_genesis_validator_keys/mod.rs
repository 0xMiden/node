//! Reads the validator signing keys retained from the genesis header.

use miden_node_db::DatabaseError;
use miden_node_db::sqlite::ReadTx;

use crate::db::GenesisValidatorKeys;

const SQL: &str = include_str!("select_genesis_validator_keys.sql");

/// Reads the validator signing keys retained from the genesis header, or `None` if the database
/// predates the column and must be re-bootstrapped.
pub fn select_genesis_validator_keys(
    tx: &ReadTx<'_>,
) -> Result<Option<GenesisValidatorKeys>, DatabaseError> {
    Ok(tx
        .query(SQL, &[], |row| row.get::<Option<GenesisValidatorKeys>>(0))?
        .into_iter()
        .next()
        .flatten())
}
