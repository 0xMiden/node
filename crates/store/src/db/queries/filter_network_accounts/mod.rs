//! Filters a set of accounts down to the network accounts among them.

use std::collections::HashSet;

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_protocol::account::AccountId;

use crate::db::queries::{NetworkAccountType, VALID_FOREVER};
use crate::errors::DatabaseError;

const SQL: &str = include_str!("filter_network_accounts.sql");

/// Returns the subset of `account_ids` whose latest committed state is a network account.
///
/// Unknown ids and non-network accounts are silently omitted.
pub(crate) fn filter_network_accounts(
    tx: &ReadTx<'_>,
    account_ids: &[AccountId],
) -> Result<HashSet<AccountId>, DatabaseError> {
    QueryParamAccountIdLimit::check(account_ids.len())?;

    let ids = InList::from_values(account_ids);

    Ok(tx
        .query(SQL, &[&ids, &NetworkAccountType::Network, &VALID_FOREVER], |row| {
            row.get::<AccountId>(0)
        })?
        .into_iter()
        .collect())
}
