use std::collections::HashSet;

use miden_node_db::sqlite::InList;
use miden_node_utils::limiter::{QueryParamAccountIdLimit, QueryParamLimiter};
use miden_protocol::account::AccountId;

use super::ReadTransaction;
use crate::db::queries::{NetworkAccountType, VALID_FOREVER};
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns the subset of `account_ids` whose latest state in this transaction's snapshot is a
    /// network account.
    pub fn filter_network_accounts(
        &self,
        account_ids: &[AccountId],
    ) -> Result<HashSet<AccountId>, DatabaseError> {
        QueryParamAccountIdLimit::check(account_ids.len())?;

        let ids = InList::from_values(account_ids);

        Ok(self
            .inner
            .query(SQL, &[&ids, &NetworkAccountType::Network, &VALID_FOREVER], |row| {
                row.get::<AccountId>(0)
            })?
            .into_iter()
            .collect())
    }
}
