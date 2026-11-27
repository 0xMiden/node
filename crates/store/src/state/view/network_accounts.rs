use std::collections::HashSet;

use miden_protocol::account::AccountId;

use super::StateView;
use crate::errors::DatabaseError;

// NETWORK ACCOUNT CLASSIFICATION
// ================================================================================================

impl StateView {
    /// Filters `account_ids` down to the subset classified as network accounts.
    pub async fn filter_network_accounts(
        &self,
        account_ids: &[AccountId],
    ) -> Result<HashSet<AccountId>, DatabaseError> {
        self.db.filter_network_accounts(account_ids.to_vec()).await
    }
}
