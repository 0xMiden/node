use std::collections::HashSet;

use miden_node_proto::domain::account::GetAccountResponse;
use miden_node_tracing::instrument;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

use super::StateView;
use crate::errors::{DatabaseError, GetAccountError};
use crate::read::open_account_witness;

impl StateView {
    /// Returns an account witness at a specific block, without account details.
    ///
    /// If `block_num` is provided, returns the witness at that historical block; otherwise,
    /// returns the witness at this view's tip. Only the account tree is read, so unlike
    /// [`ReadView::get_account`] this does not open a database transaction.
    ///
    /// [`ReadView::get_account`]: crate::read::ReadView::get_account
    #[instrument]
    pub fn get_account_witness(
        &self,
        account_id: AccountId,
        block_num: Option<BlockNumber>,
    ) -> Result<GetAccountResponse, GetAccountError> {
        let (block_num, witness) = self.with_inner_read_blocking(|snapshot| {
            open_account_witness(
                &snapshot.account_tree,
                snapshot.latest_block_num(),
                block_num,
                account_id,
            )
        })?;
        Ok(GetAccountResponse { block_num, witness, details: None })
    }
}

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
