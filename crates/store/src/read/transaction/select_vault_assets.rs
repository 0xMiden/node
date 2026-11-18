use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;

use super::ReadTransaction;
use crate::DatabaseError;

impl ReadTransaction<'_> {
    /// Returns the assets in the vault of `account_id` as of `block_num`.
    ///
    /// The result holds at most [`AccountVaultDetails::MAX_RETURN_ENTRIES`] + 1 assets, so a vault
    /// over the response limit can be detected without reading every asset.
    ///
    /// [`AccountVaultDetails::MAX_RETURN_ENTRIES`]: miden_node_proto::domain::account::AccountVaultDetails::MAX_RETURN_ENTRIES
    pub fn select_vault_assets(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<Vec<Asset>, DatabaseError> {
        crate::db::queries::select_vault_at_block(self.inner, account_id, block_num)
    }
}
