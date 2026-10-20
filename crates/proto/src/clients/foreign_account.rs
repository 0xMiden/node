use std::sync::Arc;

use anyhow::{Context, Result};
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountId,
    PartialAccount,
    PartialStorage,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotType,
};
use miden_protocol::asset::PartialVault;
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::transaction::AccountInputs;

use super::RpcClient;
use crate::DecodeMessageExt;
use crate::domain::account::{GetAccountResponse, StorageMapEntries};
use crate::generated::miden::node::v1::GetAccountRequest;
use crate::generated::miden::node::v1::get_account_request::AccountDetailRequest;
use crate::generated::miden::node::v1::get_account_request::account_detail_request::{StorageMapDetailRequest, StorageMapDetailRequests, StorageRequest, storage_map_detail_request};
use crate::generated::miden::node::v1::get_account_request::account_detail_request::storage_map_detail_request::MapKeys;

#[cfg(test)]
mod tests;

/// A partial foreign account and its account-tree witness.
#[derive(Clone)]
pub struct ForeignAccount(Arc<AccountInputs>);

impl ForeignAccount {
    /// Creates a foreign account from locally available state and its account-tree witness.
    pub fn from_account(account: Account, witness: AccountWitness) -> Self {
        let (id, vault, storage, code, nonce, seed) = account.into_parts();
        let partial = PartialAccount::new(
            id,
            nonce,
            code,
            PartialStorage::new_full(storage),
            PartialVault::new_minimal(&vault),
            seed,
        )
        .expect("a valid account has a valid partial representation");
        Self(Arc::new(AccountInputs::new(partial, witness)))
    }

    /// Loads account code, storage headers and an account-tree witness at the reference block.
    pub async fn load_at(rpc: &mut RpcClient, id: AccountId, block: BlockNumber) -> Result<Self> {
        Self::load_with_code(rpc, id, block, None).await
    }

    /// Updates the account to the specified block.
    ///
    /// Existing clones keep their state. A failed sync leaves this account unchanged.
    pub async fn sync_to(&mut self, rpc: &mut RpcClient, block: BlockNumber) -> Result<()> {
        let account = self.0.account();
        let updated =
            Self::load_with_code(rpc, account.id(), block, Some(account.code().clone())).await?;
        *self = updated;
        Ok(())
    }

    async fn load_with_code(
        rpc: &mut RpcClient,
        id: AccountId,
        block: BlockNumber,
        cached_code: Option<AccountCode>,
    ) -> Result<Self> {
        let code_commitment = cached_code.as_ref().map_or(Word::empty(), AccountCode::commitment);
        let response = rpc
            .get_account(GetAccountRequest {
                account_id: Some(id.into()),
                block_num: Some(block.into()),
                details: Some(AccountDetailRequest {
                    code_commitment: Some(code_commitment.into()),
                    vault_request: None,
                    storage_request: None,
                }),
            })
            .await?
            .into_inner()
            .decode_and_verify()?;
        check_response(&response, id, block)?;
        let details = response.details.context("foreign account details are missing")?;
        let code = details
            .account_code
            .or(cached_code)
            .context("foreign account code is missing")?;
        anyhow::ensure!(
            code.commitment() == details.account_header.code_commitment(),
            "foreign account code does not match its commitment at the reference block",
        );
        let account = PartialAccount::new(
            id,
            details.account_header.nonce(),
            code,
            PartialStorage::new(details.storage_details.header, [])?,
            PartialVault::new(details.account_header.vault_root()),
            None,
        )?;
        Ok(Self(Arc::new(AccountInputs::new(account, response.witness))))
    }

    /// Returns the partial account and its account-tree witness.
    pub fn inputs(&self) -> &AccountInputs {
        &self.0
    }

    /// Fetches a proof for one storage key, authenticated against the loaded account state.
    pub async fn storage_map_witness(
        &self,
        rpc: &mut RpcClient,
        block: BlockNumber,
        root: Word,
        key: StorageMapKey,
    ) -> Result<StorageMapWitness> {
        let account = self.0.account();
        let slot = account
            .storage()
            .header()
            .slots()
            .find(|slot| slot.slot_type() == StorageSlotType::Map && slot.value() == root)
            .context("foreign account storage map is missing")?;
        let response = rpc
            .get_account(GetAccountRequest {
                account_id: Some(account.id().into()),
                block_num: Some(block.into()),
                details: Some(AccountDetailRequest {
                    code_commitment: None,
                    vault_request: None,
                    storage_request: Some(StorageRequest::StorageMaps(StorageMapDetailRequests {
                        storage_maps: vec![StorageMapDetailRequest {
                            slot_name: slot.name().to_string(),
                            slot_data: Some(storage_map_detail_request::SlotData::MapKeys(
                                MapKeys { map_keys: vec![key.as_word().into()] },
                            )),
                        }],
                    })),
                }),
            })
            .await?
            .into_inner()
            .decode_and_verify()?;
        check_response(&response, account.id(), block)?;
        anyhow::ensure!(
            response.witness.state_commitment() == self.0.witness().state_commitment(),
            "foreign account state changed at the reference block"
        );
        let details = response.details.context("foreign account details are missing")?;
        let map = details
            .storage_details
            .map_details
            .into_iter()
            .find(|map| &map.slot_name == slot.name())
            .context("foreign account storage map proof is missing")?;
        let StorageMapEntries::PartialMap { partial_smt, map_keys } = map.entries else {
            anyhow::bail!("foreign account response did not include a partial storage map");
        };
        anyhow::ensure!(
            partial_smt.root() == root && map_keys.contains(&key),
            "foreign account storage proof does not match the requested root and key"
        );
        Ok(StorageMapWitness::new(partial_smt.open(&key.hash().as_word())?, [key])?)
    }
}

fn check_response(response: &GetAccountResponse, id: AccountId, block: BlockNumber) -> Result<()> {
    anyhow::ensure!(
        response.witness.id() == id,
        "foreign account response has the wrong account ID"
    );
    anyhow::ensure!(
        response.block_num == block,
        "foreign account response has the wrong reference block"
    );
    Ok(())
}
