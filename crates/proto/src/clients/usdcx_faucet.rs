use anyhow::Result;
use miden_protocol::account::{AccountId, AccountStorage, StorageSlot, StorageSlotType};
use miden_protocol::block::BlockNumber;
use miden_standards::account::faucets::FungibleFaucet;

use super::{ForeignAccount, RpcClient};

/// The `USDCx` faucet state used to transfer the chain's fee asset.
#[derive(Clone)]
pub struct UsdcxFaucet(ForeignAccount);

impl UsdcxFaucet {
    /// Creates the faucet from its foreign account state.
    pub fn new(account: ForeignAccount) -> Self {
        Self(account)
    }

    /// The faucet account's ID.
    pub fn account_id(&self) -> AccountId {
        self.0.inputs().account().id()
    }

    /// Loads the faucet at the specified block.
    pub async fn load_at(rpc: &mut RpcClient, id: AccountId, block: BlockNumber) -> Result<Self> {
        Ok(Self::new(ForeignAccount::load_at(rpc, id, block).await?))
    }

    /// Updates the faucet to the specified block.
    pub async fn sync_to(&mut self, rpc: &mut RpcClient, block: BlockNumber) -> Result<()> {
        self.0.sync_to(rpc, block).await
    }

    /// Reads token metadata from a faucet's value slots without loading its storage maps.
    pub fn metadata(&self) -> Result<FungibleFaucet> {
        let faucet = self.0.inputs().account();
        anyhow::ensure!(
            faucet.code_interface().contains(FungibleFaucet::code().procedure_roots()),
            "the account does not implement the fungible faucet interface",
        );
        let storage = AccountStorage::new(
            faucet
                .storage()
                .header()
                .slots()
                .filter(|slot| slot.slot_type() == StorageSlotType::Value)
                .map(|slot| StorageSlot::with_value(slot.name().clone(), slot.value()))
                .collect(),
        )?;
        Ok(FungibleFaucet::try_from(&storage)?)
    }

    /// Returns the faucet's foreign account inputs for transaction execution.
    pub fn into_foreign_account(self) -> ForeignAccount {
        self.0
    }
}
