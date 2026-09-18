use anyhow::Context;
use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountRequest,
    AccountStorageRequest,
    SlotData,
    StorageMapEntries,
    StorageMapRequest,
};
use miden_node_store::state::StateView;
use miden_protocol::Word;
use miden_protocol::account::{
    AssetCallbackFlag,
    PartialAccount,
    PartialStorage,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotType,
};
use miden_protocol::asset::PartialVault;
use miden_protocol::block::BlockNumber;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::AccountInputs;

/// Supplies native faucet state for asset callbacks at one reference block.
pub(super) struct FeeFaucetInputs<'a> {
    pub(super) account: AccountInputs,
    pub(super) block: BlockNumber,
    view: &'a StateView,
}

impl<'a> FeeFaucetInputs<'a> {
    pub(super) async fn load(
        view: &'a StateView,
        block: BlockNumber,
        config: &ProtocolConfig,
    ) -> anyhow::Result<Option<Self>> {
        let account_id = config.fee_asset_id().faucet_id();
        if account_id.asset_callback_flag() == AssetCallbackFlag::Disabled {
            return Ok(None);
        }
        let response = view
            .get_account(AccountRequest {
                account_id,
                block_num: Some(block),
                details: Some(AccountDetailRequest {
                    code_commitment: Some(Word::empty()),
                    asset_vault_commitment: None,
                    storage_request: AccountStorageRequest::None,
                }),
            })
            .await?;
        let details = response.details.context("native faucet account details are missing")?;
        let account = PartialAccount::new(
            account_id,
            details.account_header.nonce(),
            details.account_code.context("native faucet account code is missing")?,
            PartialStorage::new(details.storage_details.header, [])?,
            PartialVault::new(details.account_header.vault_root()),
            None,
        )?;
        Ok(Some(Self {
            account: AccountInputs::new(account, response.witness),
            block,
            view,
        }))
    }

    pub(super) async fn storage_map_witness(
        &self,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> anyhow::Result<StorageMapWitness> {
        let slot_name = self
            .account
            .storage()
            .header()
            .slots()
            .find(|slot| slot.slot_type() == StorageSlotType::Map && slot.value() == map_root)
            .context("native faucet storage map is missing")?
            .name()
            .clone();
        let response = self
            .view
            .get_account(AccountRequest {
                account_id: self.account.id(),
                block_num: Some(self.block),
                details: Some(AccountDetailRequest {
                    code_commitment: None,
                    asset_vault_commitment: None,
                    storage_request: AccountStorageRequest::Explicit(vec![StorageMapRequest {
                        slot_name: slot_name.clone(),
                        slot_data: SlotData::MapKeys(vec![map_key]),
                    }]),
                }),
            })
            .await?;
        let details = response.details.context("native faucet account details are missing")?;
        let map = details
            .storage_details
            .map_details
            .into_iter()
            .find(|map| map.slot_name == slot_name)
            .context("native faucet storage map witness is missing")?;
        let StorageMapEntries::PartialMap { partial_smt, .. } = map.entries else {
            anyhow::bail!("native faucet storage map witness is incomplete");
        };
        let proof = partial_smt.open(&map_key.hash().as_word())?;
        Ok(StorageMapWitness::new(proof, [map_key])?)
    }
}
