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
use miden_protocol::transaction::AccountInputs;

/// Retains native faucet code and loads its state at the transaction reference block.
#[derive(Clone)]
pub(super) struct FeeFaucet {
    pub(super) id: AccountId,
    pub(super) code: AccountCode,
}

impl FeeFaucet {
    pub(super) async fn load(view: &StateView) -> anyhow::Result<Self> {
        let commitment = view
            .get_protocol_config_commitment_at(*view.tip())
            .await?
            .context("protocol configuration commitment is missing")?;
        let config = view
            .get_protocol_config(commitment)
            .await?
            .context("protocol configuration is missing")?;
        let id = config.fee_asset_id().faucet_id();
        let response = view
            .get_account(AccountRequest {
                account_id: id,
                block_num: None,
                details: Some(AccountDetailRequest {
                    code_commitment: Some(Word::empty()),
                    asset_vault_commitment: None,
                    storage_request: AccountStorageRequest::None,
                }),
            })
            .await?;
        let details = response.details.context("native faucet account details are missing")?;
        let code = details.account_code.context("native faucet account code is missing")?;
        Ok(Self { id, code })
    }

    pub(super) async fn account_inputs(
        &self,
        view: &StateView,
        block: BlockNumber,
    ) -> anyhow::Result<AccountInputs> {
        let response = view
            .get_account(AccountRequest {
                account_id: self.id,
                block_num: Some(block),
                details: Some(AccountDetailRequest {
                    code_commitment: None,
                    asset_vault_commitment: None,
                    storage_request: AccountStorageRequest::None,
                }),
            })
            .await?;
        let details = response.details.context("native faucet account details are missing")?;
        anyhow::ensure!(
            details.account_header.code_commitment() == self.code.commitment(),
            "native faucet code does not match the reference block",
        );
        let account = PartialAccount::new(
            self.id,
            details.account_header.nonce(),
            self.code.clone(),
            PartialStorage::new(details.storage_details.header, [])?,
            PartialVault::new(details.account_header.vault_root()),
            None,
        )?;
        Ok(AccountInputs::new(account, response.witness))
    }

    pub(super) async fn storage_map_witness(
        &self,
        view: &StateView,
        block: BlockNumber,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> anyhow::Result<StorageMapWitness> {
        let account = self.account_inputs(view, block).await?;
        let slot_name = account
            .storage()
            .header()
            .slots()
            .find(|slot| slot.slot_type() == StorageSlotType::Map && slot.value() == map_root)
            .context("native faucet storage map is missing")?
            .name()
            .clone();
        let response = view
            .get_account(AccountRequest {
                account_id: self.id,
                block_num: Some(block),
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
