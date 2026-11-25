use anyhow::Context;
use miden_node_store::state::State;
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
    pub(super) async fn load(state: &State) -> anyhow::Result<Self> {
        state
            .read(|view| {
                let block_num = view.snapshot.block_num;
                let commitment = view
                    .tx
                    .select_protocol_config_commitment_at(block_num)?
                    .context("protocol configuration commitment is missing")?;
                let config = view
                    .tx
                    .select_protocol_config(commitment)?
                    .context("protocol configuration is missing")?;
                let id = config.fee_asset_id().faucet_id();
                let (header, _) = view
                    .tx
                    .select_account_header_with_storage_header(id, block_num)?
                    .context("native faucet account is missing")?;
                let code = view
                    .tx
                    .select_account_code(header.code_commitment())?
                    .context("native faucet account code is missing")?;
                Ok(Self { id, code })
            })
            .await
    }

    pub(super) async fn account_inputs(
        &self,
        state: &State,
        block: BlockNumber,
    ) -> anyhow::Result<AccountInputs> {
        let id = self.id;
        let (witness, header, storage_header) = state
            .read(move |view| {
                let witness = view
                    .snapshot
                    .account_tree
                    .open_at(id, block)
                    .context("native faucet witness is not available at the reference block")?;
                let (header, storage_header) = view
                    .tx
                    .select_account_header_with_storage_header(id, block)?
                    .context("native faucet account is missing")?;
                anyhow::Ok((witness, header, storage_header))
            })
            .await?;
        anyhow::ensure!(
            header.code_commitment() == self.code.commitment(),
            "native faucet code does not match the reference block",
        );
        let account = PartialAccount::new(
            id,
            header.nonce(),
            self.code.clone(),
            PartialStorage::new(storage_header, [])?,
            PartialVault::new(header.vault_root()),
            None,
        )?;
        Ok(AccountInputs::new(account, witness))
    }

    pub(super) async fn storage_map_witness(
        &self,
        state: &State,
        block: BlockNumber,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> anyhow::Result<StorageMapWitness> {
        let id = self.id;
        let code_commitment = self.code.commitment();
        state
            .read(move |view| {
                let (header, storage_header) = view
                    .tx
                    .select_account_header_with_storage_header(id, block)?
                    .context("native faucet account is missing")?;
                anyhow::ensure!(
                    header.code_commitment() == code_commitment,
                    "native faucet code does not match the reference block",
                );
                let slot_name = storage_header
                    .slots()
                    .find(|slot| {
                        slot.slot_type() == StorageSlotType::Map && slot.value() == map_root
                    })
                    .context("native faucet storage map is missing")?
                    .name();
                let proof = view
                    .snapshot
                    .open_storage_map_key(id, slot_name, block, map_key)
                    .context("native faucet storage map is not tracked at the reference block")??;
                Ok(StorageMapWitness::new(proof, [map_key])?)
            })
            .await
    }
}
