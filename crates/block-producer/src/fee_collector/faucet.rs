use anyhow::Context;
use miden_node_store::read::ReadView;
use miden_node_store::state::State;
use miden_protocol::account::{AccountCode, AccountId, PartialAccount, PartialStorage};
use miden_protocol::asset::PartialVault;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::AccountInputs;

/// Retains native faucet code and reads its state at the transaction reference block.
#[derive(Clone)]
pub(crate) struct FeeFaucet {
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

    /// Reads the native faucet account inputs at `block`.
    ///
    /// Callers read them together with the other transaction inputs, so the faucet state comes
    /// from the same snapshot as the reference block. The partial account holds the storage header
    /// but no map entries, which the executor requests from the data store when it needs them.
    pub(crate) fn account_inputs(
        &self,
        view: &ReadView<'_>,
        block: BlockNumber,
    ) -> anyhow::Result<AccountInputs> {
        let witness = view
            .snapshot
            .account_tree
            .open_at(self.id, block)
            .context("native faucet witness is not available at the reference block")?;
        let (header, storage_header) = view
            .tx
            .select_account_header_with_storage_header(self.id, block)?
            .context("native faucet account is missing")?;
        anyhow::ensure!(
            header.code_commitment() == self.code.commitment(),
            "native faucet code does not match the reference block",
        );
        let account = PartialAccount::new(
            self.id,
            header.nonce(),
            self.code.clone(),
            PartialStorage::new(storage_header, [])?,
            PartialVault::new(header.vault_root()),
            None,
        )?;
        Ok(AccountInputs::new(account, witness))
    }
}
