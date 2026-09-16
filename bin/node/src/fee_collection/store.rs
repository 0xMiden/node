use std::collections::BTreeSet;

use anyhow::Context;
use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountRequest,
    AccountStorageRequest,
    AccountVaultDetails,
};
use miden_protocol::account::Account;
use miden_protocol::asset::AssetVault;
use miden_protocol::note::Note;
use miden_protocol::{MAX_INPUT_NOTES_PER_TX, Word};

use super::FeeCollector;
use super::transaction::CollectionContext;

impl FeeCollector {
    pub(super) async fn collection_inputs(&self) -> anyhow::Result<(CollectionContext, Vec<Note>)> {
        self.state
            .with_view(async |view| {
                let block_header = view
                    .get_block_header(None, false)
                    .await?
                    .0
                    .context("chain tip header is missing")?;
                let protocol_config = view
                    .get_protocol_config(block_header.protocol_config_commitment())
                    .await?
                    .context("protocol configuration is missing")?;
                let template = &self.account_template;
                let response = view
                    .get_account(AccountRequest {
                        account_id: template.id(),
                        block_num: None,
                        details: Some(AccountDetailRequest {
                            code_commitment: None,
                            asset_vault_commitment: Some(Word::empty()),
                            storage_request: AccountStorageRequest::None,
                        }),
                    })
                    .await?;
                let details = response.details.context("batch builder wallet is missing")?;
                let AccountVaultDetails::Assets(assets) = details.vault_details else {
                    anyhow::bail!("batch builder wallet vault exceeds the account query limit");
                };
                let account = Account::new(
                    template.id(),
                    AssetVault::new(&assets)?,
                    template.storage().clone(),
                    template.code().clone(),
                    details.account_header.nonce(),
                    None,
                )?;
                anyhow::ensure!(
                    account.to_commitment() == response.witness.state_commitment(),
                    "batch builder account commitment does not match its witness"
                );
                let blockchain = view
                    .get_block_inclusion_proofs(block_header.block_num(), BTreeSet::new())
                    .await?;
                let notes =
                    view.get_unspent_p2id_notes(template.id(), MAX_INPUT_NOTES_PER_TX).await?;
                Ok((
                    CollectionContext {
                        account,
                        block_header,
                        protocol_config,
                        blockchain,
                    },
                    notes,
                ))
            })
            .await
    }
}
