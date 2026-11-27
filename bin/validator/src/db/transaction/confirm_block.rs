use anyhow::{Context, ensure};
use miden_protocol::block::SignedBlock;
use miden_protocol::protocol_config::ProtocolConfig;

use super::WriteTransaction;
use crate::db::{prune_expired_proving_inputs, queries, record_protocol_config_activation};

impl WriteTransaction<'_> {
    /// Installs a full node's block after verification against the local reconciliation anchor.
    pub(crate) fn confirm_block(
        &self,
        block: &SignedBlock,
        config: Option<ProtocolConfig>,
    ) -> anyhow::Result<()> {
        let chain = self.select_chain_state()?.context("validator has no genesis block")?;
        let header = block.header();
        if header == &chain.tip && chain.pending.is_none() {
            let stored = queries::load_block(self.inner, header.block_num())?
                .context("missing confirmed block")?;
            ensure!(stored == *block, "backup differs from the already confirmed block");
            return Ok(());
        }
        let height = header.block_num();
        block.validate(Some(&chain.tip))?;

        let config = if config.is_none()
            && header.protocol_config_commitment() != chain.tip.protocol_config_commitment()
        {
            queries::load_protocol_config(self.inner, header.protocol_config_commitment())?
        } else {
            config
        };
        if chain.pending.as_ref() == Some(header) {
            let stored = queries::load_block(self.inner, height)?.context("missing signed tip")?;
            ensure!(block.body() == stored.body(), "backup body differs from locally signed block");
            self.inner.execute(
                "UPDATE blocks SET block_data = ?1 WHERE block_num = ?2",
                &[block, &height],
            )?;
        } else {
            queries::delete_block(self.inner, height)?;
            self.inner
                .execute("DELETE FROM protocol_configs WHERE block_number = ?1", &[&height])?;
            queries::insert_block(self.inner, block, None)?;
            for (index, transaction) in block.body().transactions().as_slice().iter().enumerate() {
                let index = u32::try_from(index)?;
                self.inner.execute(
                    "INSERT INTO block_transactions (block_num, block_tx_index, transaction_id)
                     SELECT ?1, ?2, id FROM validated_transactions WHERE id = ?3",
                    &[&height, &index, &transaction.id()],
                )?;
            }
        }
        record_protocol_config_activation(self.inner, header, config)?;
        if header.validator_config().quorum() != chain.tip.validator_config().quorum()
            && self.select_pending_validator_quorum()? == Some(header.validator_config().quorum())
        {
            self.delete_pending_validator_quorum()?;
        }
        self.inner.execute(
            "INSERT INTO recovery_confirmation (singleton, block_num, missed_heights) VALUES (1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET block_num = excluded.block_num,
             missed_heights = missed_heights + excluded.missed_heights",
            &[&height, &chain.pending.is_none()],
        )?;
        prune_expired_proving_inputs(self.inner, self.proving_input_retention_blocks)?;
        Ok(())
    }
}
