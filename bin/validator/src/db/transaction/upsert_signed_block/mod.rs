use miden_node_db::DatabaseError;
use miden_node_proto::BlockProofRequest;
use miden_protocol::block::SignedBlock;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::TransactionHeader;

use super::WriteTransaction;
use crate::db::{persist_signed_block, prune_expired_proving_inputs, queries};

impl WriteTransaction<'_> {
    /// Stores the signed block, its proving inputs, and any protocol configuration activated at
    /// this height. Replacing a block also replaces its transaction links.
    pub(crate) fn upsert_signed_block(
        &self,
        block: &SignedBlock,
        protocol_config: Option<&ProtocolConfig>,
        proving_inputs: &BlockProofRequest,
    ) -> Result<(), DatabaseError> {
        let height = block.header().block_num();
        let replaced = queries::delete_block(self.inner, height)?;
        if let Some(config) = protocol_config {
            queries::insert_protocol_config(self.inner, config, height)?;
        } else if replaced {
            // The replacement inherits its parent's protocol configuration.
            self.inner
                .execute(include_str!("delete_protocol_config.sql"), &[&height.as_u32()])?;
        }
        let transactions = block.body().transactions().as_slice().iter().map(TransactionHeader::id);
        persist_signed_block(self.inner, block, transactions, Some(proving_inputs))?;
        prune_expired_proving_inputs(self.inner, self.proving_input_retention_blocks)
    }
}
