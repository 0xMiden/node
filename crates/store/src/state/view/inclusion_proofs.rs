//! Inclusion proof query.
//!
//! Provides note and block inclusion proofs relative to a reference block. The reference block
//! cannot be newer than the view's chain tip.

use std::collections::{BTreeMap, BTreeSet};

use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, NoteInclusionProof};
use miden_protocol::transaction::PartialBlockchain;

use super::StateView;
use crate::errors::{GetBlockInclusionProofsError, GetNoteInclusionProofsError};

impl StateView {
    /// Fetches inclusion proofs for notes included at or before the reference block.
    pub async fn get_note_inclusion_proofs(
        &self,
        reference_block: BlockNumber,
        note_ids: BTreeSet<NoteId>,
    ) -> Result<BTreeMap<NoteId, NoteInclusionProof>, GetNoteInclusionProofsError> {
        let latest_block_num = self.tip();
        let reference_block = self.scope_block(reference_block).ok_or(
            GetNoteInclusionProofsError::ReferenceBlockAfterTip {
                reference_block,
                latest_block_num: *latest_block_num,
            },
        )?;

        let note_commitments = note_ids.into_iter().map(|note_id| note_id.as_word()).collect();
        self.db
            .select_note_inclusion_proofs(note_commitments, reference_block)
            .await
            .map_err(GetNoteInclusionProofsError::SelectNoteInclusionProofError)
    }

    /// Fetches inclusion proofs for blocks relative to the reference block.
    ///
    /// The returned partial blockchain contains all requested blocks before the reference block.
    pub async fn get_block_inclusion_proofs(
        &self,
        reference_block: BlockNumber,
        block_numbers: BTreeSet<BlockNumber>,
    ) -> Result<PartialBlockchain, GetBlockInclusionProofsError> {
        let latest_block_num = self.tip();
        let reference_block = self.scope_block(reference_block).ok_or(
            GetBlockInclusionProofsError::ReferenceBlockAfterTip {
                reference_block,
                latest_block_num: *latest_block_num,
            },
        )?;

        if let Some(&block_num) = block_numbers.last()
            && block_num > *reference_block
        {
            return Err(GetBlockInclusionProofsError::BlockAfterReferenceBlock {
                block_num,
                reference_block: *reference_block,
            });
        }

        let mut blocks = block_numbers;

        // The partial blockchain describes the chain state before the reference block.
        blocks.remove(&*reference_block);

        // All blocks are at or below the reference block and the view tip.
        let scoped_blocks = blocks
            .iter()
            .map(|&block| {
                self.scope_block(block)
                    .expect("requested blocks must not exceed the reference block")
            })
            .collect::<Vec<_>>();

        // SAFETY:
        // - The reference block was scoped against the view's blockchain.
        // - The reference block was removed from the set.
        // - All remaining block numbers are less than the reference block.
        let partial_mmr = self
            .blockchain()
            .partial_mmr_from_blocks(&blocks, *reference_block)
            .expect("all requested blocks must exist before the reference block");

        let headers = self
            .db
            .select_block_headers(scoped_blocks.into_iter())
            .await
            .map_err(GetBlockInclusionProofsError::SelectBlockHeaderError)?;

        // SAFETY:
        // - The headers match the blocks in the partial MMR.
        // - No header exceeds the chain length of the partial MMR.
        // - The BTreeSet removes duplicate block numbers.
        //
        // The headers and the partial MMR use the same block set. The unchecked constructor is safe.
        Ok(PartialBlockchain::new_unchecked(partial_mmr, headers)
            .expect("partial mmr and block headers should be consistent"))
    }
}

#[cfg(test)]
mod tests {
    use miden_node_utils::fee::{test_fee_params, test_protocol_config};
    use miden_protocol::block::ValidatorConfig;
    use miden_protocol::testing::random_secret_key::random_secret_key;

    use super::*;
    use crate::GenesisState;
    use crate::state::State;

    #[tokio::test]
    async fn block_inclusion_proofs_use_the_requested_block() {
        let data_directory = tempfile::tempdir().expect("tempdir should be created");
        bootstrap_store(data_directory.path());
        let (state, _block_writer, _proof_writer) = State::for_tests(data_directory.path()).await;

        let partial_blockchain = state
            .view()
            .get_block_inclusion_proofs(BlockNumber::GENESIS, BTreeSet::new())
            .await
            .expect("block inclusion proofs should be returned");
        assert_eq!(partial_blockchain.chain_length(), BlockNumber::GENESIS);

        let error = state
            .view()
            .get_block_inclusion_proofs(
                BlockNumber::GENESIS.child(),
                BTreeSet::from([BlockNumber::GENESIS]),
            )
            .await
            .expect_err("a reference block after the tip should fail");
        assert!(matches!(
            error,
            GetBlockInclusionProofsError::ReferenceBlockAfterTip {
                reference_block,
                latest_block_num,
            } if reference_block == BlockNumber::GENESIS.child()
                && latest_block_num == BlockNumber::GENESIS
        ));

        let error = state
            .view()
            .get_block_inclusion_proofs(
                BlockNumber::GENESIS,
                BTreeSet::from([BlockNumber::GENESIS.child()]),
            )
            .await
            .expect_err("a requested block after the reference block should fail");
        assert!(matches!(
            error,
            GetBlockInclusionProofsError::BlockAfterReferenceBlock {
                block_num,
                reference_block,
            } if block_num == BlockNumber::GENESIS.child()
                && reference_block == BlockNumber::GENESIS
        ));
    }

    #[tokio::test]
    async fn note_inclusion_proofs_reject_a_reference_block_after_the_tip() {
        let data_directory = tempfile::tempdir().expect("tempdir should be created");
        bootstrap_store(data_directory.path());
        let (state, _block_writer, _proof_writer) = State::for_tests(data_directory.path()).await;

        let error = state
            .view()
            .get_note_inclusion_proofs(BlockNumber::GENESIS.child(), BTreeSet::new())
            .await
            .expect_err("a reference block after the tip should fail");
        assert!(matches!(
            error,
            GetNoteInclusionProofsError::ReferenceBlockAfterTip {
                reference_block,
                latest_block_num,
            } if reference_block == BlockNumber::GENESIS.child()
                && latest_block_num == BlockNumber::GENESIS
        ));
    }

    fn bootstrap_store(path: &std::path::Path) {
        let signer = random_secret_key();
        let genesis_state = GenesisState::new(
            vec![],
            test_fee_params(),
            1,
            1,
            ValidatorConfig::new(vec![signer.public_key()], 1)
                .expect("validator config should be valid"),
            test_protocol_config(),
        );
        let genesis_block = genesis_state.into_block().expect("genesis block should be created");

        State::bootstrap(genesis_block, path).expect("store should bootstrap");
    }
}
