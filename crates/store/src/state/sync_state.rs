use std::ops::RangeInclusive;

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrProof};
use tracing::instrument;

use super::State;
use crate::COMPONENT;
use crate::db::models::queries::StorageMapValuesPage;
use crate::db::{AccountVaultValue, NoteSyncUpdate, NullifierInfo};
use crate::errors::{DatabaseError, NoteSyncError, StateSyncError};

// STATE SYNCHRONIZATION ENDPOINTS
// ================================================================================================

impl State {
    /// Returns the complete transaction records for the specified accounts within the specified
    /// block range, including state commitments and note IDs.
    pub async fn sync_transactions(
        &self,
        account_ids: Vec<AccountId>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<crate::db::TransactionRecord>), DatabaseError> {
        self.db.select_transactions_records(account_ids, block_range).await
    }

    /// Returns the chain MMR delta and the `block_to` block header for the specified block range.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn sync_chain_mmr(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockHeader, Option<MmrDelta>, Option<MmrProof>), StateSyncError> {
        let block_from = *block_range.start();
        let block_to = *block_range.end();

        // SAFETY: block_to has been validated to be <= the chain tip by the caller,
        // so it must exist in the database.
        let block_header = self
            .db
            .select_block_header_by_block_num(Some(block_to))
            .await?
            .expect("block_to should exist in the database");

        if block_from == block_to {
            return Ok((block_header, None, None));
        }

        // Important notes about the boundary conditions:
        //
        // - The Mmr forest is 1-indexed whereas the block number is 0-indexed. The Mmr root
        //   contained in the block header always lag behind by one block, this is because the Mmr
        //   leaves are hashes of block headers, and we can't have self-referential hashes. These
        //   two points cancel out and don't require adjusting.
        // - Mmr::get_delta is inclusive, whereas the sync request block_from is defined to be the
        //   last block already present in the caller's MMR. The delta should therefore start at the
        //   next block, so the from_forest has to be adjusted with a +1.
        let from_forest = (block_from + 1).as_usize();
        let to_forest = block_to.as_usize();

        let (mmr_delta, mmr_proof) = {
            let inner = self.inner.read().await;

            inner.blockchain.num_blocks();

            let mmr_delta = inner
                .blockchain
                .as_mmr()
                .get_delta(Forest::new(from_forest), Forest::new(to_forest))
                .map_err(StateSyncError::FailedToBuildMmrDelta)?;

            // The MMR at forest N contains proofs for blocks 0..N-1, so we use block_to + 1 to
            // include the proof for block_to.
            // SAFETY: it is ensured that block_to <= chain_tip, and the blockchain MMR always has
            // at least chain_tip + 1 leaves.
            let mmr_proof = inner.blockchain.open_at(block_to, block_to + 1)?;

            (mmr_delta, mmr_proof)
        };

        Ok((block_header, Some(mmr_delta), Some(mmr_proof)))
    }

    /// Loads data to synchronize a client's notes.
    ///
    /// Returns as many blocks with matching notes as fit within the response payload limit
    /// ([`MAX_RESPONSE_PAYLOAD_BYTES`](miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES)).
    /// Each block includes its header and MMR proof at forest `block_range.end() + 1`.
    ///
    /// Also returns the last block number checked. If this equals `block_range.end()`, the
    /// sync is complete.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn sync_notes(
        &self,
        note_tags: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<(NoteSyncUpdate, MmrProof)>, BlockNumber), NoteSyncError> {
        let block_end = *block_range.end();
        // The MMR at forest N contains proofs for blocks 0..N-1, so we use block_end + 1 to
        // include the proof for block_end.
        // SAFETY: it is ensured that block_end <= chain_tip, and the blockchain MMR always has
        // at least chain_tip + 1 leaves.
        let mmr_checkpoint = block_end + 1;

        let note_syncs = self.db.get_note_sync_multi(block_range, note_tags.into()).await?;

        let mut results = Vec::new();

        for note_sync in note_syncs {
            let mmr_proof = self
                .inner
                .read()
                .await
                .blockchain
                .open_at(note_sync.block_header.block_num(), mmr_checkpoint)?;
            results.push((note_sync, mmr_proof));
        }

        // if results is empty, return `block_end` since the sync is complete.
        let last_block_checked =
            results.last().map_or(block_end, |(update, _)| update.block_header.block_num());

        Ok((results, last_block_checked))
    }

    pub async fn sync_nullifiers(
        &self,
        prefix_len: u32,
        nullifier_prefixes: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<NullifierInfo>, BlockNumber), DatabaseError> {
        self.db
            .select_nullifiers_by_prefix(prefix_len, nullifier_prefixes, block_range)
            .await
    }

    // ACCOUNT STATE SYNCHRONIZATION
    // --------------------------------------------------------------------------------------------

    /// Returns account vault updates for specified account within a block range.
    pub async fn sync_account_vault(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<AccountVaultValue>), DatabaseError> {
        self.db.get_account_vault_sync(account_id, block_range).await
    }

    /// Returns storage map values for syncing within a block range.
    pub async fn sync_account_storage_maps(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<StorageMapValuesPage, DatabaseError> {
        self.db.select_storage_map_sync_values(account_id, block_range, None).await
    }
}
