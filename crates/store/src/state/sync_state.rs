use std::ops::RangeInclusive;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrProof};
use tracing::instrument;

use super::State;
use crate::COMPONENT;
use crate::db::models::queries::StorageMapValuesPage;
use crate::db::{AccountVaultValue, NoteSyncUpdate, NullifierInfo, StateSyncUpdate};
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

    /// Loads data to synchronize a client's notes.
    ///
    /// The client's request contains a list of tags, this method will return the first
    /// block with a matching tag, or the chain tip. All the other values are filter based on this
    /// block range.
    ///
    /// # Arguments
    ///
    /// - `note_tags`: The tags the client is interested in, resulting notes are restricted to the
    ///   first block containing a matching note.
    /// - `block_range`: The range of blocks from which to synchronize notes.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn sync_notes(
        &self,
        note_tags: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(NoteSyncUpdate, MmrProof, BlockNumber), NoteSyncError> {
        let inner = self.inner.read().await;

        let (note_sync, last_included_block) =
            self.db.get_note_sync(block_range, note_tags).await?;

        let mmr_proof = inner.blockchain.open(note_sync.block_header.block_num())?;

        Ok((note_sync, mmr_proof, last_included_block))
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
        self.db.select_storage_map_sync_values(account_id, block_range).await
    }

    // FULL STATE SYNCHRONIZATION
    // --------------------------------------------------------------------------------------------

    /// Loads data to synchronize a client.
    ///
    /// The client's request contains a list of note tags, this method will return the first
    /// block with a matching tag, or the chain tip. All the other values are filtered based on this
    /// block range.
    ///
    /// # Arguments
    ///
    /// - `block_num`: The last block *known* by the client, updates start from the next block.
    /// - `account_ids`: Include the account's commitment if their _last change_ was in the result's
    ///   block range.
    /// - `note_tags`: The tags the client is interested in, result is restricted to the first block
    ///   with any matches tags.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn sync_state(
        &self,
        block_num: BlockNumber,
        account_ids: Vec<AccountId>,
        note_tags: Vec<u32>,
    ) -> Result<(StateSyncUpdate, MmrDelta), StateSyncError> {
        let inner = self.inner.read().await;

        let state_sync = self.db.get_state_sync(block_num, account_ids, note_tags).await?;

        let delta = if block_num == state_sync.block_header.block_num() {
            // The client is in sync with the chain tip.
            MmrDelta {
                forest: Forest::new(block_num.as_usize()),
                data: vec![],
            }
        } else {
            // Important notes about the boundary conditions:
            //
            // - The Mmr forest is 1-indexed whereas the block number is 0-indexed. The Mmr root
            // contained in the block header always lag behind by one block, this is because the Mmr
            // leaves are hashes of block headers, and we can't have self-referential hashes. These
            // two points cancel out and don't require adjusting.
            // - Mmr::get_delta is inclusive, whereas the sync_state request block_num is defined to
            //   be
            // exclusive, so the from_forest has to be adjusted with a +1
            let from_forest = (block_num + 1).as_usize();
            let to_forest = state_sync.block_header.block_num().as_usize();
            inner
                .blockchain
                .as_mmr()
                .get_delta(Forest::new(from_forest), Forest::new(to_forest))
                .map_err(StateSyncError::FailedToBuildMmrDelta)?
        };

        Ok((state_sync, delta))
    }
}
