use std::ops::RangeInclusive;
use std::sync::Arc;

use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrProof};
use tracing::instrument;

use super::State;
use crate::COMPONENT;
use crate::db::models::queries::StorageMapValuesPage;
use crate::db::{AccountVaultValue, NoteSyncUpdate, NullifierInfo};
use crate::errors::{DatabaseError, NoteSyncError, StateSyncError};

/// Estimated byte size of a [`NoteSyncBlock`] excluding its notes.
///
/// `BlockHeader` (~341 bytes) + MMR proof with 32 siblings (~1216 bytes).
const BLOCK_OVERHEAD_BYTES: usize = 1600;

/// Estimated byte size of a single [`NoteSyncRecord`].
///
/// Note ID (~38 bytes) + index + metadata (~26 bytes) + sparse merkle path with 16
/// siblings (~608 bytes).
const NOTE_RECORD_BYTES: usize = 700;

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

    /// Returns the chain MMR delta for the specified block range.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn sync_chain_mmr(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<MmrDelta, StateSyncError> {
        let inner = self.inner.read().await;

        let block_from = *block_range.start();
        let block_to = *block_range.end();

        if block_from == block_to {
            return Ok(MmrDelta {
                forest: Forest::new(block_from.as_usize()),
                data: vec![],
            });
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

        inner
            .blockchain
            .as_mmr()
            .get_delta(Forest::new(from_forest), Forest::new(to_forest))
            .map_err(StateSyncError::FailedToBuildMmrDelta)
    }

    /// Loads data to synchronize a client's notes.
    ///
    /// Returns as many blocks with matching notes as fit within the response payload limit
    /// ([`MAX_RESPONSE_PAYLOAD_BYTES`](miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES)).
    /// Each block includes its header and MMR proof at `block_range.end()`.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn sync_notes(
        &self,
        note_tags: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<Vec<(NoteSyncUpdate, MmrProof)>, NoteSyncError> {
        let checkpoint = *block_range.end();
        let note_tags: Arc<[u32]> = note_tags.into();

        let mut results = Vec::new();
        let mut accumulated_size: usize = 0;
        let mut current_from = *block_range.start();

        loop {
            let range = current_from..=checkpoint;
            let Some(note_sync) = self.db.get_note_sync(range, Arc::clone(&note_tags)).await?
            else {
                break;
            };

            accumulated_size += BLOCK_OVERHEAD_BYTES + note_sync.notes.len() * NOTE_RECORD_BYTES;

            if !results.is_empty() && accumulated_size > MAX_RESPONSE_PAYLOAD_BYTES {
                break;
            }

            let block_num = note_sync.block_header.block_num();

            // The MMR at `checkpoint` contains proofs for blocks 0..checkpoint-1
            if block_num >= checkpoint {
                break;
            }

            let mmr_proof = self.inner.read().await.blockchain.open_at(block_num, checkpoint)?;
            results.push((note_sync, mmr_proof));

            // The DB query uses `committed_at > block_range.start()` (exclusive),
            // so setting current_from to the found block is sufficient to skip it.
            current_from = block_num;
        }

        Ok(results)
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
