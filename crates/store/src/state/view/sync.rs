use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_tracing::miden_instrument;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber, BlockSignatures};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrProof};

use super::StateView;
use crate::COMPONENT;
use crate::db::queries::{StorageMapCursor, StorageMapUpdatesPage, StorageMapValuesPage};
use crate::db::{
    AccountVaultCursor,
    AccountVaultValue,
    AccountVaultValuesPage,
    NoteSyncUpdate,
    NullifierInfo,
};
use crate::errors::{DatabaseError, NoteSyncError, StateSyncError};

// STATE SYNCHRONIZATION ENDPOINTS
// ================================================================================================

/// A bounded page of note groups with proofs anchored at the requested target.
pub struct NoteSyncStreamPage {
    pub updates: Vec<(NoteSyncUpdate, MmrProof)>,
    pub next_cursor: Option<crate::NoteSyncCursor>,
}

impl StateView {
    /// Returns the complete transaction records for the specified accounts within the specified
    /// block range, including state commitments and note IDs.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip.
    pub async fn sync_transactions(
        &self,
        account_ids: Vec<AccountId>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<crate::db::TransactionRecord>), DatabaseError> {
        let block_range = self.scope_range(block_range)?;
        self.db.select_transactions_records(account_ids, block_range).await
    }

    /// Returns the chain MMR delta and the block header at the range's end for the specified
    /// block range.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn sync_chain_mmr(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(MmrDelta, BlockHeader, BlockSignatures), StateSyncError> {
        let block_range = self.scope_range(block_range)?;

        let block_from = block_range.start();
        let block_to = block_range.end();

        // The scoped range's end is committed (at or below this view's tip), so its header must
        // exist in the database.
        let (block_header, signatures) = self
            .db
            .select_block_header_and_signatures_by_block_num(block_range.scoped_end())
            .await?
            .expect("the range-end header should exist in the database");

        if block_from == block_to {
            return Ok((
                MmrDelta {
                    forest: Forest::new(block_from.as_usize()).expect("block index fits in u32"),
                    data: vec![],
                },
                block_header,
                signatures,
            ));
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

        let mmr_delta = self
            .blockchain()
            .as_mmr()
            .get_delta(
                Forest::new(from_forest).expect("from_forest fits in u32"),
                Forest::new(to_forest).expect("to_forest fits in u32"),
            )
            .map_err(StateSyncError::FailedToBuildMmrDelta)?;

        Ok((mmr_delta, block_header, signatures))
    }

    /// Loads bounded note records and authenticates each included block at forest target + 1.
    pub async fn sync_notes_v2_page(
        &self,
        tags: Vec<u32>,
        range: RangeInclusive<BlockNumber>,
        cursor: Option<crate::NoteSyncCursor>,
        page_size: NonZeroUsize,
    ) -> Result<NoteSyncStreamPage, NoteSyncError> {
        let range = self.scope_range(range)?;
        let checkpoint =
            range.end().as_u32().checked_add(1).ok_or(NoteSyncError::TargetOverflow)?;
        let page = self.db.select_note_sync_page(tags, range, cursor, page_size).await?;
        let mut updates: Vec<(NoteSyncUpdate, MmrProof)> = Vec::new();
        for note in page.notes {
            if updates
                .last()
                .is_some_and(|(update, _)| update.block_header.block_num() == note.block_num)
            {
                updates.last_mut().expect("matching group exists").0.notes.push(note);
            } else {
                let block_num =
                    self.scope_block(note.block_num).expect("query is scoped to the view");
                let header = self
                    .db
                    .select_block_header_by_block_num(Some(block_num))
                    .await?
                    .ok_or(NoteSyncError::EmptyBlockHeadersTable)?;
                let proof = self.blockchain().open_at(note.block_num, checkpoint.into())?;
                updates.push((NoteSyncUpdate { block_header: header, notes: vec![note] }, proof));
            }
        }
        Ok(NoteSyncStreamPage { updates, next_cursor: page.next_cursor })
    }

    /// Loads data to synchronize a client's notes.
    ///
    /// Returns as many blocks with matching notes as fit within the response payload limit
    /// ([`MAX_RESPONSE_PAYLOAD_BYTES`](miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES)).
    /// Each block includes its header and MMR proof at forest `block_range.end() + 1`.
    ///
    /// Also returns the last block number checked. If this equals `block_range.end()`, the
    /// sync is complete.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip.
    #[miden_instrument(
        level = "debug",
        target = COMPONENT,
        err,
    )]
    pub async fn sync_notes(
        &self,
        note_tags: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<(NoteSyncUpdate, MmrProof)>, BlockNumber), NoteSyncError> {
        let block_range = self.scope_range(block_range)?;

        let block_end = block_range.end();
        // The MMR at forest N contains proofs for blocks 0..N-1, so we use block_end + 1 to include
        // the proof for block_end. SAFETY: block_end <= this view's tip (checked above), and the
        // view's blockchain MMR always has at least tip + 1 leaves.
        let mmr_checkpoint = block_end + 1;

        let note_syncs = self.db.get_note_sync_multi(block_range, note_tags.into()).await?;

        let mut results = Vec::new();

        for note_sync in note_syncs {
            let mmr_proof =
                self.blockchain().open_at(note_sync.block_header.block_num(), mmr_checkpoint)?;
            results.push((note_sync, mmr_proof));
        }

        // if results is empty, return `block_end` since the sync is complete.
        let last_block_checked =
            results.last().map_or(block_end, |(update, _)| update.block_header.block_num());

        Ok((results, last_block_checked))
    }

    /// Returns nullifiers matching the given prefixes that were created within a block range.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip.
    pub async fn sync_nullifiers(
        &self,
        prefix_len: u32,
        nullifier_prefixes: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<NullifierInfo>, BlockNumber), DatabaseError> {
        let block_range = self.scope_range(block_range)?;
        self.db
            .select_nullifiers_by_prefix(prefix_len, nullifier_prefixes, block_range)
            .await
    }

    // ACCOUNT STATE SYNCHRONIZATION
    // --------------------------------------------------------------------------------------------

    /// Returns account vault updates for specified account within a block range.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip.
    pub async fn sync_account_vault(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<AccountVaultValue>), DatabaseError> {
        let block_range = self.scope_range(block_range)?;
        self.db.get_account_vault_sync(account_id, block_range).await
    }

    /// Returns a bounded page with one final update per vault key changed in a block range.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip. Returns [`DatabaseError::BlockPruned`] if the range targets a block older
    /// than the retained account history.
    pub async fn sync_account_vault_v2_page(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
        cursor: Option<AccountVaultCursor>,
        page_size: NonZeroUsize,
    ) -> Result<AccountVaultValuesPage, DatabaseError> {
        let block_range = self.scope_range(block_range)?;
        self.db
            .select_account_vault_updates_v2(account_id, block_range, cursor, page_size)
            .await
    }

    /// Loads a bounded page of squashed storage-map updates at the requested target.
    pub async fn sync_account_storage_maps_v2_page(
        &self,
        account_id: AccountId,
        range: RangeInclusive<BlockNumber>,
        cursor: Option<StorageMapCursor>,
        page_size: NonZeroUsize,
    ) -> Result<StorageMapUpdatesPage, DatabaseError> {
        let range = self.scope_range(range)?;
        self.db
            .select_account_storage_map_updates_v2(account_id, range, cursor, page_size)
            .await
    }

    /// Returns storage map values for syncing within a block range.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip.
    pub async fn sync_account_storage_maps(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<StorageMapValuesPage, DatabaseError> {
        let block_range = self.scope_range(block_range)?;
        self.db.select_storage_map_sync_values(account_id, block_range, None).await
    }
}
