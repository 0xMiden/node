use std::ops::RangeInclusive;

use miden_crypto::dsa::ecdsa_k256_keccak::Signature;
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
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn sync_chain_mmr(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(MmrDelta, BlockHeader, Signature), StateSyncError> {
        let block_from = *block_range.start();
        let block_to = *block_range.end();

        // SAFETY: block_to has been validated to be <= the effective tip (chain tip or latest
        // proven block) by the caller, so it must exist in the database.
        let (block_header, signature) = self
            .db
            .select_block_header_and_signature_by_block_num(block_to)
            .await?
            .expect("block_to should exist in the database");

        if block_from == block_to {
            return Ok((
                MmrDelta {
                    forest: Forest::new(block_from.as_usize()).expect("block index fits in u32"),
                    data: vec![],
                },
                block_header,
                signature,
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
            .inner
            .read()
            .await
            .blockchain
            .as_mmr()
            .get_delta(
                Forest::new(from_forest).expect("from_forest fits in u32"),
                Forest::new(to_forest).expect("to_forest fits in u32"),
            )
            .map_err(StateSyncError::FailedToBuildMmrDelta)?;

        Ok((mmr_delta, block_header, signature))
    }

    /// Loads data to synchronize a client's notes.
    ///
    /// Returns as many blocks with matching notes as fit within the response payload limit
    /// ([`MAX_RESPONSE_PAYLOAD_BYTES`](miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES)).
    /// Each block includes its header and MMR proof at forest `block_range.end() + 1`.
    ///
    /// Also returns the last block number checked. If this equals `block_range.end()`, the
    /// sync is complete.
    #[instrument(level = "debug", target = COMPONENT, skip_all, err)]
    pub async fn sync_notes(
        &self,
        note_tags: Vec<u32>,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<(NoteSyncUpdate, MmrProof)>, BlockNumber), NoteSyncError> {
        let block_end = *block_range.end();
        // The MMR at forest N contains proofs for blocks 0..N-1, so we use block_end + 1 to include
        // the proof for block_end. SAFETY: it is ensured that block_end <= chain_tip, and the
        // blockchain MMR always has at least chain_tip + 1 leaves.
        let mmr_checkpoint = block_end + 1;

        let note_syncs = self.db.get_note_sync_multi(block_range, note_tags.into()).await?;

        let mut results = Vec::new();

        {
            let inner = self.inner.read().await;

            for note_sync in note_syncs {
                let mmr_proof =
                    inner.blockchain.open_at(note_sync.block_header.block_num(), mmr_checkpoint)?;
                results.push((note_sync, mmr_proof));
            }
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
