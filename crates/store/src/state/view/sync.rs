use std::num::NonZeroUsize;
use std::ops::RangeInclusive;

use miden_node_tracing::miden_instrument;
use miden_node_utils::limiter::MAX_RESPONSE_PAYLOAD_BYTES;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber, BlockSignatures};
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrProof};

use super::StateView;
use crate::COMPONENT;
use crate::db::queries::{
    AccountStorageMapValuesPaged,
    AccountVaultAssets,
    NoteSyncMulti,
    NullifiersByPrefix,
    StorageMapCursor,
    StorageMapUpdatesPage,
    StorageMapValuesPage,
    TransactionsRecords,
};
use crate::db::{
    AccountVaultCursor,
    AccountVaultValue,
    AccountVaultValuesPage,
    NoteSyncUpdate,
    NullifierInfo,
    default_storage_map_entries_limit,
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
        let query = TransactionsRecords::new(account_ids, block_range.scoped_end());
        let page = self.db.page(query, block_range.start()).await?;
        Ok((page.last_block_included(block_range.end()), page.items))
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
    /// ([`MAX_RESPONSE_PAYLOAD_BYTES`]).
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

        let query =
            NoteSyncMulti::new(note_tags, block_range.scoped_end(), MAX_RESPONSE_PAYLOAD_BYTES);
        let page = self.db.page(query, block_range.start()).await?;
        let last_block_included = page.last_block_included(block_end);

        let mut results = Vec::new();

        for note_sync in page.items {
            let mmr_proof =
                self.blockchain().open_at(note_sync.block_header.block_num(), mmr_checkpoint)?;
            results.push((note_sync, mmr_proof));
        }

        Ok((results, last_block_included))
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
        assert_eq!(prefix_len, 16, "Only 16-bit prefixes are supported");

        let nullifier_prefixes =
            nullifier_prefixes.into_iter().map(|prefix| prefix as u16).collect::<Vec<_>>();
        let query =
            NullifiersByPrefix::new(prefix_len as u8, nullifier_prefixes, block_range.scoped_end());
        let page = self.db.page(query, block_range.start()).await?;
        let last_block_included = page.last_block_included(block_range.end());
        Ok((page.items, last_block_included))
    }

    // ACCOUNT STATE SYNCHRONIZATION
    // --------------------------------------------------------------------------------------------

    /// Returns account vault updates for specified account within a block range.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip, and [`RangeBelowRetention`](crate::errors::RangeBelowRetention) if the
    /// range ends below the account history retention window.
    pub async fn sync_account_vault(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(BlockNumber, Vec<AccountVaultValue>), DatabaseError> {
        let block_range = self.scope_retained_range(block_range)?;
        let query = AccountVaultAssets::new(account_id, block_range.scoped_end());
        let page = self.db.page(query, block_range.start()).await?;
        Ok((page.last_block_included(block_range.end()), page.items))
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

    /// Loads changed-account identities at the requested target; witnesses must use the same view.
    pub async fn sync_account_commitments_page(
        &self,
        ids: Vec<AccountId>,
        range: RangeInclusive<BlockNumber>,
        cursor: Option<AccountId>,
        page_size: NonZeroUsize,
    ) -> Result<crate::db::AccountCommitmentChangesPage, DatabaseError> {
        let range = self.scope_range(range)?;
        self.db.select_account_commitment_changes(ids, range, cursor, page_size).await
    }

    /// Looks up only transactions committed at or before the explicit target.
    pub async fn get_transactions_by_id_page(
        &self,
        ids: Vec<miden_protocol::transaction::TransactionId>,
        target: BlockNumber,
        cursor: Option<miden_protocol::transaction::TransactionId>,
        page_size: NonZeroUsize,
    ) -> Result<crate::db::TransactionsByIdPage, DatabaseError> {
        let target = self
            .scope_block(target)
            .ok_or(crate::RangeBeyondTip { chain_tip: *self.tip(), block_to: target })?;
        self.db.select_transactions_by_id(ids, target, cursor, page_size).await
    }

    /// Returns storage map values for syncing within a block range.
    ///
    /// Returns [`RangeBeyondTip`](crate::errors::RangeBeyondTip) if the range extends beyond this
    /// view's chain tip, and [`RangeBelowRetention`](crate::errors::RangeBelowRetention) if the
    /// range ends below the account history retention window.
    pub async fn sync_account_storage_maps(
        &self,
        account_id: AccountId,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<StorageMapValuesPage, DatabaseError> {
        let block_range = self.scope_retained_range(block_range)?;
        let query = AccountStorageMapValuesPaged::new(
            account_id,
            block_range.scoped_end(),
            default_storage_map_entries_limit(),
        );
        let page = self.db.page(query, block_range.start()).await?;
        Ok(StorageMapValuesPage {
            last_block_included: page.last_block_included(block_range.end()),
            values: page.items,
        })
    }
}

#[cfg(test)]
mod tests {
    use miden_node_utils::fee::{test_fee_params, test_protocol_config};
    use miden_protocol::block::{BlockBody, SignedBlock, ValidatorConfig};
    use miden_protocol::crypto::merkle::mmr::Mmr;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
    use miden_protocol::testing::random_secret_key::random_secret_key;
    use miden_protocol::transaction::OrderedTransactionHeaders;

    use super::*;
    use crate::GenesisState;
    use crate::db::HISTORICAL_BLOCK_RETENTION;
    use crate::errors::RangeBelowRetention;
    use crate::state::{BlockWriter, State};

    /// Applies `count` empty blocks on top of the current chain tip.
    async fn apply_empty_blocks(state: &State, writer: &mut BlockWriter, count: u32) {
        let view = state.view();
        let mut mmr = Mmr::new();
        let mut parent = None;
        for height in 0..=view.tip().as_u32() {
            let (header, _) = view.get_block_header(Some(height.into()), false).await.unwrap();
            let header = header.expect("block header should exist");
            mmr.add(header.commitment()).unwrap();
            parent = Some(header);
        }
        drop(view);
        let mut parent = parent.expect("chain should have a parent block");

        for _ in 0..count {
            let body = BlockBody::new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                OrderedTransactionHeaders::new_unchecked(Vec::new()),
            )
            .unwrap();
            let header = BlockHeader::new(
                parent.commitment(),
                parent.block_num().child(),
                mmr.peaks().hash_peaks(),
                parent.account_root(),
                parent.nullifier_root(),
                body.compute_block_note_tree().root(),
                body.transaction_commitment(),
                parent.validator_config().clone(),
                parent.fee_parameters().clone(),
                parent.protocol_config_commitment(),
                None,
                parent.timestamp() + 1,
            );
            let block = SignedBlock::new_unchecked(
                header.clone(),
                body,
                BlockSignatures::new(Vec::new()).unwrap(),
            );
            writer.apply_block(block, None).await.expect("empty block should apply");
            mmr.add(header.commitment()).unwrap();
            parent = header;
        }
    }

    async fn bootstrap_store(path: &std::path::Path) {
        let signer = random_secret_key();
        let genesis_block = GenesisState::new(
            vec![],
            test_fee_params(),
            1,
            ValidatorConfig::new(vec![signer.public_key()], 1)
                .expect("validator config should be valid"),
            test_protocol_config(),
        )
        .into_block()
        .expect("genesis block should be created");

        State::bootstrap(genesis_block, path).await.expect("store should bootstrap");
    }

    /// Account history rows are pruned once they fall out of the retention window. A sync range
    /// that ends below the window can miss updates, so it must be rejected instead of answered.
    #[tokio::test(flavor = "multi_thread")]
    async fn account_syncs_reject_ranges_that_end_below_the_retention_window() {
        let data_directory = tempfile::tempdir().expect("tempdir should be created");
        bootstrap_store(data_directory.path()).await;
        let (state, mut writer, _proof_writer) = State::for_tests(data_directory.path()).await;
        apply_empty_blocks(&state, &mut writer, HISTORICAL_BLOCK_RETENTION + 10).await;

        let view = state.view();
        let tip = *view.tip();
        let oldest_retained = BlockNumber::from(tip.as_u32() - HISTORICAL_BLOCK_RETENTION);
        let below_window = BlockNumber::from(oldest_retained.as_u32() - 1);
        let account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

        let vault = view.sync_account_vault(account_id, BlockNumber::GENESIS..=below_window).await;
        assert!(
            matches!(
                vault,
                Err(DatabaseError::RangeBelowRetention(RangeBelowRetention {
                    oldest_retained: oldest,
                    block_to,
                })) if oldest == oldest_retained && block_to == below_window
            ),
            "vault sync below the retention window must fail, got {vault:?}"
        );

        let storage = view
            .sync_account_storage_maps(account_id, BlockNumber::GENESIS..=below_window)
            .await;
        assert!(
            matches!(
                storage,
                Err(DatabaseError::RangeBelowRetention(RangeBelowRetention {
                    oldest_retained: oldest,
                    block_to,
                })) if oldest == oldest_retained && block_to == below_window
            ),
            "storage map sync below the retention window must fail, got {storage:?}"
        );

        // A range that ends at the oldest retained block is still complete.
        let (last_block, updates) = view
            .sync_account_vault(account_id, BlockNumber::GENESIS..=oldest_retained)
            .await
            .expect("vault sync at the retention boundary should succeed");
        assert_eq!(last_block, oldest_retained);
        assert!(updates.is_empty());
        view.sync_account_storage_maps(account_id, BlockNumber::GENESIS..=oldest_retained)
            .await
            .expect("storage map sync at the retention boundary should succeed");
    }
}
