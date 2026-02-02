//! Abstraction to synchronize state modifications.
//!
//! The [State] provides data access and modifications methods, its main purpose is to ensure that
//! data is atomically written, and that reads are consistent.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;

use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountDetails,
    AccountInfo,
    AccountRequest,
    AccountResponse,
    AccountStorageDetails,
    AccountStorageMapDetails,
    AccountVaultDetails,
    SlotData,
    StorageMapRequest,
};
use miden_node_proto::domain::batch::BatchInputs;
use miden_node_utils::formatting::format_array;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, StorageMapWitness, StorageSlotName};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::nullifier_tree::{NullifierTree, NullifierWitness};
use miden_protocol::block::{BlockHeader, BlockInputs, BlockNumber, Blockchain};
use miden_protocol::crypto::merkle::mmr::{MmrPeaks, MmrProof, PartialMmr};
use miden_protocol::crypto::merkle::smt::{LargeSmt, SmtProof, SmtStorage};
use miden_protocol::note::{NoteId, NoteScript, Nullifier};
use miden_protocol::transaction::PartialBlockchain;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, instrument};

use crate::accounts::AccountTreeWithHistory;
use crate::blocks::BlockStore;
use crate::db::models::Page;
use crate::db::{Db, NoteRecord, NullifierInfo};
use crate::errors::{
    ApplyBlockError,
    DatabaseError,
    GetBatchInputsError,
    GetBlockHeaderError,
    GetBlockInputsError,
    GetCurrentBlockchainDataError,
    StateInitializationError,
};
use crate::inner_forest::{InnerForest, WitnessError};
use crate::{COMPONENT, DataDirectory};

mod loader;

pub use loader::{
    ACCOUNT_TREE_STORAGE_DIR,
    NULLIFIER_TREE_STORAGE_DIR,
    StorageLoader,
    TreeStorage,
};
use loader::{load_mmr, load_smt_forest, verify_tree_consistency};

mod apply_block;
mod sync_state;

// STRUCTURES
// ================================================================================================

#[derive(Debug, Default)]
pub struct TransactionInputs {
    pub account_commitment: Word,
    pub nullifiers: Vec<NullifierInfo>,
    pub found_unauthenticated_notes: HashSet<Word>,
    pub new_account_id_prefix_is_unique: Option<bool>,
}

/// Container for state that needs to be updated atomically.
struct InnerState<S>
where
    S: SmtStorage,
{
    nullifier_tree: NullifierTree<LargeSmt<S>>,
    blockchain: Blockchain,
    account_tree: AccountTreeWithHistory<S>,
}

impl<S: SmtStorage> InnerState<S> {
    /// Returns the latest block number.
    fn latest_block_num(&self) -> BlockNumber {
        self.blockchain
            .chain_tip()
            .expect("chain should always have at least the genesis block")
    }
}

// CHAIN STATE
// ================================================================================================

/// The rollup state.
pub struct State {
    /// The database which stores block headers, nullifiers, notes, and the latest states of
    /// accounts.
    db: Arc<Db>,

    /// The block store which stores full block contents for all blocks.
    block_store: Arc<BlockStore>,

    /// Read-write lock used to prevent writing to a structure while it is being used.
    ///
    /// The lock is writer-preferring, meaning the writer won't be starved.
    inner: RwLock<InnerState<TreeStorage>>,

    /// Forest-related state `(SmtForest, storage_map_roots, vault_roots)` with its own lock.
    forest: RwLock<InnerForest>,

    /// To allow readers to access the tree data while an update in being performed, and prevent
    /// TOCTOU issues, there must be no concurrent writers. This locks to serialize the writers.
    writer: Mutex<()>,

    /// Request termination of the process due to a fatal internal state error.
    termination_ask: tokio::sync::mpsc::Sender<ApplyBlockError>,
}

impl State {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Loads the state from the data directory.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load(
        data_path: &Path,
        termination_ask: tokio::sync::mpsc::Sender<ApplyBlockError>,
    ) -> Result<Self, StateInitializationError> {
        let data_directory = DataDirectory::load(data_path.to_path_buf())
            .map_err(StateInitializationError::DataDirectoryLoadError)?;

        let block_store = Arc::new(
            BlockStore::load(data_directory.block_store_dir())
                .map_err(StateInitializationError::BlockStoreLoadError)?,
        );

        let database_filepath = data_directory.database_path();
        let mut db = Db::load(database_filepath.clone())
            .await
            .map_err(StateInitializationError::DatabaseLoadError)?;

        let blockchain = load_mmr(&mut db).await?;
        let latest_block_num = blockchain.chain_tip().unwrap_or(BlockNumber::GENESIS);

        let account_storage = TreeStorage::create(data_path, ACCOUNT_TREE_STORAGE_DIR)?;
        let account_tree = account_storage.load_account_tree(&mut db).await?;

        let nullifier_storage = TreeStorage::create(data_path, NULLIFIER_TREE_STORAGE_DIR)?;
        let nullifier_tree = nullifier_storage.load_nullifier_tree(&mut db).await?;

        // Verify that tree roots match the expected roots from the database.
        // This catches any divergence between persistent storage and the database caused by
        // corruption or incomplete shutdown.
        verify_tree_consistency(account_tree.root(), nullifier_tree.root(), &mut db).await?;

        let account_tree = AccountTreeWithHistory::new(account_tree, latest_block_num);

        let forest = load_smt_forest(&mut db, latest_block_num).await?;

        let inner = RwLock::new(InnerState { nullifier_tree, blockchain, account_tree });

        let forest = RwLock::new(forest);
        let writer = Mutex::new(());
        let db = Arc::new(db);

        Ok(Self {
            db,
            block_store,
            inner,
            forest,
            writer,
            termination_ask,
        })
    }

    // STATE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Queries a [BlockHeader] from the database, and returns it alongside its inclusion proof.
    ///
    /// If [None] is given as the value of `block_num`, the data for the latest [BlockHeader] is
    /// returned.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret(level = "debug"), err)]
    pub async fn get_block_header(
        &self,
        block_num: Option<BlockNumber>,
        include_mmr_proof: bool,
    ) -> Result<(Option<BlockHeader>, Option<MmrProof>), GetBlockHeaderError> {
        let block_header = self.db.select_block_header_by_block_num(block_num).await?;
        if let Some(header) = block_header {
            let mmr_proof = if include_mmr_proof {
                let inner = self.inner.read().await;
                let mmr_proof = inner.blockchain.open(header.block_num())?;
                Some(mmr_proof)
            } else {
                None
            };
            Ok((Some(header), mmr_proof))
        } else {
            Ok((None, None))
        }
    }

    /// Generates membership proofs for each one of the `nullifiers` against the latest nullifier
    /// tree.
    ///
    /// Note: these proofs are invalidated once the nullifier tree is modified, i.e. on a new block.
    #[instrument(level = "debug", target = COMPONENT, skip_all, ret)]
    pub async fn check_nullifiers(&self, nullifiers: &[Nullifier]) -> Vec<SmtProof> {
        let inner = self.inner.read().await;
        nullifiers
            .iter()
            .map(|n| inner.nullifier_tree.open(n))
            .map(NullifierWitness::into_proof)
            .collect()
    }

    /// Queries a list of notes from the database.
    ///
    /// If the provided list of [`NoteId`] given is empty or no note matches the provided
    /// [`NoteId`] an empty list is returned.
    pub async fn get_notes_by_id(
        &self,
        note_ids: Vec<NoteId>,
    ) -> Result<Vec<NoteRecord>, DatabaseError> {
        self.db.select_notes_by_id(note_ids).await
    }

    /// If the input block number is the current chain tip, `None` is returned.
    /// Otherwise, gets the current chain tip's block header with its corresponding MMR peaks.
    pub async fn get_current_blockchain_data(
        &self,
        block_num: Option<BlockNumber>,
    ) -> Result<Option<(BlockHeader, MmrPeaks)>, GetCurrentBlockchainDataError> {
        let blockchain = &self.inner.read().await.blockchain;
        if let Some(number) = block_num
            && number == self.latest_block_num().await
        {
            return Ok(None);
        }

        // SAFETY: `select_block_header_by_block_num` will always return `Some(chain_tip_header)`
        // when `None` is passed
        let block_header: BlockHeader = self
            .db
            .select_block_header_by_block_num(None)
            .await
            .map_err(GetCurrentBlockchainDataError::ErrorRetrievingBlockHeader)?
            .unwrap();
        let peaks = blockchain
            .peaks_at(block_header.block_num())
            .map_err(GetCurrentBlockchainDataError::InvalidPeaks)?;

        Ok(Some((block_header, peaks)))
    }

    /// Fetches the inputs for a transaction batch from the database.
    ///
    /// ## Inputs
    ///
    /// The function takes as input:
    /// - The tx reference blocks are the set of blocks referenced by transactions in the batch.
    /// - The unauthenticated note commitments are the set of commitments of unauthenticated notes
    ///   consumed by all transactions in the batch. For these notes, we attempt to find inclusion
    ///   proofs. Not all notes will exist in the DB necessarily, as some notes can be created and
    ///   consumed within the same batch.
    ///
    /// ## Outputs
    ///
    /// The function will return:
    /// - A block inclusion proof for all tx reference blocks and for all blocks which are
    ///   referenced by a note inclusion proof.
    /// - Note inclusion proofs for all notes that were found in the DB.
    /// - The block header that the batch should reference, i.e. the latest known block.
    pub async fn get_batch_inputs(
        &self,
        tx_reference_blocks: BTreeSet<BlockNumber>,
        unauthenticated_note_commitments: BTreeSet<Word>,
    ) -> Result<BatchInputs, GetBatchInputsError> {
        if tx_reference_blocks.is_empty() {
            return Err(GetBatchInputsError::TransactionBlockReferencesEmpty);
        }

        // First we grab note inclusion proofs for the known notes. These proofs only
        // prove that the note was included in a given block. We then also need to prove that
        // each of those blocks is included in the chain.
        let note_proofs = self
            .db
            .select_note_inclusion_proofs(unauthenticated_note_commitments)
            .await
            .map_err(GetBatchInputsError::SelectNoteInclusionProofError)?;

        // The set of blocks that the notes are included in.
        let note_blocks = note_proofs.values().map(|proof| proof.location().block_num());

        // Collect all blocks we need to query without duplicates, which is:
        // - all blocks for which we need to prove note inclusion.
        // - all blocks referenced by transactions in the batch.
        let mut blocks: BTreeSet<BlockNumber> = tx_reference_blocks;
        blocks.extend(note_blocks);

        // Scoped block to automatically drop the read lock guard as soon as we're done.
        // We also avoid accessing the db in the block as this would delay dropping the guard.
        let (batch_reference_block, partial_mmr) = {
            let inner_state = self.inner.read().await;

            let latest_block_num = inner_state.latest_block_num();

            let highest_block_num =
                *blocks.last().expect("we should have checked for empty block references");
            if highest_block_num > latest_block_num {
                return Err(GetBatchInputsError::UnknownTransactionBlockReference {
                    highest_block_num,
                    latest_block_num,
                });
            }

            // Remove the latest block from the to-be-tracked blocks as it will be the reference
            // block for the batch itself and thus added to the MMR within the batch kernel, so
            // there is no need to prove its inclusion.
            blocks.remove(&latest_block_num);

            // SAFETY:
            // - The latest block num was retrieved from the inner blockchain from which we will
            //   also retrieve the proofs, so it is guaranteed to exist in that chain.
            // - We have checked that no block number in the blocks set is greater than latest block
            //   number *and* latest block num was removed from the set. Therefore only block
            //   numbers smaller than latest block num remain in the set. Therefore all the block
            //   numbers are guaranteed to exist in the chain state at latest block num.
            let partial_mmr = inner_state
                .blockchain
                .partial_mmr_from_blocks(&blocks, latest_block_num)
                .expect("latest block num should exist and all blocks in set should be < than latest block");

            (latest_block_num, partial_mmr)
        };

        // Fetch the reference block of the batch as part of this query, so we can avoid looking it
        // up in a separate DB access.
        let mut headers = self
            .db
            .select_block_headers(blocks.into_iter().chain(std::iter::once(batch_reference_block)))
            .await
            .map_err(GetBatchInputsError::SelectBlockHeaderError)?;

        // Find and remove the batch reference block as we don't want to add it to the chain MMR.
        let header_index = headers
            .iter()
            .enumerate()
            .find_map(|(index, header)| {
                (header.block_num() == batch_reference_block).then_some(index)
            })
            .expect("DB should have returned the header of the batch reference block");

        // The order doesn't matter for PartialBlockchain::new, so swap remove is fine.
        let batch_reference_block_header = headers.swap_remove(header_index);

        // SAFETY: This should not error because:
        // - we're passing exactly the block headers that we've added to the partial MMR,
        // - so none of the block headers block numbers should exceed the chain length of the
        //   partial MMR,
        // - and we've added blocks to a BTreeSet, so there can be no duplicates.
        //
        // We construct headers and partial MMR in concert, so they are consistent. This is why we
        // can call the unchecked constructor.
        let partial_block_chain = PartialBlockchain::new_unchecked(partial_mmr, headers)
            .expect("partial mmr and block headers should be consistent");

        Ok(BatchInputs {
            batch_reference_block_header,
            note_proofs,
            partial_block_chain,
        })
    }

    /// Returns data needed by the block producer to construct and prove the next block.
    pub async fn get_block_inputs(
        &self,
        account_ids: Vec<AccountId>,
        nullifiers: Vec<Nullifier>,
        unauthenticated_note_commitments: BTreeSet<Word>,
        reference_blocks: BTreeSet<BlockNumber>,
    ) -> Result<BlockInputs, GetBlockInputsError> {
        // Get the note inclusion proofs from the DB.
        // We do this first so we have to acquire the lock to the state just once. There we need the
        // reference blocks of the note proofs to get their authentication paths in the chain MMR.
        let unauthenticated_note_proofs = self
            .db
            .select_note_inclusion_proofs(unauthenticated_note_commitments)
            .await
            .map_err(GetBlockInputsError::SelectNoteInclusionProofError)?;

        // The set of blocks that the notes are included in.
        let note_proof_reference_blocks =
            unauthenticated_note_proofs.values().map(|proof| proof.location().block_num());

        // Collect all blocks we need to prove inclusion for, without duplicates.
        let mut blocks = reference_blocks;
        blocks.extend(note_proof_reference_blocks);

        let (latest_block_number, account_witnesses, nullifier_witnesses, partial_mmr) =
            self.get_block_inputs_witnesses(&mut blocks, account_ids, nullifiers).await?;

        // Fetch the block headers for all blocks in the partial MMR plus the latest one which will
        // be used as the previous block header of the block being built.
        let mut headers = self
            .db
            .select_block_headers(blocks.into_iter().chain(std::iter::once(latest_block_number)))
            .await
            .map_err(GetBlockInputsError::SelectBlockHeaderError)?;

        // Find and remove the latest block as we must not add it to the chain MMR, since it is
        // not yet in the chain.
        let latest_block_header_index = headers
            .iter()
            .enumerate()
            .find_map(|(index, header)| {
                (header.block_num() == latest_block_number).then_some(index)
            })
            .expect("DB should have returned the header of the latest block header");

        // The order doesn't matter for PartialBlockchain::new, so swap remove is fine.
        let latest_block_header = headers.swap_remove(latest_block_header_index);

        // SAFETY: This should not error because:
        // - we're passing exactly the block headers that we've added to the partial MMR,
        // - so none of the block header's block numbers should exceed the chain length of the
        //   partial MMR,
        // - and we've added blocks to a BTreeSet, so there can be no duplicates.
        //
        // We construct headers and partial MMR in concert, so they are consistent. This is why we
        // can call the unchecked constructor.
        let partial_block_chain = PartialBlockchain::new_unchecked(partial_mmr, headers)
            .expect("partial mmr and block headers should be consistent");

        Ok(BlockInputs::new(
            latest_block_header,
            partial_block_chain,
            account_witnesses,
            nullifier_witnesses,
            unauthenticated_note_proofs,
        ))
    }

    /// Get account and nullifier witnesses for the requested account IDs and nullifier as well as
    /// the [`PartialMmr`] for the given blocks. The MMR won't contain the latest block and its
    /// number is removed from `blocks` and returned separately.
    ///
    /// This method acquires the lock to the inner state and does not access the DB so we release
    /// the lock asap.
    async fn get_block_inputs_witnesses(
        &self,
        blocks: &mut BTreeSet<BlockNumber>,
        account_ids: Vec<AccountId>,
        nullifiers: Vec<Nullifier>,
    ) -> Result<
        (
            BlockNumber,
            BTreeMap<AccountId, AccountWitness>,
            BTreeMap<Nullifier, NullifierWitness>,
            PartialMmr,
        ),
        GetBlockInputsError,
    > {
        let inner = self.inner.read().await;

        let latest_block_number = inner.latest_block_num();

        // If `blocks` is empty, use the latest block number which will never trigger the error.
        let highest_block_number = blocks.last().copied().unwrap_or(latest_block_number);
        if highest_block_number > latest_block_number {
            return Err(GetBlockInputsError::UnknownBatchBlockReference {
                highest_block_number,
                latest_block_number,
            });
        }

        // The latest block is not yet in the chain MMR, so we can't (and don't need to) prove its
        // inclusion in the chain.
        blocks.remove(&latest_block_number);

        // Fetch the partial MMR at the state of the latest block with authentication paths for the
        // provided set of blocks.
        //
        // SAFETY:
        // - The latest block num was retrieved from the inner blockchain from which we will also
        //   retrieve the proofs, so it is guaranteed to exist in that chain.
        // - We have checked that no block number in the blocks set is greater than latest block
        //   number *and* latest block num was removed from the set. Therefore only block numbers
        //   smaller than latest block num remain in the set. Therefore all the block numbers are
        //   guaranteed to exist in the chain state at latest block num.
        let partial_mmr =
            inner.blockchain.partial_mmr_from_blocks(blocks, latest_block_number).expect(
                "latest block num should exist and all blocks in set should be < than latest block",
            );

        // Fetch witnesses for all accounts.
        let account_witnesses = account_ids
            .iter()
            .copied()
            .map(|account_id| (account_id, inner.account_tree.open_latest(account_id)))
            .collect::<BTreeMap<AccountId, AccountWitness>>();

        // Fetch witnesses for all nullifiers. We don't check whether the nullifiers are spent or
        // not as this is done as part of proposing the block.
        let nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness> = nullifiers
            .iter()
            .copied()
            .map(|nullifier| (nullifier, inner.nullifier_tree.open(&nullifier)))
            .collect();

        Ok((latest_block_number, account_witnesses, nullifier_witnesses, partial_mmr))
    }

    /// Returns data needed by the block producer to verify transactions validity.
    #[instrument(target = COMPONENT, skip_all, ret)]
    pub async fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        nullifiers: &[Nullifier],
        unauthenticated_note_commitments: Vec<Word>,
    ) -> Result<TransactionInputs, DatabaseError> {
        info!(target: COMPONENT, account_id = %account_id.to_string(), nullifiers = %format_array(nullifiers));

        let inner = self.inner.read().await;

        let account_commitment = inner.account_tree.get_latest_commitment(account_id);

        let new_account_id_prefix_is_unique = if account_commitment.is_empty() {
            Some(!inner.account_tree.contains_account_id_prefix_in_latest(account_id.prefix()))
        } else {
            None
        };

        // Non-unique account Id prefixes for new accounts are not allowed.
        if let Some(false) = new_account_id_prefix_is_unique {
            return Ok(TransactionInputs {
                new_account_id_prefix_is_unique,
                ..Default::default()
            });
        }

        let nullifiers = nullifiers
            .iter()
            .map(|nullifier| NullifierInfo {
                nullifier: *nullifier,
                block_num: inner.nullifier_tree.get_block_num(nullifier).unwrap_or_default(),
            })
            .collect();

        let found_unauthenticated_notes = self
            .db
            .select_existing_note_commitments(unauthenticated_note_commitments)
            .await?;

        Ok(TransactionInputs {
            account_commitment,
            nullifiers,
            found_unauthenticated_notes,
            new_account_id_prefix_is_unique,
        })
    }

    /// Returns details for public (on-chain) account.
    pub async fn get_account_details(&self, id: AccountId) -> Result<AccountInfo, DatabaseError> {
        self.db.select_account(id).await
    }

    /// Returns details for public (on-chain) network accounts by full account ID.
    pub async fn get_network_account_details_by_id(
        &self,
        account_id: AccountId,
    ) -> Result<Option<AccountInfo>, DatabaseError> {
        self.db.select_network_account_by_id(account_id).await
    }

    /// Returns network account IDs within the specified block range (based on account creation
    /// block).
    ///
    /// The function may return fewer accounts than exist in the range if the result would exceed
    /// `MAX_RESPONSE_PAYLOAD_BYTES / AccountId::SERIALIZED_SIZE` rows. In this case, the result is
    /// truncated at a block boundary to ensure all accounts from included blocks are returned.
    ///
    /// The response includes the last block number that was fully included in the result.
    pub async fn get_all_network_accounts(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> Result<(Vec<AccountId>, BlockNumber), DatabaseError> {
        self.db.select_all_network_account_ids(block_range).await
    }

    /// Returns an account witness and optionally account details at a specific block.
    ///
    /// The witness is a Merkle proof of inclusion in the account tree, proving the account's
    /// state commitment. If `details` is requested, the method also returns the account's code,
    /// vault assets, and storage data. Account details are only available for public accounts.
    ///
    /// If `block_num` is provided, returns the state at that historical block; otherwise, returns
    /// the latest state. Note that historical states are only available for recent blocks close
    /// to the chain tip.
    pub async fn get_account(
        &self,
        account_request: AccountRequest,
    ) -> Result<AccountResponse, DatabaseError> {
        let AccountRequest { block_num, account_id, details } = account_request;

        if details.is_some() && !account_id.has_public_state() {
            return Err(DatabaseError::AccountNotPublic(account_id));
        }

        let (block_num, witness) = self.get_account_witness(block_num, account_id).await?;

        let details = if let Some(request) = details {
            Some(self.fetch_public_account_details(account_id, block_num, request).await?)
        } else {
            None
        };

        Ok(AccountResponse { block_num, witness, details })
    }

    /// Returns an account witness (Merkle proof of inclusion in the account tree).
    ///
    /// If `block_num` is provided, returns the witness at that historical block;
    /// otherwise, returns the witness at the latest block.
    async fn get_account_witness(
        &self,
        block_num: Option<BlockNumber>,
        account_id: AccountId,
    ) -> Result<(BlockNumber, AccountWitness), DatabaseError> {
        let inner_state = self.inner.read().await;

        // Determine which block to query
        let (block_num, witness) = if let Some(requested_block) = block_num {
            // Historical query: use the account tree with history
            let witness = inner_state
                .account_tree
                .open_at(account_id, requested_block)
                .ok_or_else(|| DatabaseError::HistoricalBlockNotAvailable {
                    block_num: requested_block,
                    reason: "Block is either in the future or has been pruned from history"
                        .to_string(),
                })?;
            (requested_block, witness)
        } else {
            // Latest query: use the latest state
            let block_num = inner_state.account_tree.block_number_latest();
            let witness = inner_state.account_tree.open_latest(account_id);
            (block_num, witness)
        };

        Ok((block_num, witness))
    }

    /// Fetches the account details (code, vault, storage) for a public account at the specified
    /// block.
    ///
    /// This method queries the database to fetch the account state and processes the detail
    /// request to return only the requested information.
    ///
    /// For specific key queries (`SlotData::MapKeys`), the forest is used to provide SMT proofs.
    /// Returns an error if the forest doesn't have data for the requested slot.
    /// All-entries queries (`SlotData::All`) use the forest to return all entries.
    async fn fetch_public_account_details(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        detail_request: AccountDetailRequest,
    ) -> Result<AccountDetails, DatabaseError> {
        let AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_requests,
        } = detail_request;

        if !account_id.has_public_state() {
            return Err(DatabaseError::AccountNotPublic(account_id));
        }

        // Validate block exists in the blockchain before querying the database
        self.validate_block_exists(block_num).await?;

        // Query account header and storage header together in a single DB call
        let (account_header, storage_header) = self
            .db
            .select_account_header_with_storage_header_at_block(account_id, block_num)
            .await?
            .ok_or(DatabaseError::AccountAtBlockHeightNotFoundInDb(account_id, block_num))?;

        let account_code = match code_commitment {
            Some(commitment) if commitment == account_header.code_commitment() => None,
            Some(_) => {
                self.db
                    .select_account_code_by_commitment(account_header.code_commitment())
                    .await?
            },
            None => None,
        };

        let vault_details = match asset_vault_commitment {
            Some(commitment) if commitment == account_header.vault_root() => {
                AccountVaultDetails::empty()
            },
            Some(_) => {
                let vault_assets =
                    self.db.select_account_vault_at_block(account_id, block_num).await?;
                AccountVaultDetails::from_assets(vault_assets)
            },
            None => AccountVaultDetails::empty(),
        };

        let mut storage_map_details =
            Vec::<AccountStorageMapDetails>::with_capacity(storage_requests.len());

        // Use forest for storage map queries
        let forest_guard = self.forest.read().await;

        for StorageMapRequest { slot_name, slot_data } in storage_requests {
            let details = match &slot_data {
                SlotData::MapKeys(keys) => forest_guard
                    .open_storage_map(account_id, slot_name.clone(), block_num, keys)
                    .ok_or_else(|| DatabaseError::StorageRootNotFound {
                        account_id,
                        slot_name: slot_name.to_string(),
                        block_num,
                    })?
                    .map_err(DatabaseError::MerkleError)?,
                SlotData::All => forest_guard
                    .storage_map_entries(account_id, slot_name.clone(), block_num)
                    .ok_or_else(|| DatabaseError::StorageRootNotFound {
                        account_id,
                        slot_name: slot_name.to_string(),
                        block_num,
                    })?,
            };

            storage_map_details.push(details);
        }

        Ok(AccountDetails {
            account_header,
            account_code,
            vault_details,
            storage_details: AccountStorageDetails {
                header: storage_header,
                map_details: storage_map_details,
            },
        })
    }

    /// Loads a block from the block store. Return `Ok(None)` if the block is not found.
    pub async fn load_block(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        if block_num > self.latest_block_num().await {
            return Ok(None);
        }
        self.block_store.load_block(block_num).await.map_err(Into::into)
    }

    /// Returns the latest block number.
    pub async fn latest_block_num(&self) -> BlockNumber {
        self.inner.read().await.latest_block_num()
    }

    /// Validates that a block exists in the blockchain
    ///
    /// # Attention
    ///
    /// Acquires a *read lock** on `self.inner`.
    ///
    /// # Errors
    ///
    /// Returns `DatabaseError::BlockNotFound` if the block doesn't exist in the blockchain.
    async fn validate_block_exists(&self, block_num: BlockNumber) -> Result<(), DatabaseError> {
        let inner = self.inner.read().await;
        let latest_block_num = inner.latest_block_num();

        if block_num > latest_block_num {
            return Err(DatabaseError::BlockNotFound(block_num));
        }

        Ok(())
    }

    /// Emits metrics for each database table's size.
    pub async fn analyze_table_sizes(&self) -> Result<(), DatabaseError> {
        self.db.analyze_table_sizes().await
    }

    /// Returns the network notes for an account that are unconsumed by a specified block number,
    /// along with the next pagination token.
    pub async fn get_unconsumed_network_notes_for_account(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        page: Page,
    ) -> Result<(Vec<NoteRecord>, Page), DatabaseError> {
        self.db.select_unconsumed_network_notes(account_id, block_num, page).await
    }

    /// Returns the script for a note by its root.
    pub async fn get_note_script_by_root(
        &self,
        root: Word,
    ) -> Result<Option<NoteScript>, DatabaseError> {
        self.db.select_note_script_by_root(root).await
    }

    /// Returns vault asset witnesses for the specified account and block number.
    pub async fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> Result<Vec<AssetWitness>, WitnessError> {
        let witnesses = self
            .forest
            .read()
            .await
            .get_vault_asset_witnesses(account_id, block_num, vault_keys)?;
        Ok(witnesses)
    }

    /// Returns a storage map witness for the specified account and storage entry at the block
    /// number.
    ///
    /// Note that the `raw_key` is the raw, user-provided key that needs to be hashed in order to
    /// get the actual key into the storage map.
    pub async fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
        raw_key: Word,
    ) -> Result<StorageMapWitness, WitnessError> {
        let witness = self
            .forest
            .read()
            .await
            .get_storage_map_witness(account_id, slot_name, block_num, raw_key)?;
        Ok(witness)
    }
}
