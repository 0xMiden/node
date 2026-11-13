//! The write worker: single-task owner of the store's mutable trees.

use std::collections::BTreeSet;
use std::sync::{Arc, Once};

use arc_swap::ArcSwap;
use miden_node_tracing::{ErrorReport, Instrument, debug, instrument, miden_span_record, warn};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountUpdateDetails};
use miden_protocol::block::account_tree::AccountMutationSet;
use miden_protocol::block::nullifier_tree::{NullifierMutationSet, NullifierTree};
use miden_protocol::block::{BlockBody, BlockHeader, BlockNumber, Blockchain, SignedBlock};
use miden_protocol::crypto::merkle::smt::LargeSmt;
use miden_protocol::note::{NoteDetails, Nullifier};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::OutputNote;
use rayon::ThreadPool;
use thread_priority::{ThreadPriority, set_current_thread_priority};
use tokio::sync::{mpsc, watch};

use super::WriteRequest;
use crate::HistoricalError;
use crate::account_state_forest::{
    AccountStateForest,
    AccountStateForestBackend,
    PreparedAccountStateForestBlockUpdate,
};
use crate::accounts::AccountTreeWithHistory;
use crate::blocks::BlockStore;
use crate::db::queries::PreparedTransactionLogs;
use crate::db::{Db, NoteRecord};
use crate::errors::{ApplyBlockError, InvalidBlockError};
use crate::state::block_lifecycle::{BlockLifecycle, lifecycle_events_enabled};
use crate::state::loader::TreeStorage;
use crate::state::view::{PublishedGenerations, StateSnapshot};
use crate::state::{BlockCache, BlockNotification};

// WRITE WORKER
// ================================================================================================

/// Single-task owner of the mutable trees. Processes [`WriteRequest`]s serially.
///
/// The writer owns the writable trees directly, so no locks are held at any point: validation and
/// mutation-computation read the owned trees, the DB commit runs without touching them, and the
/// new [`StateSnapshot`] snapshot is published atomically at the end.
pub(in crate::state) struct WriteWorker {
    db: Arc<Db>,
    block_store: Arc<BlockStore>,
    /// Atomically swappable pointer through which new snapshots are published.
    latest_snapshot: Arc<ArcSwap<StateSnapshot>>,
    committed_tip_tx: Arc<watch::Sender<BlockNumber>>,
    block_cache: BlockCache,
    rx: mpsc::Receiver<WriteRequest>,
    /// The mutable nullifier tree owned by this writer.
    nullifier_tree: NullifierTree<LargeSmt<TreeStorage>>,
    /// The mutable account tree owned by this writer.
    account_tree: AccountTreeWithHistory<TreeStorage>,
    /// The blockchain MMR owned by this writer.
    blockchain: Blockchain,
    /// The mutable account state forest owned by this writer.
    forest: AccountStateForest<AccountStateForestBackend>,
    /// Writer-local log of published generations; its oldest still-pinned height feeds the
    /// snapshot-aware history-pruning tip.
    published_generations: PublishedGenerations,
    /// Dedicated rayon pool for the CPU-heavy sections of the write path.
    ///
    /// Applying a block must not queue behind unrelated jobs on the global rayon pool, so its
    /// parallel tree work runs here instead. The pool spans all cores and, when configured, its
    /// threads run at raised priority (best-effort), giving apply-block work high scheduling
    /// weight while runnable and costing nothing while idle.
    apply_pool: Arc<ThreadPool>,
}

/// Note records and state mutations computed from a validated block, before any modifications.
struct PreparedBlockUpdate {
    logs: PreparedTransactionLogs,
    notes: Vec<(NoteRecord, Option<Nullifier>)>,
    nullifier_tree_update: NullifierMutationSet,
    account_tree_update: AccountMutationSet,
    account_forest_update: PreparedAccountStateForestBlockUpdate<AccountStateForestBackend>,
    /// The accounts that the block creates. The forest and the database both use this set, so they
    /// cannot make different decisions for the same account.
    new_account_ids: BTreeSet<AccountId>,
}

impl WriteWorker {
    /// Assembles the write worker from the loaded trees and the store's shared infrastructure.
    ///
    /// Only construction is exposed outside this module: once assembled, the worker's internals
    /// are reachable solely through [`Self::run`].
    #[expect(clippy::too_many_arguments)]
    pub(in crate::state) fn new(
        db: Arc<Db>,
        block_store: Arc<BlockStore>,
        latest_snapshot: Arc<ArcSwap<StateSnapshot>>,
        committed_tip_tx: Arc<watch::Sender<BlockNumber>>,
        block_cache: BlockCache,
        rx: mpsc::Receiver<WriteRequest>,
        nullifier_tree: NullifierTree<LargeSmt<TreeStorage>>,
        account_tree: AccountTreeWithHistory<TreeStorage>,
        blockchain: Blockchain,
        forest: AccountStateForest<AccountStateForestBackend>,
        apply_block_thread_priority: bool,
    ) -> Self {
        // Seed the generation log with the initial snapshot so its readers hold back pruning
        // exactly like readers of any later generation.
        let mut published_generations = PublishedGenerations::new();
        let initial_snapshot = latest_snapshot.load_full();
        published_generations.record(initial_snapshot.latest_block_num(), &initial_snapshot);

        let mut pool_builder =
            rayon::ThreadPoolBuilder::new().thread_name(|index| format!("apply_block_{index}"));
        if apply_block_thread_priority {
            pool_builder = pool_builder.start_handler(|_| raise_thread_priority());
        }
        let apply_pool =
            Arc::new(pool_builder.build().expect("apply_block thread pool should build"));

        Self {
            db,
            block_store,
            latest_snapshot,
            committed_tip_tx,
            block_cache,
            rx,
            nullifier_tree,
            account_tree,
            blockchain,
            forest,
            published_generations,
            apply_pool,
        }
    }

    /// Runs the writer loop, processing requests until `shutdown` is signalled or the
    /// [`BlockWriter`] (holding the only request sender) is dropped.
    ///
    /// Cancellation is only observed between requests: an in-flight block write always runs to
    /// completion, so shutdown never leaves the trees lagging the committed database state.
    /// Requests still queued when cancellation fires are dropped, failing their senders.
    pub async fn run(mut self, shutdown: CancellationToken) {
        loop {
            let req = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                req = self.rx.recv() => match req {
                    Some(req) => req,
                    None => break,
                },
            };
            let result = self
                .write_block(req.signed_block, req.protocol_config)
                .instrument(req.span)
                .await;
            let _ = req.result_tx.send(result);
        }
    }

    /// Validates and commits a signed block to all persistent and in-memory stores.
    ///
    /// ## Note on state consistency
    ///
    /// Readers access the in-memory state through frozen snapshots, so consistency is maintained
    /// by ordering the commit steps rather than by locking:
    ///
    /// - the block is validated against the writer-owned trees and the DB prior to starting any
    ///   modifications.
    /// - the block is saved to the block store. Such blocks are considered candidates and are not
    ///   yet available for reading because the latest block pointer is not updated yet.
    /// - the DB transaction is committed. Concurrent readers still see the previous in-memory
    ///   snapshot; queries that combine DB and in-memory data are scoped by block number.
    /// - the in-memory structures owned by the writer are updated. On a crash in between, the trees
    ///   lag the DB by one block, which is detected by the consistency checks at startup (the same
    ///   crash semantics as the previous lock-based implementation).
    /// - the new snapshot is published atomically, making the block visible to readers.
    #[instrument(err)]
    async fn write_block(
        &mut self,
        signed_block: SignedBlock,
        protocol_config: Option<ProtocolConfig>,
    ) -> Result<(), ApplyBlockError> {
        let header = signed_block.header();
        let body = signed_block.body();

        let block_num = header.block_num();
        let block_commitment = header.commitment();
        let num_transactions =
            body.transactions().iter().map(|batch| batch.as_slice().len()).sum::<usize>();

        miden_span_record!(
            block.number = block_num,
            block.commitment = block_commitment,
            block.transaction.count = num_transactions
        );

        let previous_config_commitment = self.validate_block_header(header).await?;

        let commitment = header.protocol_config_commitment();
        if let Some(config) = protocol_config.as_ref() {
            let calculated = config.to_commitment();
            if calculated != commitment {
                return Err(crate::errors::DatabaseError::ProtocolConfigCommitmentMismatch {
                    expected: commitment,
                    calculated,
                }
                .into());
            }
        }

        let stored = self.db.select_protocol_config_by_commitment(commitment).await?;
        if stored.is_none() && protocol_config.is_none() {
            return Err(crate::errors::DatabaseError::ProtocolConfigNotFound(commitment).into());
        }
        let activated_protocol_config = if previous_config_commitment == commitment {
            None
        } else {
            stored.or(protocol_config)
        };

        let block_lifecycle =
            lifecycle_events_enabled().then(|| BlockLifecycle::from_block_body(block_num, body));
        let unresolved_note_nullifiers = block_lifecycle
            .as_ref()
            .map_or_else(Vec::new, BlockLifecycle::unresolved_note_nullifiers);

        // Compute the tree and forest mutations and note records upfront, before any modifications.
        // The writer is the sole forest mutator, so the precomputed forest update stays valid until
        // it is applied after the DB commit below.
        let (prepared, signed_block_bytes) = self.prepare_block_update(&signed_block)?;
        let PreparedBlockUpdate {
            logs,
            notes,
            nullifier_tree_update,
            account_tree_update,
            account_forest_update,
            new_account_ids,
        } = prepared;
        let precomputed_public_states = account_forest_update.account_states.clone();

        // Save the block to the block store. In a case of a failed DB transaction, the in-memory
        // state will be unchanged, but the file might still be written. Such blocks should be
        // considered candidates, not finalized blocks.
        self.block_store.save_block(block_num, &signed_block_bytes).await?;

        // Commit to the DB. Readers continue to see the previous in-memory snapshot while the DB
        // commits; queries that combine DB and in-memory data are scoped by block number.
        //
        // History pruning runs inside the same DB transaction, keyed off the oldest live snapshot
        // generation rather than the actual tip: unlike the `RocksDB`-backed trees, SQLite reads
        // have no point-in-time protection, so pruning lags while pinned views can still reach
        // the history and catches up once they are released.
        let generations = self.published_generations.advance(block_num);
        let snapshot_lag = generations
            .oldest_pinned
            .map_or(0, |oldest| block_num.as_u32() - oldest.as_u32());
        // `unwrap_or_default` keeps the field present with a zero value when the oldest pinned
        // generation is not superseded; a `None` value would omit the field from the span.
        miden_span_record!(
            snapshots.lag_blocks = snapshot_lag,
            snapshots.oldest_superseded_for_ms =
                generations.oldest_superseded_for.unwrap_or_default()
        );
        let prune_tip = generations.prune_tip;
        let resolved_note_ids = self
            .db
            .apply_block(
                signed_block,
                activated_protocol_config,
                notes,
                precomputed_public_states,
                new_account_ids,
                unresolved_note_nullifiers,
                prune_tip,
                logs,
            )
            .await
            .map_err(|err| ApplyBlockError::DbUpdateTaskFailed(err.as_report()))?;

        // The DB is committed at this point, so the prepared mutations must be applied and any
        // failure to do so aborts the process.
        let snapshot = self.apply_prepared_mutations(
            block_num,
            block_commitment,
            nullifier_tree_update,
            account_tree_update,
            account_forest_update,
        );

        // Atomically publish the new state. Readers that call `snapshot()` after this point will
        // see the updated state. Readers that hold the old snapshot are not affected.
        self.published_generations.record(block_num, &snapshot);
        self.latest_snapshot.swap(snapshot);

        miden_span_record!(snapshots.live = self.published_generations.live());

        // Push to cache and notify replica subscribers.
        self.block_cache
            .push(block_num, BlockNotification::new(block_num, signed_block_bytes))
            .expect("block cache receives sequential block numbers");
        // `send` is a no-op (and reports an error) when there are no subscribers, which would leave
        // `committed_tip()` stuck reporting a stale value. Use `send_replace` so the tip is always
        // updated regardless of whether anything is currently subscribed.
        self.committed_tip_tx.send_replace(block_num);

        if let Some(block_lifecycle) = block_lifecycle {
            block_lifecycle.emit(&resolved_note_ids);
        }
        debug!("Block applied");

        Ok(())
    }

    /// Computes the note records and all tree and forest mutations for a block, without mutating
    /// any state, and serializes the signed block.
    ///
    /// The work may block on backend I/O and fans out via rayon, so it runs on the dedicated
    /// apply-block pool via [`run_on_pool`]; the block serialization is folded in so that all
    /// write-path CPU work lands on the pool. The returned forest update is bound to the forest
    /// state observed here; it remains valid until applied because the writer is the sole forest
    /// mutator.
    #[instrument(err)]
    fn prepare_block_update(
        &self,
        signed_block: &SignedBlock,
    ) -> Result<(PreparedBlockUpdate, Vec<u8>), ApplyBlockError> {
        run_on_pool(&self.apply_pool, || {
            let header = signed_block.header();
            let body = signed_block.body();

            // The header must commit to the body's transactions. Checked here rather than in
            // `validate_block_header` so the transaction hashing runs on the apply-block pool.
            let tx_commitment = body.compute_transactions_commitment();
            if header.transactions_commitment() != tx_commitment {
                return Err(InvalidBlockError::InvalidBlockTxCommitment {
                    expected: tx_commitment,
                    actual: header.transactions_commitment(),
                }
                .into());
            }

            let notes = Self::build_note_records(header, body)?;
            let (nullifier_tree_update, account_tree_update) =
                self.compute_tree_mutations(header, body)?;

            // Public account updates carry patches; private accounts are filtered out since they
            // don't expose their state changes.
            let account_patches =
                body.updated_accounts().iter().filter_map(|update| match update.details() {
                    AccountUpdateDetails::Public(patch) => Some(patch.clone()),
                    AccountUpdateDetails::Private => None,
                });
            let new_account_ids = body
                .transactions()
                .iter()
                .flat_map(
                    miden_protocol::transaction::OrderedTransactionHeaders::created_account_ids,
                )
                .collect();
            let account_forest_update = self
                .forest
                .compute_block_update_mutations(
                    header.block_num(),
                    account_patches,
                    &new_account_ids,
                )
                .map_err(ApplyBlockError::AccountStateForestPreparation)?;

            let prepared = PreparedBlockUpdate {
                logs: PreparedTransactionLogs::from_block(body)?,
                notes,
                nullifier_tree_update,
                account_tree_update,
                account_forest_update,
                new_account_ids,
            };
            Ok((prepared, miden_node_persistence::encode(signed_block)))
        })
    }

    /// Applies the prepared mutations to the writer-owned trees and builds the new snapshot from
    /// reader views of them. The reader views are point-in-time storage snapshots, so no tree data
    /// is copied.
    ///
    /// Must only be called after the corresponding DB commit: at that point the mutations are part
    /// of canonical state, so a failure to apply them leaves the trees divergent and panics.
    /// Returning an error instead would expose components at different block heights. The panic
    /// unwinds the writer task, whose join error shuts the node down; readers keep serving the
    /// previous published snapshot (block-scoped, so still consistent) until then, and the startup
    /// consistency checks detect the trees lagging the database on restart.
    ///
    /// The work may block on backend I/O and fans out via rayon, so it runs on the dedicated
    /// apply-block pool via [`run_on_pool`].
    ///
    /// # Panics
    ///
    /// Panics if applying any prepared mutation fails; see above.
    #[instrument]
    fn apply_prepared_mutations(
        &mut self,
        block_num: BlockNumber,
        block_commitment: Word,
        nullifier_tree_update: NullifierMutationSet,
        account_tree_update: AccountMutationSet,
        account_forest_update: PreparedAccountStateForestBlockUpdate<AccountStateForestBackend>,
    ) -> Arc<StateSnapshot> {
        let apply_pool = Arc::clone(&self.apply_pool);
        run_on_pool(&apply_pool, || {
            self.nullifier_tree
                .apply_mutations(nullifier_tree_update)
                .unwrap_or_else(|error| {
                    panic!("nullifier tree update failed after database commit: {error}")
                });

            self.account_tree.apply_mutations(account_tree_update).unwrap_or_else(|error| {
                panic!("account tree update failed after database commit: {error}")
            });

            self.blockchain.push(block_commitment);

            self.forest
                .apply_precomputed_block_update(block_num, account_forest_update)
                .unwrap_or_else(|error| {
                    panic!("account-state forest update failed after database commit: {error}")
                });

            Arc::new(StateSnapshot::new(
                self.nullifier_tree
                    .reader()
                    .expect("nullifier tree snapshot creation should not fail"),
                self.blockchain.clone(),
                self.account_tree.reader(),
                self.forest.reader().expect("forest snapshot creation should not fail"),
            ))
        })
    }

    /// Validates that the block header is consistent with the committed chain state.
    ///
    /// Consistency between the header and the block body is checked in
    /// [`Self::prepare_block_update`], where the hashing runs on the apply-block pool.
    #[instrument(err)]
    async fn validate_block_header(&self, header: &BlockHeader) -> Result<Word, ApplyBlockError> {
        let block_num = header.block_num();

        // Validate that the applied block is the next block in sequence.
        let prev_block = self
            .db
            .select_block_header_by_block_num(None)
            .await?
            .ok_or(ApplyBlockError::DbBlockHeaderEmpty)?;
        let expected_block_num = prev_block.block_num().child();
        if block_num != expected_block_num {
            return Err(InvalidBlockError::NewBlockInvalidBlockNum {
                expected: expected_block_num,
                submitted: block_num,
            }
            .into());
        }
        if header.prev_block_commitment() != prev_block.commitment() {
            return Err(InvalidBlockError::NewBlockInvalidPrevCommitment.into());
        }

        Ok(prev_block.protocol_config_commitment())
    }

    /// Computes nullifier and account tree mutations, validating roots against the block header.
    #[instrument(err)]
    fn compute_tree_mutations(
        &self,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<(NullifierMutationSet, AccountMutationSet), ApplyBlockError> {
        let block_num = header.block_num();

        // A nullifier can only ever be created once, so the block is invalid if any of its
        // nullifiers are already recorded in the tree.
        let duplicate_nullifiers: Vec<_> = body
            .created_nullifiers()
            .iter()
            .filter(|&nullifier| self.nullifier_tree.get_block_num(nullifier).is_some())
            .copied()
            .collect();
        if !duplicate_nullifiers.is_empty() {
            return Err(InvalidBlockError::DuplicatedNullifiers(duplicate_nullifiers).into());
        }

        // The header's chain commitment must equal the chain MMR root prior to this block.
        let peaks = self.blockchain.peaks();
        if peaks.hash_peaks() != header.chain_commitment() {
            return Err(InvalidBlockError::NewBlockInvalidChainCommitment.into());
        }

        // Compute the nullifier tree mutations and verify that they produce the nullifier root
        // claimed in the header.
        let nullifier_tree_update = self
            .nullifier_tree
            .compute_mutations(
                body.created_nullifiers().iter().map(|nullifier| (*nullifier, block_num)),
            )
            .map_err(InvalidBlockError::NewBlockNullifierAlreadySpent)?;

        if nullifier_tree_update.as_mutation_set().root() != header.nullifier_root() {
            return Err(InvalidBlockError::NewBlockInvalidNullifierRoot.into());
        }

        // Compute the account tree mutations and verify that they produce the account root claimed
        // in the header.
        let account_tree_update = self
            .account_tree
            .compute_mutations(
                body.updated_accounts()
                    .iter()
                    .map(|update| (update.account_id(), update.final_state_commitment())),
            )
            .map_err(|e| match e {
                HistoricalError::AccountTreeError(err) => {
                    InvalidBlockError::NewBlockDuplicateAccountIdPrefix(err)
                },
                HistoricalError::MerkleError(_) => {
                    panic!("Unexpected MerkleError during account tree mutation computation")
                },
            })?;

        if account_tree_update.as_mutation_set().root() != header.account_root() {
            return Err(InvalidBlockError::NewBlockInvalidAccountRoot.into());
        }

        Ok((nullifier_tree_update, account_tree_update))
    }

    /// Builds note records with inclusion proofs from the block body.
    #[instrument(err)]
    fn build_note_records(
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<Vec<(NoteRecord, Option<Nullifier>)>, ApplyBlockError> {
        let block_num = header.block_num();

        let note_tree = body.compute_block_note_tree();
        if note_tree.root() != header.note_root() {
            return Err(InvalidBlockError::NewBlockInvalidNoteRoot.into());
        }

        let notes = body
            .output_notes()
            .map(|(note_index, note)| {
                let (details, attachments, nullifier) = match note {
                    OutputNote::Public(public) => (
                        Some(NoteDetails::from(public.as_note())),
                        public.as_note().attachments().clone(),
                        Some(public.as_note().nullifier()),
                    ),
                    OutputNote::Private(private) => (None, private.attachments().clone(), None),
                };

                let inclusion_path = note_tree.open(note_index);

                let note_record = NoteRecord {
                    block_num,
                    note_index,
                    note_id: note.id().as_word(),
                    metadata: *note.metadata(),
                    details,
                    attachments,
                    inclusion_path,
                };

                Ok((note_record, nullifier))
            })
            .collect::<Result<Vec<_>, InvalidBlockError>>()?;

        Ok(notes)
    }
}

// APPLY-BLOCK POOL
// ================================================================================================

/// Runs `op` on the dedicated apply-block pool, blocking in place until it completes.
///
/// The closure executes on a pool thread, so every rayon primitive it invokes fans out over the
/// pool rather than the global one. The caller's tracing span is propagated so spans opened
/// inside `op` stay parented under it.
fn run_on_pool<T: Send>(pool: &ThreadPool, op: impl FnOnce() -> T + Send) -> T {
    let span = miden_node_tracing::Span::current();
    tokio::task::block_in_place(|| pool.install(|| span.in_scope(op)))
}

/// Raises the current thread's scheduling priority, best-effort.
///
/// Runs on each apply-block pool thread at startup when raised priority is enabled in the
/// storage options. The OS may deny the raise (on Linux it
/// requires `CAP_SYS_NICE`); the pool still isolates apply-block work from the global rayon pool
/// at normal priority, so a denial is only logged, and only once rather than per thread.
fn raise_thread_priority() {
    static WARN_ONCE: Once = Once::new();
    if let Err(error) = set_current_thread_priority(ThreadPriority::Max) {
        WARN_ONCE.call_once(|| {
            warn!(
                &error,
                "failed to raise apply-block thread priority; continuing at normal priority"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use std::iter::once;
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use miden_node_proto::domain::account::GetAccountRequest;
    use miden_node_proto::generated::blockchain::SignedBlock as ProtoSignedBlock;
    use miden_node_utils::clap::StorageOptions;
    use miden_node_utils::fee::{test_fee_params, test_protocol_config};
    use miden_node_utils::shutdown::CancellationToken;
    use miden_protocol::Word;
    use miden_protocol::account::{
        AccountBuilder,
        AccountId,
        AccountPatch,
        AccountType,
        AccountUpdateDetails,
    };
    use miden_protocol::asset::AssetId;
    use miden_protocol::block::account_tree::AccountTree;
    use miden_protocol::block::code_tree::{CodePatch, CodeTree};
    use miden_protocol::block::{
        BlockAccountUpdate,
        BlockBody,
        BlockHeader,
        BlockSignatures,
        SignedBlock,
        ValidatorConfig,
    };
    use miden_protocol::crypto::merkle::mmr::Mmr;
    use miden_protocol::crypto::merkle::smt::Smt;
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
    use miden_protocol::testing::add_component::AddComponent;
    use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
    use miden_protocol::testing::random_secret_key::random_secret_key;
    use miden_protocol::transaction::PublicTransactionLogs;
    use tempfile::TempDir;

    use crate::errors::{ApplyBlockError, DatabaseError};
    use crate::genesis::GenesisState;
    use crate::state::{BlockWriter, State, WriterTask};

    async fn start_store() -> (TempDir, Arc<State>, BlockWriter, WriterTask, ProtocolConfig) {
        let temp_dir = tempfile::tempdir().expect("test directory should be created");
        let protocol_config = test_protocol_config();
        let signer = random_secret_key();
        let genesis = GenesisState::new(
            Vec::new(),
            test_fee_params(),
            0,
            ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
            protocol_config.clone(),
        )
        .into_block()
        .expect("genesis block should be created");
        State::bootstrap(genesis, temp_dir.path())
            .await
            .expect("store should bootstrap");

        let (state, block_writer, _proof_writer, writer_task) =
            State::load(temp_dir.path(), StorageOptions::default())
                .await
                .expect("state should load")
                .start(CancellationToken::new());

        (temp_dir, state, block_writer, writer_task, protocol_config)
    }

    fn alternate_protocol_config() -> ProtocolConfig {
        ProtocolConfig::current(AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
        ))
        .unwrap()
    }

    async fn empty_block(state: &State, protocol_config: &ProtocolConfig) -> SignedBlock {
        let view = state.view();
        let (parent, _) = view.get_block_header(None, false).await.unwrap();
        let parent = parent.expect("chain should have a parent block");
        let mut mmr = Mmr::new();
        for height in 0..=parent.block_num().as_u32() {
            let (header, _) = view.get_block_header(Some(height.into()), false).await.unwrap();
            mmr.add(header.expect("block header should exist").commitment()).unwrap();
        }
        let body = BlockBody::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PublicTransactionLogs::default(),
        )
        .unwrap();
        let header = BlockHeader::new(
            parent.commitment(),
            parent.block_num().child(),
            mmr.peaks().hash_peaks(),
            parent.account_root(),
            parent.nullifier_root(),
            CodeTree::<Smt>::default().root(),
            body.compute_block_note_tree().root(),
            body.compute_transactions_commitment(),
            parent.validator_config().clone(),
            parent.fee_parameters().clone(),
            protocol_config.to_commitment(),
            None,
            parent.timestamp() + 1,
        );
        SignedBlock::new_unchecked(header, body, BlockSignatures::new(Vec::new()).unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_inserts_a_new_protocol_config_with_its_block() {
        let (_temp_dir, state, mut writer, writer_task, _genesis_config) = start_store().await;
        let protocol_config = alternate_protocol_config();
        let block = empty_block(&state, &protocol_config).await;

        writer.apply_block(block, Some(protocol_config.clone())).await.unwrap();

        assert_eq!(state.committed_tip(), 1.into());
        assert_eq!(
            state.view().get_protocol_config(protocol_config.to_commitment()).await.unwrap(),
            Some(protocol_config)
        );
        writer.stop(writer_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_records_reactivations_and_scopes_history() {
        let (_temp_dir, state, mut writer, writer_task, first) = start_store().await;
        let second = alternate_protocol_config();
        let pinned = state.view();
        for (config, supplied) in [
            (&first, false),
            (&second, true),
            (&second, false),
            (&first, false),
            (&second, true),
        ] {
            let block = empty_block(&state, config).await;
            writer.apply_block(block, supplied.then(|| config.clone())).await.unwrap();
        }
        assert_eq!(
            pinned.get_protocol_config_commitment_at(0.into()).await.unwrap(),
            Some(first.to_commitment())
        );
        assert!(matches!(
            pinned.get_protocol_config_commitment_at(1.into()).await,
            Err(DatabaseError::RangeBeyondTip(_))
        ));
        let view = state.view();
        for (height, config) in
            [(0, &first), (1, &first), (2, &second), (3, &second), (4, &first), (5, &second)]
        {
            assert_eq!(
                view.get_protocol_config_commitment_at(height.into()).await.unwrap(),
                Some(config.to_commitment())
            );
        }
        let activations: Vec<i64> = state
            .db
            .writer()
            .write::<_, DatabaseError, _>("activation history", |tx| {
                Ok(tx.query(
                    "SELECT block_number FROM protocol_configs ORDER BY block_number ASC",
                    &[],
                    |row| row.get::<i64>(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(activations, vec![0, 2, 4, 5]);
        drop(view);
        drop(pinned);
        writer.stop(writer_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_reuses_a_known_protocol_config_without_a_supplied_config() {
        let (_temp_dir, state, mut writer, writer_task, protocol_config) = start_store().await;
        let block = empty_block(&state, &protocol_config).await;

        writer.apply_block(block, None).await.unwrap();

        assert_eq!(state.committed_tip(), 1.into());
        writer.stop(writer_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_reuses_a_known_protocol_config_when_it_is_supplied() {
        let (_temp_dir, state, mut writer, writer_task, protocol_config) = start_store().await;
        let block = empty_block(&state, &protocol_config).await;

        writer.apply_block(block, Some(protocol_config)).await.unwrap();

        assert_eq!(state.committed_tip(), 1.into());
        writer.stop(writer_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_rejects_an_unknown_protocol_config() {
        let (_temp_dir, state, mut writer, writer_task, _genesis_config) = start_store().await;
        let protocol_config = alternate_protocol_config();
        let commitment = protocol_config.to_commitment();
        let block = empty_block(&state, &protocol_config).await;

        let error = writer.apply_block(block, None).await.unwrap_err();

        assert_matches!(
            error,
            ApplyBlockError::DatabaseError(DatabaseError::ProtocolConfigNotFound(actual))
                if actual == commitment
        );
        assert_eq!(state.committed_tip(), 0.into());
        writer.stop(writer_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_rejects_a_mismatched_supplied_protocol_config() {
        let (_temp_dir, state, mut writer, writer_task, genesis_config) = start_store().await;
        let protocol_config = alternate_protocol_config();
        let expected = protocol_config.to_commitment();
        let calculated = genesis_config.to_commitment();
        let block = empty_block(&state, &protocol_config).await;

        let error = writer.apply_block(block, Some(genesis_config)).await.unwrap_err();

        assert_matches!(
            error,
            ApplyBlockError::DatabaseError(DatabaseError::ProtocolConfigCommitmentMismatch {
                expected: actual_expected,
                calculated: actual_calculated,
            }) if actual_expected == expected && actual_calculated == calculated
        );
        assert_eq!(state.committed_tip(), 0.into());
        writer.stop(writer_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_rejects_a_corrupt_persisted_protocol_config() {
        let (_temp_dir, state, mut writer, writer_task, protocol_config) = start_store().await;
        let commitment = protocol_config.to_commitment();
        let block = empty_block(&state, &protocol_config).await;
        let mut bytes = miden_node_persistence::encode(&protocol_config);
        bytes.push(0xff);
        state
            .db
            .writer()
            .write::<_, DatabaseError, _>("corrupt protocol config", move |tx| {
                tx.execute(
                    "UPDATE protocol_configs SET protocol_config = ?1 WHERE commitment = ?2",
                    &[&bytes, &commitment],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let error = writer.apply_block(block, Some(protocol_config)).await.unwrap_err();

        assert_matches!(error, ApplyBlockError::DatabaseError(DatabaseError::Persistence(_)));
        assert_eq!(state.committed_tip(), 0.into());
        writer.stop(writer_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn protocol_config_insertion_rolls_back_when_the_block_write_fails() {
        let (_temp_dir, state, mut writer, writer_task, genesis_config) = start_store().await;
        let protocol_config = alternate_protocol_config();
        let commitment = protocol_config.to_commitment();
        let block = empty_block(&state, &protocol_config).await;
        state
            .db
            .writer()
            .write::<_, DatabaseError, _>("reject block inserts", |tx| {
                tx.execute(
                    "CREATE TRIGGER reject_block_insert BEFORE INSERT ON block_headers \
                     BEGIN SELECT RAISE(ABORT, 'test block rejection'); END",
                    &[],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        assert_matches!(
            writer.apply_block(block, Some(protocol_config)).await,
            Err(ApplyBlockError::DbUpdateTaskFailed(_))
        );

        assert_eq!(state.committed_tip(), 0.into());
        assert_eq!(state.view().get_protocol_config(commitment).await.unwrap(), None);
        assert_eq!(
            state
                .db
                .select_protocol_config_commitment_at(crate::state::ScopedBlockNum::new_unchecked(
                    1.into()
                ),)
                .await
                .unwrap(),
            Some(genesis_config.to_commitment())
        );
        assert_eq!(
            state
                .db
                .select_block_header_by_block_num(Some(
                    crate::state::ScopedBlockNum::new_unchecked(1.into()),
                ))
                .await
                .unwrap(),
            None
        );
        writer.stop(writer_task).await;
    }

    async fn block_with_account_and_log(
        state: &State,
        config: &ProtocolConfig,
    ) -> (SignedBlock, AccountId, Word) {
        use miden_node_proto::DecodeMessageExt;
        use miden_protocol::Word;
        use miden_protocol::transaction::{
            InputNotes,
            LogTopic,
            OrderedTransactionHeaders,
            PublicTransactionLogs,
            TransactionHeader,
            TransactionLog,
            TransactionLogs,
        };
        let account = AccountBuilder::new([99; 32])
            .account_type(AccountType::Public)
            .with_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build_existing()
            .unwrap();
        let id = account.id();
        let commitment = account.to_commitment();
        let patch = AccountPatch::try_from(account).unwrap();
        let update =
            BlockAccountUpdate::new(id, commitment, AccountUpdateDetails::Public(patch)).unwrap();
        let mut account_tree: AccountTree = AccountTree::default();
        account_tree.insert(id, commitment).unwrap();
        let logs = TransactionLogs::new(vec![
            TransactionLog::new(
                id,
                LogTopic::new(1_u32.into(), 2_u32.into()),
                vec![Word::from([7, 8, 9, 10u32])],
            )
            .unwrap(),
        ])
        .unwrap();
        let header = TransactionHeader::new(
            id,
            Word::empty(),
            commitment,
            InputNotes::default(),
            vec![],
            logs.commitment(),
            CodePatch::default().commitment(),
        )
        .unwrap();
        let public = PublicTransactionLogs::new(vec![(header.id(), logs)], once(&header)).unwrap();
        let body = BlockBody::new(
            vec![update],
            vec![],
            vec![],
            vec![OrderedTransactionHeaders::new_unchecked(vec![header])],
            public,
        )
        .unwrap();
        let mut wire = ProtoSignedBlock::from(empty_block(state, config).await);
        wire.header.as_mut().unwrap().tx_commitment =
            Some(body.compute_transactions_commitment().into());
        wire.header.as_mut().unwrap().account_root = Some(account_tree.root().into());
        wire.body = Some(body.into());
        let block: SignedBlock = wire.decode_and_build_unchecked().unwrap();
        (block, id, commitment)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_log_insertion_does_not_publish_a_block_and_can_be_retried() {
        use miden_protocol::Word;
        let (_root, state, mut writer, task, config) = start_store().await;
        let mut notifications = state.subscribe_committed_tip();
        let (block, id, commitment) = block_with_account_and_log(&state, &config).await;
        state.db.writer().write::<_, DatabaseError, _>("fail log insertion", |tx| {
            tx.execute("CREATE TRIGGER fail_log BEFORE INSERT ON transaction_logs BEGIN SELECT RAISE(ABORT, 'log insert failure'); END", &[])?;
            Ok(())
        }).await.unwrap();
        assert!(writer.apply_block(block.clone(), None).await.is_err());
        assert_eq!(state.committed_tip(), 0.into());
        assert!(!notifications.has_changed().unwrap());
        assert!(state.load_block(1.into()).await.unwrap().is_none());
        let witness = state
            .view()
            .get_account(GetAccountRequest {
                account_id: id,
                block_num: None,
                details: None,
            })
            .await
            .unwrap()
            .witness;
        assert_eq!(witness.state_commitment(), Word::empty());
        let counts = state.db.writer().write::<_, DatabaseError, _>("check rollback", |tx| {
            let counts = tx.query("SELECT (SELECT COUNT(*) FROM block_headers), (SELECT COUNT(*) FROM transactions), (SELECT COUNT(*) FROM transaction_logs), (SELECT COUNT(*) FROM accounts)", &[], |row| Ok((row.get::<u32>(0)?,row.get::<u32>(1)?,row.get::<u32>(2)?,row.get::<u32>(3)?)))?;
            tx.execute("DROP TRIGGER fail_log", &[])?;
            Ok(counts)
        }).await.unwrap();
        assert_eq!(counts, vec![(1, 0, 0, 0)]);
        writer.apply_block(block, None).await.unwrap();
        notifications.changed().await.unwrap();
        assert_eq!(state.committed_tip(), 1.into());
        let witness = state
            .view()
            .get_account(GetAccountRequest {
                account_id: id,
                block_num: None,
                details: None,
            })
            .await
            .unwrap()
            .witness;
        assert_eq!(witness.state_commitment(), commitment);
        writer.stop(task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn eidos_block_replica_roundtrip_preserves_commitments_and_logs() {
        use miden_protocol::block::BlockNumber;

        let source_dir = tempfile::tempdir().unwrap();
        let replica_dir = tempfile::tempdir().unwrap();
        let signer = random_secret_key();
        let config = test_protocol_config();
        for dir in [&source_dir, &replica_dir] {
            let genesis = GenesisState::new(
                Vec::new(),
                test_fee_params(),
                0,
                ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
                config.clone(),
            )
            .into_block()
            .unwrap();
            State::bootstrap(genesis, dir.path()).await.unwrap();
        }
        let (source, mut writer, source_proofs, source_task) =
            State::load(source_dir.path(), StorageOptions::default())
                .await
                .unwrap()
                .start(CancellationToken::new());
        let (replica, mut replica_writer, replica_proofs, replica_task) =
            State::load(replica_dir.path(), StorageOptions::default())
                .await
                .unwrap()
                .start(CancellationToken::new());
        let (block, id, commitment) = block_with_account_and_log(&source, &config).await;
        let block = SignedBlock::new(
            block.header().clone(),
            block.body().clone(),
            BlockSignatures::new(vec![signer.sign(block.header().commitment())]).unwrap(),
        )
        .unwrap();
        writer.apply_block(block.clone(), None).await.unwrap();
        let bytes = source.load_block(BlockNumber::ONE).await.unwrap().unwrap();
        let transported: SignedBlock = miden_node_persistence::decode(&bytes).unwrap();
        assert_eq!(transported, block);
        replica_writer.apply_block(transported, None).await.unwrap();
        assert_eq!(replica.load_block(BlockNumber::ONE).await.unwrap().unwrap(), bytes);
        replica_writer.stop(replica_task).await;
        drop(replica_proofs);
        drop(replica);
        let (reopened, reopened_writer, _proofs, task) =
            State::load(replica_dir.path(), StorageOptions::default())
                .await
                .unwrap()
                .start(CancellationToken::new());
        let stored: SignedBlock = miden_node_persistence::decode(
            &reopened.load_block(BlockNumber::ONE).await.unwrap().unwrap(),
        )
        .unwrap();
        assert_eq!(stored.header().commitment(), block.header().commitment());
        assert_eq!(stored.body().public_logs(), block.body().public_logs());
        let response = reopened
            .view()
            .get_account(GetAccountRequest {
                account_id: id,
                block_num: None,
                details: None,
            })
            .await
            .unwrap();
        assert_eq!(response.witness.state_commitment(), commitment);
        assert_eq!(reopened.committed_tip(), BlockNumber::ONE);
        reopened_writer.stop(task).await;
        writer.stop(source_task).await;
        drop(source_proofs);
    }
}
