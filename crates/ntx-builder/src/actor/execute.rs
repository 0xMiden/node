use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use miden_node_proto::clients::ValidatorClient;
use miden_node_proto::generated::{self as proto};
use miden_node_utils::lru_cache::LruCache;
use miden_node_utils::tracing::OpenTelemetrySpanExt;
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountStorageHeader,
    PartialAccount,
    StorageMapWitness,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::errors::TransactionInputError;
use miden_protocol::note::{Note, NoteScript};
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNote,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
    TransactionId,
    TransactionInputs,
};
use miden_protocol::vm::FutureMaybeSend;
use miden_remote_prover_client::remote_prover::tx_prover::RemoteTransactionProver;
use miden_tx::auth::UnreachableAuth;
use miden_tx::utils::Serializable;
use miden_tx::{
    DataStore,
    DataStoreError,
    FailedNote,
    LocalTransactionProver,
    MastForestStore,
    NoteCheckerError,
    NoteConsumptionChecker,
    NoteConsumptionInfo,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionMastStore,
    TransactionProverError,
};
use tokio::sync::Mutex;
use tokio::task::JoinError;
use tracing::{Instrument, instrument};

use crate::COMPONENT;
use crate::actor::account_state::TransactionCandidate;
use crate::block_producer::BlockProducerClient;
use crate::store::StoreClient;

#[derive(Debug, thiserror::Error)]
pub enum NtxError {
    #[error("note inputs were invalid")]
    InputNotes(#[source] TransactionInputError),
    #[error("failed to filter notes")]
    NoteFilter(#[source] NoteCheckerError),
    #[error("all notes failed to be executed")]
    AllNotesFailed(Vec<FailedNote>),
    #[error("failed to execute transaction")]
    Execution(#[source] TransactionExecutorError),
    #[error("failed to prove transaction")]
    Proving(#[source] TransactionProverError),
    #[error("failed to submit transaction")]
    Submission(#[source] tonic::Status),
    #[error("the ntx task panicked")]
    Panic(#[source] JoinError),
}

type NtxResult<T> = Result<T, NtxError>;

// NETWORK TRANSACTION CONTEXT
// ================================================================================================

/// Provides the context for execution [network transaction candidates](TransactionCandidate).
#[derive(Clone)]
pub struct NtxContext {
    /// Client for submitting proven transactions to the Block Producer.
    block_producer: BlockProducerClient,

    /// Client for validating transactions via the Validator.
    validator: ValidatorClient,

    /// The prover to delegate proofs to.
    ///
    /// Defaults to local proving if unset. This should be avoided in production as this is
    /// computationally intensive.
    prover: Option<RemoteTransactionProver>,

    /// The store client for retrieving note scripts.
    store: StoreClient,

    /// LRU cache for storing retrieved note scripts to avoid repeated store calls.
    script_cache: LruCache<Word, NoteScript>,
}

impl NtxContext {
    /// Creates a new [`NtxContext`] instance.
    pub fn new(
        block_producer: BlockProducerClient,
        validator: ValidatorClient,
        prover: Option<RemoteTransactionProver>,
        store: StoreClient,
        script_cache: LruCache<Word, NoteScript>,
    ) -> Self {
        Self {
            block_producer,
            validator,
            prover,
            store,
            script_cache,
        }
    }

    /// Executes a transaction end-to-end: filtering, executing, proving, and submitted to the block
    /// producer.
    ///
    /// The provided [`TransactionCandidate`] is processed in the following stages:
    /// 1. Note filtering – all input notes are checked for consumability. Any notes that cannot be
    ///    executed are returned as [`FailedNote`]s.
    /// 2. Execution – the remaining notes are executed against the account state.
    /// 3. Proving – a proof is generated for the executed transaction.
    /// 4. Submission – the proven transaction is submitted to the block producer.
    ///
    /// # Returns
    ///
    /// On success, returns the [`TransactionId`] of the executed transaction and a list of
    /// [`FailedNote`]s representing notes that were filtered out before execution.
    ///
    /// # Errors
    ///
    /// Returns an [`NtxError`] if any step of the pipeline fails, including:
    /// - Note filtering (e.g., all notes fail consumability checks).
    /// - Transaction execution.
    /// - Proof generation.
    /// - Submission to the network.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction", skip_all, err)]
    pub fn execute_transaction(
        self,
        tx: TransactionCandidate,
    ) -> impl FutureMaybeSend<NtxResult<(TransactionId, Vec<FailedNote>)>> {
        let TransactionCandidate {
            account,
            notes,
            chain_tip_header,
            chain_mmr,
        } = tx;
        tracing::Span::current().set_attribute("account.id", account.id());
        tracing::Span::current()
            .set_attribute("account.id.network_prefix", account.id().prefix().to_string().as_str());
        tracing::Span::current().set_attribute("notes.count", notes.len());
        tracing::Span::current()
            .set_attribute("reference_block.number", chain_tip_header.block_num());

        async move {
            Box::pin(async move {
                let data_store = NtxDataStore::new(
                    account,
                    chain_tip_header,
                    chain_mmr,
                    self.store.clone(),
                    self.script_cache.clone(),
                );

                // Filter notes.
                let notes = notes.into_iter().map(Note::from).collect::<Vec<_>>();
                let (successful_notes, failed_notes) =
                    self.filter_notes(&data_store, notes).await?;

                // Execute transaction.
                let executed_tx = Box::pin(self.execute(&data_store, successful_notes)).await?;

                // Prove transaction.
                let tx_inputs: TransactionInputs = executed_tx.into();
                let proven_tx = Box::pin(self.prove(&tx_inputs)).await?;

                // Validate proven transaction.
                self.validate(&proven_tx, &tx_inputs).await?;

                // Submit transaction to block producer.
                self.submit(&proven_tx).await?;

                Ok((proven_tx.id(), failed_notes))
            })
            .in_current_span()
            .await
            .inspect_err(|err| tracing::Span::current().set_error(err))
        }
    }

    /// Filters a collection of notes, returning only those that can be successfully executed
    /// against the given network account.
    ///
    /// This function performs a consumability check on each provided note and partitions them into
    /// two sets:
    /// - Successful notes: notes that can be executed and are returned wrapped in [`InputNotes`].
    /// - Failed notes: notes that cannot be executed.
    ///
    /// # Guarantees
    ///
    /// - On success, the returned [`InputNotes`] set is guaranteed to be non-empty.
    /// - The original ordering of notes is not preserved if any notes have failed.
    ///
    /// # Errors
    ///
    /// Returns an [`NtxError`] if:
    /// - The consumability check fails unexpectedly.
    /// - All notes fail the check (i.e., no note is consumable).
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.filter_notes", skip_all, err)]
    async fn filter_notes(
        &self,
        data_store: &NtxDataStore,
        notes: Vec<Note>,
    ) -> NtxResult<(InputNotes<InputNote>, Vec<FailedNote>)> {
        let executor: TransactionExecutor<'_, '_, _, UnreachableAuth> =
            TransactionExecutor::new(data_store);
        let checker = NoteConsumptionChecker::new(&executor);

        match Box::pin(checker.check_notes_consumability(
            data_store.account.id(),
            data_store.reference_block.block_num(),
            notes,
            TransactionArgs::default(),
        ))
        .await
        {
            Ok(NoteConsumptionInfo { successful, failed, .. }) => {
                // Map successful notes to input notes.
                let successful = InputNotes::from_unauthenticated_notes(successful)
                    .map_err(NtxError::InputNotes)?;

                // If none are successful, abort.
                if successful.is_empty() {
                    return Err(NtxError::AllNotesFailed(failed));
                }

                Ok((successful, failed))
            },
            Err(err) => return Err(NtxError::NoteFilter(err)),
        }
    }

    /// Creates an executes a transaction with the network account and the given set of notes.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.execute", skip_all, err)]
    async fn execute(
        &self,
        data_store: &NtxDataStore,
        notes: InputNotes<InputNote>,
    ) -> NtxResult<ExecutedTransaction> {
        let executor: TransactionExecutor<'_, '_, _, UnreachableAuth> =
            TransactionExecutor::new(data_store);

        Box::pin(executor.execute_transaction(
            data_store.account.id(),
            data_store.reference_block.block_num(),
            notes,
            TransactionArgs::default(),
        ))
        .await
        .map_err(NtxError::Execution)
    }

    /// Delegates the transaction proof to the remote prover if configured, otherwise performs the
    /// proof locally.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.prove", skip_all, err)]
    async fn prove(&self, tx_inputs: &TransactionInputs) -> NtxResult<ProvenTransaction> {
        if let Some(remote) = &self.prover {
            remote.prove(tx_inputs).await
        } else {
            // Only perform tx inptus clone for local proving.
            let tx_inputs = tx_inputs.clone();
            tokio::task::spawn_blocking(move || LocalTransactionProver::default().prove(tx_inputs))
                .await
                .map_err(NtxError::Panic)?
        }
        .map_err(NtxError::Proving)
    }

    /// Submits the transaction to the block producer.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.submit", skip_all, err)]
    async fn submit(&self, proven_tx: &ProvenTransaction) -> NtxResult<()> {
        self.block_producer
            .submit_proven_transaction(proven_tx)
            .await
            .map_err(NtxError::Submission)
    }

    /// Validates the transaction against the Validator.
    #[instrument(target = COMPONENT, name = "ntx.execute_transaction.validate", skip_all, err)]
    async fn validate(
        &self,
        proven_tx: &ProvenTransaction,
        tx_inputs: &TransactionInputs,
    ) -> NtxResult<()> {
        let request = proto::transaction::ProvenTransaction {
            transaction: proven_tx.to_bytes(),
            transaction_inputs: Some(tx_inputs.to_bytes()),
        };
        self.validator
            .clone()
            .submit_proven_transaction(request)
            .await
            .map_err(NtxError::Submission)?;
        Ok(())
    }
}

// NETWORK TRANSACTION DATA STORE
// ================================================================================================

/// A [`DataStore`] implementation which provides transaction inputs for a single account and
/// reference block with LRU caching for note scripts.
///
/// This implementation includes an LRU (Least Recently Used) cache for note scripts to improve
/// performance by avoiding repeated RPC calls for the same script roots. The cache automatically
/// manages memory usage by evicting least recently used entries when the cache reaches capacity.
///
/// This is sufficient for executing a network transaction.
struct NtxDataStore {
    account: Account,
    reference_block: BlockHeader,
    chain_mmr: PartialBlockchain,
    mast_store: TransactionMastStore,
    /// Store client for retrieving note scripts.
    store: StoreClient,
    /// LRU cache for storing retrieved note scripts to avoid repeated store calls.
    script_cache: LruCache<Word, NoteScript>,
    /// Mapping of storage map roots to storage slot names observed during various calls.
    ///
    /// The registered slot names are subsequently used to retrieve storage map witnesses from the
    /// store. We need this because the store interface (and the underling SMT forest) use storage
    /// slot names, but the `DataStore` interface works with tree roots. To get around this problem
    /// we populate this map when:
    /// - The the native account is loaded (in `get_transaction_inputs()`).
    /// - When a foreign account is loaded (in `get_foreign_account_inputs`).
    ///
    /// The assumption here are:
    /// - Once an account is loaded, the mapping between `(account_id, map_root)` and slot names do
    ///   not change. This is always the case.
    /// - New storage slots created during transaction execution will not be accesses in the same
    ///   transaction. The mechanism for adding new storage slots is not implemented yet, but the
    ///   plan for it is consistent with this assumption.
    ///
    /// One nuance worth mentioning: it is possible that there could be a root collision where an
    /// account has two storage maps with the same root. In this case, the map will contain only a
    /// single entry with the storage slot name that was added last. Thus, technically, requests
    /// to the store could be "wrong", but given that two identical maps have identical witnesses
    /// this does not cause issues in practice.
    storage_slots: Arc<Mutex<BTreeMap<(AccountId, Word), StorageSlotName>>>,
}

impl NtxDataStore {
    /// Creates a new `NtxDataStore` with default cache size.
    fn new(
        account: Account,
        reference_block: BlockHeader,
        chain_mmr: PartialBlockchain,
        store: StoreClient,
        script_cache: LruCache<Word, NoteScript>,
    ) -> Self {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(account.code());

        Self {
            account,
            reference_block,
            chain_mmr,
            mast_store,
            store,
            script_cache,
            storage_slots: Arc::new(Mutex::new(BTreeMap::default())),
        }
    }

    /// Registers storage map slot names for the given account ID and storage header.
    ///
    /// These slot names are subsequently used to query for storage map witnesses against the store.
    async fn register_storage_map_slots(
        &self,
        account_id: AccountId,
        storage_header: &AccountStorageHeader,
    ) {
        let mut storage_slots = self.storage_slots.lock().await;
        for slot_header in storage_header.slots() {
            if let StorageSlotType::Map = slot_header.slot_type() {
                storage_slots.insert((account_id, slot_header.value()), slot_header.name().clone());
            }
        }
    }
}

impl DataStore for NtxDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError>>
    {
        async move {
            if self.account.id() != account_id {
                return Err(DataStoreError::AccountNotFound(account_id));
            }

            // The latest supplied reference block must match the current reference block.
            match ref_blocks.last().copied() {
                Some(reference) if reference == self.reference_block.block_num() => {},
                Some(other) => return Err(DataStoreError::BlockNotFound(other)),
                None => return Err(DataStoreError::other("no reference block requested")),
            }

            // Register slot names from the native account for later use.
            self.register_storage_map_slots(account_id, &self.account.storage().to_header())
                .await;

            let partial_account = PartialAccount::from(&self.account);
            Ok((partial_account, self.reference_block.clone(), self.chain_mmr.clone()))
        }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async move {
            debug_assert_eq!(ref_block, self.reference_block.block_num());

            // Get foreign account inputs from store.
            let account_inputs =
                self.store.get_account_inputs(foreign_account_id, ref_block).await.map_err(
                    |err| DataStoreError::other_with_source("failed to get account inputs", err),
                )?;

            // Ensure foreign account procedures are available to the executor via the mast store.
            // This assumes the code was not loaded from before
            self.mast_store.load_account_code(account_inputs.code());

            // Register slot names from the foreign account for later use.
            self.register_storage_map_slots(foreign_account_id, account_inputs.storage().header())
                .await;

            Ok(account_inputs)
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        _vault_root: Word,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            let ref_block = self.reference_block.block_num();

            // Get vault asset witnesses from the store.
            let witnesses = self
                .store
                .get_vault_asset_witnesses(account_id, vault_keys, Some(ref_block))
                .await
                .map_err(|err| {
                    DataStoreError::other_with_source("failed to get vault asset witnesses", err)
                })?;

            Ok(witnesses)
        }
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: Word,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            // The slot name that corresponds to the given account ID and map root must have been
            // registered during previous calls of this data store.
            let storage_slots = self.storage_slots.lock().await;
            let Some(slot_name) = storage_slots.get(&(account_id, map_root)) else {
                return Err(DataStoreError::other(
                    "requested storage slot has not been registered",
                ));
            };

            let ref_block = self.reference_block.block_num();

            // Get storage map witness from the store.
            let witness = self
                .store
                .get_storage_map_witness(account_id, slot_name.clone(), map_key, Some(ref_block))
                .await
                .map_err(|err| {
                    DataStoreError::other_with_source("failed to get storage map witness", err)
                })?;

            Ok(witness)
        }
    }

    /// Retrieves a note script by its root hash.
    ///
    /// This implementation uses the configured RPC client to call the `GetNoteScriptByRoot`
    /// endpoint on the RPC server.
    fn get_note_script(
        &self,
        script_root: Word,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async move {
            // Attempt to retrieve the script from the cache.
            if let Some(cached_script) = self.script_cache.get(&script_root).await {
                return Ok(Some(cached_script));
            }

            // Retrieve the script from the store.
            let maybe_script =
                self.store.get_note_script_by_root(script_root).await.map_err(|err| {
                    DataStoreError::Other {
                        error_msg: "failed to retrieve note script from store".to_string().into(),
                        source: Some(err.into()),
                    }
                })?;
            // Handle response.
            if let Some(script) = maybe_script {
                self.script_cache.put(script_root, script.clone()).await;
                Ok(Some(script))
            } else {
                Ok(None)
            }
        }
    }
}

impl MastForestStore for NtxDataStore {
    fn get(
        &self,
        procedure_hash: &miden_protocol::Word,
    ) -> Option<std::sync::Arc<miden_protocol::MastForest>> {
        self.mast_store.get(procedure_hash)
    }
}
