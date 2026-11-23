//! Provides transaction inputs to validator transaction execution.
use std::collections::BTreeSet;
use std::sync::Arc;

use miden_protocol::account::{AccountId, PartialAccount, StorageMapKey, StorageMapWitness};
use miden_protocol::asset::{AssetId, AssetWitness};
use miden_protocol::block::code_tree::{CodeTreeRoot, CodeWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::code::ProcedureRoot;
use miden_protocol::note::{NoteScript, NoteScriptRoot};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{AccountInputs, PartialBlockchain, TransactionInputs};
use miden_protocol::vm::FutureMaybeSend;
use miden_protocol::{MastForest, Word};
use miden_tx::{
    DataStore,
    DataStoreError,
    LoadedMastForest,
    MastForestStore,
    TransactionMastStore,
};

// TRANSACTION INPUTS DATA STORE
// ================================================================================================

/// A [`DataStore`] implementation that wraps [`TransactionInputs`]
pub struct TransactionInputsDataStore {
    tx_inputs: TransactionInputs,
    mast_store: TransactionMastStore,
}

impl TransactionInputsDataStore {
    pub fn new(tx_inputs: TransactionInputs) -> Self {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(tx_inputs.account().code());
        for account in tx_inputs.foreign_accounts().values() {
            mast_store.load_account_code(account.code());
        }
        Self { tx_inputs, mast_store }
    }

    fn account(&self, id: AccountId) -> Result<&PartialAccount, DataStoreError> {
        if self.tx_inputs.account().id() == id {
            Ok(self.tx_inputs.account())
        } else {
            self.tx_inputs
                .foreign_accounts()
                .get(&id)
                .map(AccountInputs::account)
                .ok_or(DataStoreError::AccountNotFound(id))
        }
    }
}

impl DataStore for TransactionInputsDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        async move {
            if self.tx_inputs.account().id() != account_id {
                return Err(DataStoreError::AccountNotFound(account_id));
            }

            if ref_blocks.iter().any(|block| {
                *block != self.tx_inputs.ref_block()
                    && self.tx_inputs.blockchain().get_block(*block).is_none()
            }) {
                return Err(DataStoreError::other("reference block missing from captured inputs"));
            }
            Ok((
                self.tx_inputs.account().clone(),
                self.tx_inputs.block_header().clone(),
                self.tx_inputs.protocol_config().clone(),
                self.tx_inputs.blockchain().clone(),
            ))
        }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async move {
            if ref_block != self.tx_inputs.ref_block() {
                return Err(DataStoreError::other("foreign account reference block mismatch"));
            }
            self.tx_inputs
                .foreign_accounts()
                .get(&foreign_account_id)
                .cloned()
                .ok_or(DataStoreError::AccountNotFound(foreign_account_id))
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            let account = self.account(account_id)?;
            if account.vault().root() != vault_root {
                return Err(DataStoreError::other("captured vault root mismatch"));
            }
            vault_keys
                .into_iter()
                .map(|key| {
                    account.vault().open(key).map_err(|err| {
                        DataStoreError::other_with_source("missing captured asset witness", err)
                    })
                })
                .collect()
        }
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            let account = self.account(account_id)?;
            let map = account
                .storage()
                .maps()
                .find(|map| map.root() == map_root)
                .ok_or_else(|| DataStoreError::other("missing captured storage map"))?;
            map.open(&map_key).map_err(|err| {
                DataStoreError::other_with_source("missing captured storage witness", err)
            })
        }
    }

    fn get_code_witnesses(
        &self,
        code_tree_root: CodeTreeRoot,
        procedure_roots: Vec<ProcedureRoot>,
    ) -> impl FutureMaybeSend<Result<Vec<CodeWitness>, DataStoreError>> {
        async move {
            let tree = self.tx_inputs.code_tree();
            if tree.root() != code_tree_root {
                return Err(DataStoreError::other("captured code tree root mismatch"));
            }
            procedure_roots
                .iter()
                .map(|root| {
                    tree.open(root).map_err(|err| {
                        DataStoreError::other_with_source("missing captured code witness", err)
                    })
                })
                .collect()
        }
    }

    /// This store has no code designated for publication in the code registry.
    fn get_code_to_register(
        &self,
        _procedure_roots: BTreeSet<ProcedureRoot>,
    ) -> impl FutureMaybeSend<Result<Vec<Arc<MastForest>>, DataStoreError>> {
        async move { Ok(Vec::new()) }
    }

    fn get_note_script(
        &self,
        script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async move { Ok(self.tx_inputs.note_scripts().get(&script_root).cloned()) }
    }
}

impl MastForestStore for TransactionInputsDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}
