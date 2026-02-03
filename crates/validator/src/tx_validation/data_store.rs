/// NOTE: This module contains logic that will eventually be moved to the Validator component
/// when it is added to this repository.
use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::{AccountId, PartialAccount, StorageMapWitness};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{AccountInputs, PartialBlockchain, TransactionInputs};
use miden_protocol::vm::FutureMaybeSend;
use miden_tx::{DataStore, DataStoreError, MastForestStore, TransactionMastStore};

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
        for code in tx_inputs.foreign_account_code() {
            mast_store.load_account_code(code);
        }
        Self { tx_inputs, mast_store }
    }
}

impl DataStore for TransactionInputsDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        _ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError>>
    {
        async move {
            if self.tx_inputs.account().id() != account_id {
                return Err(DataStoreError::AccountNotFound(account_id));
            }

            Ok((
                self.tx_inputs.account().clone(),
                self.tx_inputs.block_header().clone(),
                self.tx_inputs.blockchain().clone(),
            ))
        }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async move {
            self.tx_inputs.read_foreign_account_inputs(foreign_account_id).map_err(|err| {
                DataStoreError::other_with_source("failed to read foreign account inputs", err)
            })
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        _account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            // Retrieve native and foreign account asset witnesses from the advice inputs.
            self.tx_inputs
                .read_vault_asset_witnesses(vault_root, vault_keys)
                .map_err(|err| {
                    DataStoreError::other_with_source("failed to read vault asset witnesses", err)
                })
        }
    }

    fn get_storage_map_witness(
        &self,
        _account_id: AccountId,
        _map_root: Word,
        _map_key: Word,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            unimplemented!(
                "get_storage_map_witness is not used during re-execution of transactions"
            )
        }
    }

    fn get_note_script(
        &self,
        _script_root: Word,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async move { unimplemented!("get_note_script is not used during re-execution of transactions") }
    }
}

impl MastForestStore for TransactionInputsDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<std::sync::Arc<miden_protocol::MastForest>> {
        self.mast_store.get(procedure_hash)
    }
}
