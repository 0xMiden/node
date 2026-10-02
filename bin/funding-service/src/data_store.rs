//! In-memory transaction data store.

use std::collections::{BTreeSet, HashMap};

use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountId,
    PartialAccount,
    StorageMapKey,
    StorageMapWitness,
    StorageSlotContent,
};
use miden_protocol::asset::{AssetId, AssetWitness};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteScript, NoteScriptRoot};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{AccountInputs, PartialBlockchain};
use miden_protocol::vm::FutureMaybeSend;
use miden_tx::{
    DataStore,
    DataStoreError,
    LoadedMastForest,
    MastForestStore,
    TransactionMastStore,
};

// IN-MEMORY DATA STORE
// ================================================================================================

/// An in-memory [`DataStore`] which holds the accounts one transaction needs.
///
/// The store is built for a single transaction: it holds the reference block, the partial
/// blockchain proving that block, the executing account, and any account the transaction reaches
/// through a foreign procedure invocation.
pub struct InMemoryDataStore {
    accounts: HashMap<AccountId, Account>,
    account_witnesses: HashMap<AccountId, AccountWitness>,
    block_header: BlockHeader,
    partial_block_chain: PartialBlockchain,
    /// The protocol configuration committed by `block_header`.
    protocol_config: ProtocolConfig,
    mast_store: TransactionMastStore,
}

impl InMemoryDataStore {
    pub fn new(
        block_header: BlockHeader,
        partial_block_chain: PartialBlockchain,
        protocol_config: ProtocolConfig,
    ) -> Self {
        Self {
            accounts: HashMap::new(),
            account_witnesses: HashMap::new(),
            block_header,
            partial_block_chain,
            protocol_config,
            mast_store: TransactionMastStore::new(),
        }
    }

    /// Add or replace an account in the store and load its code into the MAST store.
    pub fn add_account(&mut self, account: Account) {
        self.mast_store.load_account_code(account.code());
        self.accounts.insert(account.id(), account);
    }

    /// Register an account the transaction reaches through a foreign procedure invocation, together
    /// with the account-tree witness proving its state in the store's reference block.
    pub fn add_foreign_account(&mut self, account: Account, witness: AccountWitness) {
        self.add_account(account);
        self.account_witnesses.insert(witness.id(), witness);
    }

    /// Returns a reference to the account or a standardized "unknown account" error.
    fn get_account(&self, account_id: AccountId) -> Result<&Account, DataStoreError> {
        self.accounts.get(&account_id).ok_or_else(|| DataStoreError::Other {
            error_msg: "unknown account".into(),
            source: None,
        })
    }
}

impl DataStore for InMemoryDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        mut _block_refs: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        async move {
            let account = self.get_account(account_id)?;
            let partial_account = PartialAccount::from(account);

            Ok((
                partial_account,
                self.block_header.clone(),
                self.protocol_config.clone(),
                self.partial_block_chain.clone(),
            ))
        }
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            let account = self.get_account(account_id)?;

            account
                .storage()
                .slots()
                .iter()
                .filter_map(|slot| match slot.content() {
                    StorageSlotContent::Map(map) => Some(map),
                    StorageSlotContent::Value(_) => None,
                })
                .find(|map| map.root() == map_root)
                .map(|map| map.open(&map_key))
                .ok_or_else(|| DataStoreError::Other {
                    error_msg: format!(
                        "no storage map with the requested root in account {account_id}"
                    )
                    .into(),
                    source: None,
                })
        }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async move {
            let account = self.get_account(foreign_account_id)?;
            let witness =
                self.account_witnesses.get(&foreign_account_id).cloned().ok_or_else(|| {
                    DataStoreError::Other {
                        error_msg: format!(
                            "no account witness for foreign account {foreign_account_id}"
                        )
                        .into(),
                        source: None,
                    }
                })?;

            Ok(AccountInputs::new(PartialAccount::from(account), witness))
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            let account = self.get_account(account_id)?;

            if account.vault().root() != vault_root {
                return Err(DataStoreError::Other {
                    error_msg: "vault root mismatch".into(),
                    source: None,
                });
            }

            vault_keys
                .into_iter()
                .map(|vault_key| {
                    AssetWitness::new(account.vault().open(vault_key).into(), [vault_key]).map_err(
                        |err| DataStoreError::Other {
                            error_msg: "failed to open vault asset tree".into(),
                            source: Some(Box::new(err)),
                        },
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        }
    }

    fn get_note_script(
        &self,
        _script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async move { Ok(None) }
    }
}

impl MastForestStore for InMemoryDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}
