//! In-memory transaction data store.

use std::collections::BTreeSet;
use std::sync::Arc;

use miden_node_proto::clients::{ForeignAccount, RpcClient};
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
/// blockchain proving that block, the funding wallet, and the fee faucet.
pub struct InMemoryDataStore {
    wallet: Arc<Account>,
    faucet: ForeignAccount,
    rpc_client: RpcClient,
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
        rpc_client: RpcClient,
        wallet: Arc<Account>,
        faucet: ForeignAccount,
    ) -> Self {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(wallet.code());
        mast_store.load_account_code(faucet.inputs().account().code());
        Self {
            wallet,
            faucet,
            rpc_client,
            block_header,
            partial_block_chain,
            protocol_config,
            mast_store,
        }
    }

    /// Returns a reference to the account or a standardized "unknown account" error.
    fn get_account(&self, account_id: AccountId) -> Result<&Account, DataStoreError> {
        (account_id == self.wallet.id()).then_some(self.wallet.as_ref()).ok_or_else(|| {
            DataStoreError::Other {
                error_msg: "unknown account".into(),
                source: None,
            }
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
            if account_id == self.faucet.inputs().account().id() {
                let account = &self.faucet;
                if let Some(map) =
                    account.inputs().account().storage().maps().find(|map| map.root() == map_root)
                    && let Ok(witness) = map.open(&map_key)
                {
                    return Ok(witness);
                }
                let mut rpc = self.rpc_client.clone();
                return account
                    .storage_map_witness(&mut rpc, self.block_header.block_num(), map_root, map_key)
                    .await
                    .map_err(|err| DataStoreError::Other {
                        error_msg: "failed to load foreign account storage proof".into(),
                        source: Some(err.into()),
                    });
            }
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
            (foreign_account_id == self.faucet.inputs().account().id())
                .then(|| self.faucet.inputs().clone())
                .ok_or_else(|| DataStoreError::Other {
                    error_msg: format!(
                        "no account witness for foreign account {foreign_account_id}"
                    )
                    .into(),
                    source: None,
                })
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
