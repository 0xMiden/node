//! Account deployment module.
//!
//! This module contains functionality for deploying Miden accounts to the network.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_node_proto::generated::transaction::ProvenTransaction;
use miden_protocol::account::{Account, AccountId, PartialAccount, PartialStorage, StorageMapKey};
use miden_protocol::assembly::{
    DefaultSourceManager,
    Library,
    Module,
    ModuleKind,
    Path as MidenPath,
};
use miden_protocol::asset::{AssetVaultKey, AssetWitness, PartialVault};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::merkle::mmr::{MmrPeaks, PartialMmr};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{
    AccountInputs,
    InputNotes,
    PartialBlockchain,
    TransactionArgs,
    TransactionKernel,
};
use miden_protocol::{MastForest, Word};
use miden_tx::auth::BasicAuthenticator;
use miden_tx::utils::Serializable;
use miden_tx::{
    DataStore,
    DataStoreError,
    LocalTransactionProver,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};
use tracing::instrument;
use url::Url;

use crate::COMPONENT;
use crate::deploy::counter::{create_counter_account, save_counter_account};
use crate::deploy::wallet::{create_wallet_account, save_wallet_account};

pub mod counter;
pub mod wallet;

/// Create an RPC client configured with the correct genesis metadata in the
/// `Accept` header so that write RPCs such as `SubmitProvenTransaction` are
/// accepted by the node.
pub async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<RpcClient> {
    // First, create a temporary client without genesis metadata to discover the
    // genesis block header and its commitment.
    let mut rpc: RpcClient = Builder::new(rpc_url.clone())
        .with_tls()
        .context("Failed to configure TLS for RPC client")?
        .with_timeout(timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to create RPC client for genesis discovery")?;

    let block_header_request = BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    };

    let response = rpc
        .get_block_header_by_number(block_header_request)
        .await
        .context("Failed to get genesis block header from RPC")?
        .into_inner();

    let genesis_block_header = response
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    let genesis_header: BlockHeader =
        genesis_block_header.try_into().context("Failed to convert block header")?;
    let genesis_commitment = genesis_header.commitment();
    let genesis = genesis_commitment.to_hex();

    // Rebuild the client, this time including the required genesis metadata so that
    // write RPCs like SubmitProvenTransaction are accepted by the node.
    let rpc_client = Builder::new(rpc_url.clone())
        .with_tls()
        .context("Failed to configure TLS for RPC client")?
        .with_timeout(timeout)
        .without_metadata_version()
        .with_metadata_genesis(genesis)
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to connect to RPC server with genesis metadata")?;

    Ok(rpc_client)
}

/// Ensure accounts exist, creating them if they don't.
///
/// This function checks if the wallet and counter account files exist.
/// If they don't exist, it creates new accounts and saves them to the specified files.
/// If they do exist, it does nothing.
///
/// # Arguments
///
/// * `wallet_file` - Path to the wallet account file.
/// * `counter_file` - Path to the counter program account file.
///
/// # Returns
///
/// `Ok(())` if the accounts exist or were successfully created, or an error if creation fails.
pub async fn ensure_accounts_exist(
    wallet_filepath: &Path,
    counter_filepath: &Path,
    rpc_url: &Url,
) -> Result<()> {
    let wallet_exists = wallet_filepath.exists();
    let counter_exists = counter_filepath.exists();

    if wallet_exists && counter_exists {
        tracing::info!("Account files already exist, skipping account creation");
        return Ok(());
    }

    tracing::info!("Account files not found, creating new accounts");

    // Create wallet account
    let (wallet_account, secret_key) = create_wallet_account()?;

    // Create counter program account
    let counter_account = create_counter_account(wallet_account.id())?;

    deploy_counter_account(&counter_account, rpc_url).await?;
    tracing::info!("Successfully created and deployed accounts");

    // Save accounts to files
    save_wallet_account(&wallet_account, &secret_key, wallet_filepath)?;
    save_counter_account(&counter_account, counter_filepath)
}

/// Deploy counter account to the network.
///
/// This function creates a counter program account,
/// then saves it to the specified file.
#[instrument(target = COMPONENT, name = "deploy-counter-account", skip_all, ret(level = "debug"))]
pub async fn deploy_counter_account(counter_account: &Account, rpc_url: &Url) -> Result<()> {
    // Deploy counter account to the network using a genesis-aware RPC client.
    let mut rpc_client = create_genesis_aware_rpc_client(rpc_url, Duration::from_secs(10)).await?;

    let block_header_request = BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    };

    let response = rpc_client
        .get_block_header_by_number(block_header_request)
        .await
        .context("Failed to get block header from RPC")?;

    let root_block_header = response
        .into_inner()
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    let genesis_header: BlockHeader =
        root_block_header.try_into().context("Failed to convert block header")?;

    let genesis_chain_mmr =
        PartialBlockchain::new(PartialMmr::from_peaks(MmrPeaks::default()), Vec::new())
            .context("Failed to create empty ChainMmr")?;

    let mut data_store = MonitorDataStore::new(genesis_header, genesis_chain_mmr);
    data_store.add_account(counter_account.clone());

    let executor: TransactionExecutor<'_, '_, _, BasicAuthenticator> =
        TransactionExecutor::new(&data_store).with_debug_mode();

    let tx_args = TransactionArgs::default();

    let executed_tx = executor
        .execute_transaction(
            counter_account.id(),
            BlockNumber::GENESIS,
            InputNotes::default(),
            tx_args,
        )
        .await
        .context("Failed to execute transaction")?;

    let transaction_inputs = executed_tx.tx_inputs().to_bytes();

    let prover = LocalTransactionProver::default();

    let proven_tx = prover.prove(executed_tx).context("Failed to prove transaction")?;

    let request = ProvenTransaction {
        transaction: proven_tx.to_bytes(),
        transaction_inputs: Some(transaction_inputs),
    };

    rpc_client
        .submit_proven_transaction(request)
        .await
        .context("Failed to submit proven transaction to RPC")?;

    Ok(())
}

pub(crate) fn get_counter_library() -> Result<Library> {
    let assembler = TransactionKernel::assembler();
    let source_manager = Arc::new(DefaultSourceManager::default());
    let script =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/assets/counter_program.masm"));

    let library_path = MidenPath::new("external_contract::counter_contract");

    let module = Module::parser(ModuleKind::Library)
        .parse_str(library_path, script, source_manager)
        .map_err(|e| anyhow::anyhow!("Failed to parse module: {e}"))?;

    assembler
        .clone()
        .assemble_library([module])
        .map_err(|e| anyhow::anyhow!("Failed to assemble library: {e}"))
}

// MONITOR DATA STORE
// ================================================================================================

/// A [`DataStore`] implementation for the network monitor.
pub struct MonitorDataStore {
    accounts: HashMap<AccountId, Account>,
    block_header: BlockHeader,
    partial_block_chain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl MonitorDataStore {
    pub fn new(block_header: BlockHeader, partial_block_chain: PartialBlockchain) -> Self {
        Self {
            accounts: HashMap::new(),
            block_header,
            partial_block_chain,
            mast_store: TransactionMastStore::new(),
        }
    }

    /// Add or replace an account in the store and load its code into the MAST store.
    pub fn add_account(&mut self, account: Account) {
        self.mast_store.load_account_code(account.code());
        self.accounts.insert(account.id(), account);
    }

    /// Update an account after a transaction (loads latest code too).
    pub fn update_account(&mut self, account: Account) {
        self.add_account(account);
    }

    /// Insert external library procedures used by transactions.
    pub fn insert_library(&mut self, library: &Library) {
        self.mast_store.insert(library.mast_forest().clone());
    }

    /// Returns a reference to the account or a standardized "unknown account" error.
    fn get_account(&self, account_id: AccountId) -> Result<&Account, DataStoreError> {
        self.accounts.get(&account_id).ok_or_else(|| DataStoreError::Other {
            error_msg: "unknown account".into(),
            source: None,
        })
    }
}

impl DataStore for MonitorDataStore {
    async fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        mut _block_refs: BTreeSet<BlockNumber>,
    ) -> Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError> {
        let account = self.get_account(account_id)?.clone();
        let partial_storage = PartialStorage::new_full(account.storage().clone());
        let assert_vault = PartialVault::new_full(account.vault().clone());
        let partial_account = PartialAccount::new(
            account_id,
            account.nonce(),
            account.code().clone(),
            partial_storage,
            assert_vault,
            account.seed(),
        )
        .expect("Partial account be valid");

        Ok((partial_account, self.block_header.clone(), self.partial_block_chain.clone()))
    }

    async fn get_storage_map_witness(
        &self,
        _account_id: AccountId,
        _map_root: Word,
        _map_key: StorageMapKey,
    ) -> Result<miden_protocol::account::StorageMapWitness, DataStoreError> {
        unimplemented!("Not needed")
    }

    async fn get_foreign_account_inputs(
        &self,
        _foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> Result<AccountInputs, DataStoreError> {
        unimplemented!("Not needed")
    }

    async fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> Result<Vec<AssetWitness>, DataStoreError> {
        let account = self.get_account(account_id)?;

        if account.vault().root() != vault_root {
            return Err(DataStoreError::Other {
                error_msg: "vault root mismatch".into(),
                source: None,
            });
        }

        Result::<Vec<_>, _>::from_iter(vault_keys.into_iter().map(|vault_key| {
            AssetWitness::new(account.vault().open(vault_key).into()).map_err(|err| {
                DataStoreError::Other {
                    error_msg: "failed to open vault asset tree".into(),
                    source: Some(Box::new(err)),
                }
            })
        }))
    }

    async fn get_note_script(
        &self,
        _script_root: Word,
    ) -> Result<Option<NoteScript>, DataStoreError> {
        Ok(None)
    }
}

impl MastForestStore for MonitorDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<Arc<MastForest>> {
        self.mast_store.get(procedure_hash)
    }
}
