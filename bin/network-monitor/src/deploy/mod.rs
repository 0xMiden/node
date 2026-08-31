//! Account deployment module.
//!
//! This module contains functionality for deploying Miden accounts to the network.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use backon::{ExponentialBuilder, Retryable};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::domain::account::AccountResponse;
use miden_node_proto::domain::encryption::{
    TransactionInputsSealer,
    TrustedTransactionEncryptionState,
    verify_transaction_encryption_key,
};
use miden_node_proto::generated::rpc::{
    AccountRequest as ProtoAccountRequest,
    BlockHeaderByNumberRequest,
    FinalityLevel,
    SyncChainMmrRequest,
};
use miden_node_proto::generated::submission::ProvenTransactionSubmission as ProtoProvenTransaction;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{debug, info, miden_instrument, warn};
use miden_node_utils::retry;
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
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrPeaks, PartialMmr};
use miden_protocol::note::{NoteScript, NoteScriptRoot};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
    TransactionInputs,
};
use miden_protocol::utils::serde::Serializable;
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{
    DataStore,
    DataStoreError,
    LoadedMastForest,
    LocalTransactionProver,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};
use tokio::sync::Mutex;
use url::Url;

use crate::deploy::counter::create_counter_account;
use crate::deploy::wallet::create_wallet_account;
use crate::{COMPONENT, LOG_TARGET};

pub mod counter;
pub mod wallet;

/// Monitor accounts and signing key created as one deployment unit.
pub struct DeployedMonitorAccounts {
    pub wallet: Account,
    pub secret_key: SecretKey,
    pub counter: Account,
    pub counter_anchor: CounterAnchor,
}

/// RPC client and verified transaction-input sealer shared by monitor submission workflows.
#[derive(Clone)]
pub struct TransactionSubmissionClient {
    rpc_client: RpcClient,
    genesis_commitment: Word,
    trusted_validator_signing_keys: Arc<[ValidatorPublicKey]>,
    sealer: Arc<Mutex<Option<TransactionInputsSealer>>>,
}

impl TransactionSubmissionClient {
    /// Connects to RPC and pins the validator key trusted for encryption-key attestations.
    pub async fn connect(
        rpc_url: &Url,
        timeout: Duration,
        trusted_validator_signing_key: ValidatorPublicKey,
    ) -> Result<Self> {
        let (rpc_client, genesis_commitment) =
            create_genesis_aware_rpc_client(rpc_url, timeout).await?;
        let client = Self {
            rpc_client,
            genesis_commitment,
            trusted_validator_signing_keys: Arc::from([trusted_validator_signing_key]),
            sealer: Arc::new(Mutex::new(None)),
        };
        client.sealer().await?;
        Ok(client)
    }

    /// Returns a clone of the underlying RPC client for read operations.
    pub fn rpc_client(&self) -> RpcClient {
        self.rpc_client.clone()
    }

    /// Returns the cached verified sealer, fetching and checking the attested key on first use.
    async fn sealer(&self) -> Result<TransactionInputsSealer> {
        if let Some(sealer) = self.sealer.lock().await.clone() {
            return Ok(sealer);
        }

        let key = self
            .rpc_client
            .clone()
            .get_transaction_encryption_key(())
            .await
            .context("Failed to fetch the transaction encryption key")?
            .into_inner();
        let verified = verify_transaction_encryption_key(
            key,
            TrustedTransactionEncryptionState::new(
                self.genesis_commitment,
                &self.trusted_validator_signing_keys,
            ),
        )
        .context("Untrusted transaction encryption key")?;
        let sealer = TransactionInputsSealer::new(verified);

        let mut cached = self.sealer.lock().await;
        if let Some(sealer) = cached.clone() {
            return Ok(sealer);
        }
        *cached = Some(sealer.clone());
        Ok(sealer)
    }

    /// Seals and submits one proven transaction, retrying once with a fresh key when needed.
    pub async fn submit(
        &self,
        proven_tx: &ProvenTransaction,
        transaction_inputs: &[u8],
    ) -> Result<BlockNumber> {
        let tx_id = proven_tx.id();
        let stale_key = AtomicBool::new(false);

        let result = (|| async {
            if stale_key.swap(false, Ordering::Relaxed) {
                *self.sealer.lock().await = None;
            }

            let sealed = self
                .sealer()
                .await?
                .seal(tx_id, transaction_inputs)
                .context("Failed to seal the transaction inputs")?;
            self.rpc_client
                .clone()
                .submit_proven_tx(ProtoProvenTransaction {
                    transaction: Some(proven_tx.into()),
                    sealed_transaction_inputs: Some(sealed),
                })
                .await
                .context("Failed to submit proven transaction to RPC")
        })
        .retry(retry::constant(Duration::ZERO, Some(1)))
        .when(|err: &anyhow::Error| {
            err.downcast_ref::<tonic::Status>()
                .is_some_and(|status| status.code() == tonic::Code::FailedPrecondition)
        })
        .notify(|status: &anyhow::Error, _| {
            stale_key.store(true, Ordering::Relaxed);
            warn!(
                status,
                target: COMPONENT,
                "Transaction inputs rejected as stale, refreshing the encryption key and retrying",
                transaction.id = tx_id
            );
        })
        .await;

        Ok(result?.into_inner().block_num.into())
    }
}

/// Backoff schedule applied to the genesis-discovery RPC handshake.
///
/// At startup the monitor may come up before the node's RPC endpoint is accepting connections, so
/// the eager `connect()` (and the follow-up `get_block_header_by_number` request) is retried with
/// exponential backoff instead of failing on the first refused connection. The schedule is bounded
/// so a single handshake attempt returns within a few minutes; callers that must survive a
/// genuinely unreachable endpoint (e.g. the NTX bootstrap in `monitor::tasks`) wrap it in their
/// own unbounded retry loop.
const GENESIS_DISCOVERY_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const GENESIS_DISCOVERY_BACKOFF_MAX: Duration = Duration::from_secs(30);
const GENESIS_DISCOVERY_MAX_RETRIES: usize = 10;

/// Builds the [`ExponentialBuilder`] used to back off retries on transient genesis-discovery
/// failures.
fn genesis_discovery_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(GENESIS_DISCOVERY_BACKOFF_INITIAL)
        .with_max_delay(GENESIS_DISCOVERY_BACKOFF_MAX)
        .with_factor(2.0)
        .with_max_times(GENESIS_DISCOVERY_MAX_RETRIES)
        .with_jitter()
}

/// Create an RPC client configured with the correct genesis metadata in the `Accept` header so that
/// write RPCs such as `SubmitProvenTx` are accepted by the node.
///
/// The full handshake (genesis discovery plus the genesis-aware reconnect) is retried with
/// [`genesis_discovery_backoff`] so a node that is still starting up does not abort the monitor.
pub async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<(RpcClient, Word)> {
    (|| async {
        // First, create a temporary client without genesis metadata to discover the genesis block
        // header and its commitment.
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
        // Rebuild the client, this time including the required genesis metadata so that write RPCs
        // like SubmitProvenTx are accepted by the node.
        let rpc_client = Builder::new(rpc_url.clone())
            .with_tls()
            .context("Failed to configure TLS for RPC client")?
            .with_timeout(timeout)
            .without_metadata_version()
            .with_metadata_genesis(genesis_commitment)
            .without_otel_context_injection()
            .connect()
            .await
            .context("Failed to connect to RPC server with genesis metadata")?;

        Ok((rpc_client, genesis_commitment))
    })
    .retry(genesis_discovery_backoff())
    .notify(|err: &anyhow::Error, sleep: Duration| {
        warn!(
            err,
            target: COMPONENT,
            "RPC genesis discovery failed; retrying after backoff",
            retry.delay_ms = sleep.as_millis() as u64
        );
    })
    .await
}

/// Create a fresh wallet + counter pair in memory and deploy the counter to the network.
///
/// Used both at startup and by the increment task when accounts are fundamentally outdated
/// (e.g., after a network reset) and re-syncing from the RPC is not sufficient. The accounts
/// are never persisted to disk; the monitor re-creates them on every restart.
pub async fn create_and_deploy_accounts(
    submission_client: &TransactionSubmissionClient,
    prover: &LocalTransactionProver,
    fee_faucet_id: AccountId,
) -> Result<DeployedMonitorAccounts> {
    info!(target: LOG_TARGET, "Creating fresh monitor accounts");

    let mut rpc_client = submission_client.rpc_client();

    // The genesis header is immutable, so it is fetched once and reused by every step below.
    let genesis_header = fetch_genesis_block_header(&mut rpc_client).await?;
    ensure_monitor_supported_fee_parameters(&genesis_header)?;
    let protocol_config = ProtocolConfig::current(AssetId::new_fungible(fee_faucet_id))
        .context("failed to construct the target protocol configuration")?;
    anyhow::ensure!(
        protocol_config.to_commitment() == genesis_header.protocol_config_commitment(),
        "configured fee faucet does not match the chain's protocol configuration",
    );

    let (wallet_account, secret_key) = create_wallet_account()?;
    let counter_account = create_counter_account(wallet_account.id(), fee_faucet_id)?;

    let committed_counter = deploy_counter_account(
        &counter_account,
        &genesis_header,
        &protocol_config,
        submission_client,
        prover,
    )
    .await?;
    let counter_anchor = resolve_counter_anchor(
        &mut rpc_client,
        &genesis_header,
        &protocol_config,
        &committed_counter,
    )
    .await?;

    info!(
        target: LOG_TARGET,
        "Successfully created and deployed accounts"
    );

    Ok(DeployedMonitorAccounts {
        wallet: wallet_account,
        secret_key,
        counter: counter_account,
        counter_anchor,
    })
}

/// Rejects chains the monitor's accounts cannot pay fees on.
///
/// Both monitor accounts are created in memory with empty vaults and are never funded: there is no
/// faucet the monitor could claim the fee asset from. So on a chain with a non-zero verification base
/// fee the wallet's `AuthSingleSig` fee payment would find no asset to withdraw and the counter's
/// network transaction would abort the same way, on every single increment. The counter's fee
/// schedule prices its own note at zero for the same reason.
pub fn ensure_monitor_supported_fee_parameters(genesis_header: &BlockHeader) -> Result<()> {
    let verification_base_fee = genesis_header.fee_parameters().verification_base_fee();
    anyhow::ensure!(
        verification_base_fee == 0,
        "the network monitor requires a chain with a zero verification base fee, but this chain's \
         genesis sets it to {verification_base_fee}: the monitor's accounts hold no assets and \
         cannot pay transaction fees",
    );
    Ok(())
}

/// The immutable chain state that counter-increment transactions are anchored at.
///
/// Every increment transaction emits a note targeted at the counter account, which makes the
/// paying account's auth procedure invoke the counter account's `estimate_note_fee` through FPI.
/// The kernel authenticates the foreign account against the reference block's account root, so the
/// transaction must reference a block that already contains the counter account, and the counter
/// state fed to the executor must be the state committed in that block.
///
/// The anchor is resolved once, right after deployment and before any increment note exists, and
/// then reused: the referenced block is historical and immutable, so later increments (which do
/// change the counter's live state) never invalidate it.
pub struct CounterAnchor {
    /// Header of the block the increment transactions reference.
    pub block_header: BlockHeader,
    /// Chain MMR whose peaks hash to `block_header.chain_commitment()`.
    pub blockchain: PartialBlockchain,
    /// Protocol configuration whose commitment is carried by `block_header`.
    pub protocol_config: ProtocolConfig,
    /// The counter account exactly as committed in `block_header`.
    pub counter_account: Account,
    /// Witness proving `counter_account`'s inclusion in `block_header`'s account tree.
    pub witness: AccountWitness,
}

/// Number of attempts to resolve the counter anchor before giving up.
const ANCHOR_RESOLUTION_ATTEMPTS: usize = 30;

/// Delay between counter anchor resolution attempts.
const ANCHOR_RESOLUTION_DELAY: Duration = Duration::from_secs(1);

/// Resolve the [`CounterAnchor`] for a freshly deployed counter account.
///
/// Retries until the chain tip contains the counter account in the state `committed_counter`
/// describes, since the deployment transaction needs a block to land in first.
async fn resolve_counter_anchor(
    rpc_client: &mut RpcClient,
    genesis_header: &BlockHeader,
    protocol_config: &ProtocolConfig,
    committed_counter: &Account,
) -> Result<CounterAnchor> {
    let genesis_commitment = genesis_header.commitment();
    let expected_state = committed_counter.to_commitment();
    let mut last_error = None;

    for attempt in 1..=ANCHOR_RESOLUTION_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(ANCHOR_RESOLUTION_DELAY).await;
        }

        match try_resolve_counter_anchor(
            rpc_client,
            committed_counter,
            expected_state,
            genesis_commitment,
            protocol_config,
        )
        .await
        {
            Ok(Some(anchor)) => {
                info!(
                    target: LOG_TARGET,
                    "Resolved counter FPI anchor",
                    account.id = committed_counter.id(),
                    block.number = anchor.block_header.block_num()
                );
                return Ok(anchor);
            },
            Ok(None) => debug!(
                target: LOG_TARGET,
                "Counter account not yet committed in the expected state; retrying",
                account.id = committed_counter.id(),
                retry.attempt = attempt
            ),
            Err(err) => {
                debug!(
                    &err,
                    target: LOG_TARGET,
                    "Counter anchor resolution attempt failed; retrying",
                    account.id = committed_counter.id(),
                    retry.attempt = attempt
                );
                last_error = Some(err);
            },
        }
    }

    let reason = last_error.map_or_else(
        || "the account was never committed in the expected state".to_string(),
        |err| format!("{err:#}"),
    );
    anyhow::bail!(
        "could not resolve the FPI anchor for counter account {} within {} attempts: {reason}",
        committed_counter.id(),
        ANCHOR_RESOLUTION_ATTEMPTS
    )
}

/// One [`resolve_counter_anchor`] attempt.
///
/// Returns `Ok(None)` when the chain is reachable but does not yet hold the counter account in the
/// expected state, which is the normal case while the deployment transaction is still in flight.
async fn try_resolve_counter_anchor(
    rpc_client: &mut RpcClient,
    committed_counter: &Account,
    expected_state: Word,
    genesis_commitment: Word,
    protocol_config: &ProtocolConfig,
) -> Result<Option<CounterAnchor>> {
    let (block_header, blockchain) = fetch_tip_chain_state(rpc_client, genesis_commitment).await?;
    let block_num = block_header.block_num();

    let witness = fetch_account_witness(rpc_client, committed_counter.id(), block_num).await?;

    // An account absent from the tree yields a witness for the requested ID whose commitment is the
    // empty word, so a plain state comparison covers "not committed yet" as well. Pin the ID too:
    // an account-ID prefix collision makes the tree return a witness for the *other* account, and
    // `MonitorDataStore` keys witnesses by the account they prove.
    if witness.id() != committed_counter.id() {
        anyhow::bail!(
            "account tree returned a witness for {} when {} was requested",
            witness.id(),
            committed_counter.id()
        );
    }

    if witness.state_commitment() != expected_state {
        return Ok(None);
    }

    Ok(Some(CounterAnchor {
        block_header,
        blockchain,
        protocol_config: protocol_config.clone(),
        counter_account: committed_counter.clone(),
        witness,
    }))
}

/// Fetch the chain tip header together with a [`PartialBlockchain`] whose peaks hash to that
/// header's chain commitment, making the pair usable as a transaction reference block.
async fn fetch_tip_chain_state(
    rpc_client: &mut RpcClient,
    genesis_commitment: Word,
) -> Result<(BlockHeader, PartialBlockchain)> {
    let response = rpc_client
        .sync_chain_mmr(SyncChainMmrRequest {
            // The MMR is seeded with the genesis block below, so the delta starts at block 1.
            current_client_block_height: BlockNumber::GENESIS.as_u32(),
            finality_level: FinalityLevel::Committed.into(),
        })
        .await
        .context("failed to sync the chain MMR")?
        .into_inner();

    let tip_header: BlockHeader = response
        .block_header
        .context("sync_chain_mmr response did not include a block header")?
        .try_into()
        .context("failed to convert the sync target block header")?;

    let delta: MmrDelta = response
        .mmr_delta
        .context("sync_chain_mmr response did not include an MMR delta")?
        .try_into()
        .context("failed to convert the MMR delta")?;

    let mut mmr = PartialMmr::from_peaks(
        MmrPeaks::new(Forest::new(0).context("empty forest should be valid")?, Vec::new())
            .context("empty MMR peaks should be valid")?,
    );

    if tip_header.block_num() != BlockNumber::GENESIS {
        mmr.add(genesis_commitment, false)
            .context("failed to seed the MMR with the genesis block")?;
        mmr.apply(delta).context("failed to apply the MMR delta")?;
    }

    anyhow::ensure!(
        mmr.peaks().hash_peaks() == tip_header.chain_commitment(),
        "synced MMR peaks do not match the chain commitment of block {}",
        tip_header.block_num()
    );

    let blockchain = PartialBlockchain::new(mmr, Vec::new())
        .context("failed to build the partial blockchain")?;

    Ok((tip_header, blockchain))
}

/// Fetch the account-tree witness proving an account's state in the given block.
async fn fetch_account_witness(
    rpc_client: &mut RpcClient,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<AccountWitness> {
    let request = ProtoAccountRequest {
        account_id: Some(account_id.into()),
        block_num: Some(block_num.into()),
        details: None,
    };

    let response = rpc_client
        .get_account(request)
        .await
        .context("failed to fetch the account witness")?
        .into_inner();

    let response =
        AccountResponse::try_from(response).context("failed to convert the account response")?;

    Ok(response.witness)
}

/// Fetch the genesis block header from RPC.
async fn fetch_genesis_block_header(rpc_client: &mut RpcClient) -> Result<BlockHeader> {
    let block_header_request = BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    };

    let response = rpc_client
        .get_block_header_by_number(block_header_request)
        .await
        .context("Failed to get the genesis block header from RPC")?;

    let root_block_header = response
        .into_inner()
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    root_block_header.try_into().context("Failed to convert block header")
}

/// Execute the counter account's genesis (creation) transaction in-memory.
///
/// Builds a [`MonitorDataStore`] over the genesis block header and executes the creation
/// transaction. Does not prove or submit.
pub(crate) async fn execute_counter_genesis_tx(
    counter_account: &Account,
    genesis_header: &BlockHeader,
    protocol_config: &ProtocolConfig,
) -> Result<ExecutedTransaction> {
    let genesis_header = genesis_header.clone();

    let genesis_chain_mmr =
        PartialBlockchain::new(PartialMmr::from_peaks(MmrPeaks::default()), Vec::new())
            .context("Failed to create empty ChainMmr")?;

    let mut data_store =
        MonitorDataStore::new(genesis_header, protocol_config.clone(), genesis_chain_mmr);
    data_store.add_account(counter_account.clone());

    let executor: TransactionExecutor<'_, '_, _, BasicAuthenticator> =
        TransactionExecutor::new(&data_store);

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

    Ok(executed_tx)
}

/// Build a valid set of transaction inputs for a throwaway counter genesis transaction.
///
/// Used as the static payload for the remote-prover probe: it produces a real, self-consistent
/// transaction the remote prover can re-execute and prove, without depending on the network
/// transaction service or any pre-existing on-chain account. The only network access is the RPC
/// handshake plus a single read of the genesis block header, which supplies both the reference block
/// and the fee faucet the counter's fee policy is denominated in. Nothing is proven or submitted
/// here.
pub async fn build_probe_transaction_inputs(
    rpc_url: &Url,
    fee_faucet_id: AccountId,
) -> Result<TransactionInputs> {
    let (wallet_account, _secret_key) = create_wallet_account()?;

    let (mut rpc_client, _) =
        create_genesis_aware_rpc_client(rpc_url, Duration::from_secs(10)).await?;
    let genesis_header = fetch_genesis_block_header(&mut rpc_client).await?;
    ensure_monitor_supported_fee_parameters(&genesis_header)?;
    let protocol_config = ProtocolConfig::current(AssetId::new_fungible(fee_faucet_id))
        .context("failed to construct the target protocol configuration")?;
    anyhow::ensure!(
        protocol_config.to_commitment() == genesis_header.protocol_config_commitment(),
        "configured fee faucet does not match the chain's protocol configuration",
    );
    let counter_account = create_counter_account(wallet_account.id(), fee_faucet_id)?;
    let executed_tx =
        execute_counter_genesis_tx(&counter_account, &genesis_header, &protocol_config).await?;

    Ok(executed_tx.tx_inputs().clone())
}

/// Deploy a counter account to the network by submitting its genesis transaction via RPC.
#[miden_instrument(
    target = COMPONENT,
    name = "deploy-counter-account",
    ret(level = "debug"),
)]
pub async fn deploy_counter_account(
    counter_account: &Account,
    genesis_header: &BlockHeader,
    protocol_config: &ProtocolConfig,
    submission_client: &TransactionSubmissionClient,
    prover: &LocalTransactionProver,
) -> Result<Account> {
    let executed_tx =
        execute_counter_genesis_tx(counter_account, genesis_header, protocol_config).await?;

    let transaction_inputs = executed_tx.tx_inputs().to_bytes();

    let committed_counter = Account::try_from(executed_tx.account_patch())
        .context("counter creation patch should convert to an account")?;

    let prover = prover.clone();
    let proven_tx = spawn_blocking_in_current_span(move || prover.prove(executed_tx))
        .await
        .context("prover task panicked")?
        .context("Failed to prove transaction")?;

    submission_client.submit(&proven_tx, &transaction_inputs).await?;

    Ok(committed_counter)
}

// MONITOR DATA STORE
// ================================================================================================

/// A [`DataStore`] implementation for the network monitor.
pub struct MonitorDataStore {
    accounts: HashMap<AccountId, Account>,
    account_witnesses: HashMap<AccountId, AccountWitness>,
    block_header: BlockHeader,
    protocol_config: ProtocolConfig,
    partial_block_chain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl MonitorDataStore {
    pub fn new(
        block_header: BlockHeader,
        protocol_config: ProtocolConfig,
        partial_block_chain: PartialBlockchain,
    ) -> Self {
        Self {
            accounts: HashMap::new(),
            account_witnesses: HashMap::new(),
            block_header,
            protocol_config,
            partial_block_chain,
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

impl DataStore for MonitorDataStore {
    async fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        mut _block_refs: BTreeSet<BlockNumber>,
    ) -> Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>
    {
        let account = self.get_account(account_id)?;
        let partial_account = PartialAccount::from(account);

        Ok((
            partial_account,
            self.block_header.clone(),
            self.protocol_config.clone(),
            self.partial_block_chain.clone(),
        ))
    }

    async fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> Result<StorageMapWitness, DataStoreError> {
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

    async fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> Result<AccountInputs, DataStoreError> {
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

    async fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetId>,
    ) -> Result<Vec<AssetWitness>, DataStoreError> {
        let account = self.get_account(account_id)?;

        if account.vault().root() != vault_root {
            return Err(DataStoreError::Other {
                error_msg: "vault root mismatch".into(),
                source: None,
            });
        }

        Result::<Vec<_>, _>::from_iter(vault_keys.into_iter().map(|vault_key| {
            AssetWitness::new(account.vault().open(vault_key).into(), [vault_key]).map_err(|err| {
                DataStoreError::Other {
                    error_msg: "failed to open vault asset tree".into(),
                    source: Some(Box::new(err)),
                }
            })
        }))
    }

    async fn get_note_script(
        &self,
        _script_root: NoteScriptRoot,
    ) -> Result<Option<NoteScript>, DataStoreError> {
        Ok(None)
    }
}

impl MastForestStore for MonitorDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_testing::MockChain;

    use super::ensure_monitor_supported_fee_parameters;

    /// A zero verification base fee is the only configuration the monitor's asset-less accounts can
    /// operate under, and the guard must say so at startup instead of letting every increment abort
    /// inside fee payment.
    #[test]
    fn fee_parameter_guard_accepts_only_a_zero_base_fee() {
        let zero_fee_chain = MockChain::builder().build().expect("chain should build");
        ensure_monitor_supported_fee_parameters(&zero_fee_chain.genesis_block_header())
            .expect("a zero base fee is supported");

        let fee_charging_chain = MockChain::builder()
            .verification_base_fee(500)
            .build()
            .expect("chain should build");
        let err =
            ensure_monitor_supported_fee_parameters(&fee_charging_chain.genesis_block_header())
                .expect_err("a non-zero base fee must be rejected");
        assert!(
            format!("{err:#}").contains("500"),
            "the error should name the offending base fee, got: {err:#}"
        );
    }
}
