//! Counter increment task functionality.
//!
//! This module contains the implementation for periodically incrementing the counter
//! of the network account deployed at startup by creating and submitting network notes.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_node_proto::generated::transaction::ProvenTransaction;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountCode, AccountFile, AccountHeader, AccountId};
use miden_protocol::asset::AssetVault;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::transaction::{InputNotes, PartialBlockchain, TransactionArgs};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Felt, Word};
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{LocalTransactionProver, TransactionExecutor};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::sync::Mutex;
use tracing::{error, info, instrument, warn};

use crate::config::MonitorConfig;
use crate::deploy::counter::COUNTER_SLOT_NAME;
use crate::deploy::{MonitorDataStore, create_genesis_aware_rpc_client};
use crate::service::Service;
use crate::status::{
    CounterTrackingDetails,
    IncrementDetails,
    PendingLatencyDetails,
    ServiceDetails,
    ServiceStatus,
};
use crate::{COMPONENT, current_unix_timestamp_secs};

/// Number of consecutive increment failures before re-syncing the wallet account from the RPC.
const RESYNC_FAILURE_THRESHOLD: usize = 3;

/// Number of consecutive increment failures before regenerating accounts from scratch.
const REGENERATE_FAILURE_THRESHOLD: usize = 10;

/// Minimum time between account regeneration attempts.
const REGENERATE_COOLDOWN: Duration = Duration::from_secs(3600);

// SHARED STATE
// ================================================================================================

#[derive(Debug, Default, Clone)]
pub struct LatencyState {
    pending: Option<PendingLatencyDetails>,
    pending_started: Option<Instant>,
    last_latency_blocks: Option<u32>,
}

// TX BUILDER
// ================================================================================================

/// Everything needed to build and submit one increment network note.
///
/// Produced by [`setup_increment_task`].
struct TxBuilder {
    wallet_account: Account,
    counter_account: Account,
    secret_key: SecretKey,
    increment_script: NoteScript,
    data_store: MonitorDataStore,
    block_header: BlockHeader,
    rng: ChaCha20Rng,
}

// FAILURE TRACKER
// ================================================================================================

/// Tracks consecutive increment failures and gates re-sync / regeneration actions.
#[derive(Default)]
struct FailureTracker {
    consecutive_failures: usize,
    last_regeneration: Option<Instant>,
}

impl FailureTracker {
    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
    }

    fn reset(&mut self) {
        self.consecutive_failures = 0;
    }

    fn should_resync(&self) -> bool {
        self.consecutive_failures >= RESYNC_FAILURE_THRESHOLD
    }

    fn should_regenerate(&self) -> bool {
        self.consecutive_failures >= REGENERATE_FAILURE_THRESHOLD
            && self.last_regeneration.is_none_or(|t| t.elapsed() >= REGENERATE_COOLDOWN)
    }

    fn mark_regenerated(&mut self) {
        self.last_regeneration = Some(Instant::now());
    }
}

// INCREMENT SERVICE
// ================================================================================================

/// Periodically submits a network note that increments the counter account.
pub struct IncrementService {
    config: MonitorConfig,
    rpc_client: RpcClient,
    tx: TxBuilder,
    failures: FailureTracker,
    details: IncrementDetails,
    expected_counter_value: Arc<AtomicU64>,
    latency_state: Arc<Mutex<LatencyState>>,
}

impl IncrementService {
    pub async fn new(
        config: MonitorConfig,
        expected_counter_value: Arc<AtomicU64>,
        latency_state: Arc<Mutex<LatencyState>>,
    ) -> Result<Self> {
        let mut rpc_client =
            create_genesis_aware_rpc_client(&config.rpc_url, config.request_timeout).await?;
        let (tx, details) = setup_increment_task(config.clone(), &mut rpc_client).await?;
        Ok(Self {
            config,
            rpc_client,
            tx,
            failures: FailureTracker::default(),
            details,
            expected_counter_value,
            latency_state,
        })
    }

    /// Applies a successful increment: updates the wallet nonce, bumps counters, and returns the
    /// next expected counter value.
    fn handle_increment_success(&mut self, final_account: &AccountHeader, tx_id: String) -> u64 {
        let updated_wallet = Account::new(
            self.tx.wallet_account.id(),
            self.tx.wallet_account.vault().clone(),
            self.tx.wallet_account.storage().clone(),
            self.tx.wallet_account.code().clone(),
            final_account.nonce(),
            None,
        )
        .expect("nonce-only update of an already-valid account cannot fail");
        self.tx.wallet_account = updated_wallet;
        self.tx.data_store.update_account(self.tx.wallet_account.clone());

        self.details.success_count += 1;
        self.details.last_tx_id = Some(tx_id);

        self.expected_counter_value.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Re-sync the wallet account from the RPC after repeated failures.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.counter.try_resync_wallet_account",
        skip_all,
        fields(account.id = %self.tx.wallet_account.id()),
        level = "warn",
        err,
    )]
    async fn try_resync_wallet_account(&mut self) -> Result<()> {
        let fresh_account = fetch_wallet_account(&mut self.rpc_client, self.tx.wallet_account.id())
            .await
            .inspect_err(|e| {
                error!(account.id = %self.tx.wallet_account.id(), err = ?e, "failed to re-sync wallet account from RPC");
            })?
            .context("wallet account not found on-chain during re-sync")
            .inspect_err(|e| {
                error!(account.id = %self.tx.wallet_account.id(), err = ?e, "wallet account not found on-chain during re-sync");
            })?;

        info!(account.id = %self.tx.wallet_account.id(), "wallet account re-synced from RPC");
        self.tx.wallet_account = fresh_account;
        self.tx.data_store.update_account(self.tx.wallet_account.clone());
        Ok(())
    }

    /// Regenerate accounts from scratch when re-sync is ineffective.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.counter.try_regenerate_accounts",
        skip_all,
        level = "warn",
        err,
    )]
    async fn try_regenerate_accounts(&mut self) -> Result<()> {
        crate::deploy::force_recreate_accounts(
            &self.config.wallet_filepath,
            &self.config.counter_filepath,
            &self.config.rpc_url,
        )
        .await
        .context("failed to regenerate accounts")?;

        let (tx, details) = setup_increment_task(self.config.clone(), &mut self.rpc_client).await?;
        self.tx = tx;
        self.details = details;

        info!("account regeneration completed, increment task re-initialized");
        Ok(())
    }

    /// Create and submit a network note that increments the counter account.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.counter.submit_increment",
        skip_all,
        level = "info",
        ret(level = "debug"),
        err
    )]
    async fn submit_increment(&mut self) -> Result<(String, AccountHeader, BlockNumber)> {
        let authenticator = BasicAuthenticator::new(&[AuthSecretKey::Falcon512Poseidon2(
            self.tx.secret_key.clone(),
        )]);

        let account_interface = AccountInterface::from_account(&self.tx.wallet_account);

        let (network_note, note_recipient) = create_network_note(
            &self.tx.wallet_account,
            &self.tx.counter_account,
            self.tx.increment_script.clone(),
            &mut self.tx.rng,
        )?;
        let script = account_interface.build_send_notes_script(&[network_note.into()], None)?;

        let executor =
            TransactionExecutor::new(&self.tx.data_store).with_authenticator(&authenticator);

        let mut tx_args = TransactionArgs::default().with_tx_script(script);
        tx_args.add_output_note_recipient(Box::new(note_recipient));

        let executed_tx = Box::pin(executor.execute_transaction(
            self.tx.wallet_account.id(),
            self.tx.block_header.block_num(),
            InputNotes::default(),
            tx_args,
        ))
        .await
        .context("Failed to execute transaction")?;

        let tx_inputs = executed_tx.tx_inputs().to_bytes();
        let final_account = executed_tx.final_account().clone();

        let prover = LocalTransactionProver::default();
        let proven_tx = prover.prove(executed_tx).await.context("Failed to prove transaction")?;

        let request = ProvenTransaction {
            transaction: proven_tx.to_bytes(),
            transaction_inputs: Some(tx_inputs),
        };

        let block_height: BlockNumber = self
            .rpc_client
            .submit_proven_tx(request)
            .await
            .context("Failed to submit proven transaction to RPC")?
            .into_inner()
            .block_num
            .into();

        info!("Submitted proven transaction to RPC");

        let tx_id = proven_tx.id().to_hex();

        Ok((tx_id, final_account, block_height))
    }
}

impl Service for IncrementService {
    fn name(&self) -> &'static str {
        "Local Transactions"
    }

    fn interval(&self) -> Duration {
        self.config.counter_increment_interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::NtxIncrement(IncrementDetails::default()),
        )
    }

    async fn check(&mut self) -> ServiceStatus {
        let mut last_error = None;

        match self.submit_increment().await {
            Ok((tx_id, final_account, block_height)) => {
                self.failures.reset();
                let target_value = self.handle_increment_success(&final_account, tx_id);
                let mut guard = self.latency_state.lock().await;
                guard.pending = Some(PendingLatencyDetails {
                    submit_height: block_height.as_u32(),
                    target_value,
                });
                guard.pending_started = Some(Instant::now());
            },
            Err(e) => {
                error!("Failed to create and submit network note: {:?}", e);
                self.details.failure_count += 1;
                self.failures.record_failure();
                last_error = Some(format!("create/submit note failed: {e}"));

                if self.failures.should_resync() && self.try_resync_wallet_account().await.is_ok() {
                    self.failures.reset();
                }

                if self.failures.should_regenerate() {
                    warn!(
                        consecutive_failures = self.failures.consecutive_failures,
                        "re-sync ineffective, regenerating accounts from scratch"
                    );
                    self.failures.mark_regenerated();
                    match self.try_regenerate_accounts().await {
                        Ok(()) => self.failures.reset(),
                        Err(regen_err) => {
                            error!("account regeneration failed: {regen_err:?}");
                        },
                    }
                }
            },
        }

        {
            let guard = self.latency_state.lock().await;
            self.details.last_latency_blocks = guard.last_latency_blocks;
        }

        build_increment_status(&self.details, last_error)
    }
}

// COUNTER TRACKING SERVICE
// ================================================================================================

/// Periodically fetches the counter value and reports how far the observed value trails the
/// expected value.
pub struct CounterTrackingService {
    config: MonitorConfig,
    rpc_client: RpcClient,
    counter_account: Account,
    details: CounterTrackingDetails,
    expected_counter_value: Arc<AtomicU64>,
    latency_state: Arc<Mutex<LatencyState>>,
}

impl CounterTrackingService {
    pub async fn new(
        config: MonitorConfig,
        expected_counter_value: Arc<AtomicU64>,
        latency_state: Arc<Mutex<LatencyState>>,
    ) -> Result<Self> {
        let mut rpc_client =
            create_genesis_aware_rpc_client(&config.rpc_url, config.request_timeout).await?;
        let counter_account = load_counter_account(&config.counter_filepath)
            .context("Failed to load counter account")?;

        let mut details = CounterTrackingDetails::default();
        initialize_tracking_state(
            &mut rpc_client,
            &counter_account,
            &expected_counter_value,
            &mut details,
        )
        .await;

        Ok(Self {
            config,
            rpc_client,
            counter_account,
            details,
            expected_counter_value,
            latency_state,
        })
    }

    /// The increment service regenerates accounts on persistent failure and rewrites the counter
    /// account file. If the file's account ID has changed, switch to the new account and reset
    /// tracking state.
    async fn reload_counter_account_if_changed(&mut self) {
        let reloaded = match load_counter_account(&self.config.counter_filepath) {
            Ok(account) => account,
            Err(e) => {
                warn!(err = ?e, "failed to reload counter account file");
                return;
            },
        };

        if reloaded.id() == self.counter_account.id() {
            return;
        }

        info!(
            old.id = %self.counter_account.id(),
            new.id = %reloaded.id(),
            "counter account file changed, resetting tracking state",
        );
        self.counter_account = reloaded;
        self.details = CounterTrackingDetails::default();
        initialize_tracking_state(
            &mut self.rpc_client,
            &self.counter_account,
            &self.expected_counter_value,
            &mut self.details,
        )
        .await;
    }

    /// Poll the counter once, updating details and latency tracking state.
    async fn poll_counter_once(&mut self) -> Option<String> {
        let mut last_error = None;
        let current_time = current_unix_timestamp_secs();

        match fetch_counter_value(&mut self.rpc_client, self.counter_account.id()).await {
            Ok(Some(value)) => {
                self.details.current_value = Some(value);
                self.details.last_updated = Some(current_time);

                update_expected_and_pending(&mut self.details, &self.expected_counter_value, value);
                self.handle_latency_tracking(value, &mut last_error).await;
            },
            Ok(None) => {
                // Counter value not available, but not an error
            },
            Err(e) => {
                error!("Failed to fetch counter value: {:?}", e);
                last_error = Some(format!("fetch counter value failed: {e}"));
            },
        }

        last_error
    }

    /// Update latency tracking state, performing RPC as needed while minimizing lock hold time.
    async fn handle_latency_tracking(
        &mut self,
        observed_value: u64,
        last_error: &mut Option<String>,
    ) {
        let (pending, pending_started) = {
            let guard = self.latency_state.lock().await;
            (guard.pending.clone(), guard.pending_started)
        };

        let Some(pending) = pending else {
            return;
        };

        if observed_value >= pending.target_value {
            match fetch_chain_tip(&mut self.rpc_client).await {
                Ok(observed_height) => {
                    let latency_blocks = observed_height.saturating_sub(pending.submit_height);
                    let mut guard = self.latency_state.lock().await;
                    if guard.pending.as_ref().map(|p| p.target_value) == Some(pending.target_value)
                    {
                        guard.last_latency_blocks = Some(latency_blocks);
                        guard.pending = None;
                        guard.pending_started = None;
                    }
                },
                Err(e) => {
                    *last_error = Some(format!("Failed to fetch chain tip for latency calc: {e}"));
                },
            }
        } else if let Some(started) = pending_started {
            if Instant::now().saturating_duration_since(started)
                >= self.config.counter_latency_timeout
            {
                warn!(
                    "Latency measurement timed out after {:?} for target value {}",
                    self.config.counter_latency_timeout, pending.target_value
                );
                let mut guard = self.latency_state.lock().await;
                if guard.pending.as_ref().map(|p| p.target_value) == Some(pending.target_value) {
                    guard.pending = None;
                    guard.pending_started = None;
                }
                *last_error = Some(format!(
                    "Timed out after {:?} waiting for counter to reach {}",
                    self.config.counter_latency_timeout, pending.target_value
                ));
            }
        }
    }
}

impl Service for CounterTrackingService {
    fn name(&self) -> &'static str {
        "Network Transactions"
    }

    fn interval(&self) -> Duration {
        // Tracking polls twice per increment cadence so it catches freshly-incremented values soon
        // after submission.
        self.config.counter_increment_interval / 2
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(self.name(), ServiceDetails::NtxTracking(self.details.clone()))
    }

    async fn check(&mut self) -> ServiceStatus {
        self.reload_counter_account_if_changed().await;
        let last_error = self.poll_counter_once().await;
        build_tracking_status(&self.details, last_error)
    }
}

// SETUP
// ================================================================================================

/// Load wallet + counter accounts, fetch the genesis block header, and build the data store and
/// increment script needed to produce network notes.
async fn setup_increment_task(
    config: MonitorConfig,
    rpc_client: &mut RpcClient,
) -> Result<(TxBuilder, IncrementDetails)> {
    let wallet_account_file =
        AccountFile::read(config.wallet_filepath).context("Failed to read wallet account file")?;
    let wallet_account = fetch_wallet_account(rpc_client, wallet_account_file.account.id())
        .await?
        .unwrap_or(wallet_account_file.account.clone());

    let AuthSecretKey::Falcon512Poseidon2(secret_key) = wallet_account_file
        .auth_secret_keys
        .first()
        .expect("wallet account file should have one auth secret key")
        .clone()
    else {
        anyhow::bail!("Failed to load wallet account, auth secret key not found")
    };

    let counter_account = load_counter_account(&config.counter_filepath)
        .inspect_err(|e| error!("Failed to load counter account: {:?}", e))?;

    let block_header = get_genesis_block_header(rpc_client).await?;

    let increment_script = create_increment_script()?;

    let mut data_store = MonitorDataStore::new(block_header.clone(), PartialBlockchain::default());
    data_store.add_account(wallet_account.clone());
    data_store.add_account(counter_account.clone());

    let tx = TxBuilder {
        wallet_account,
        counter_account,
        secret_key,
        increment_script,
        data_store,
        block_header,
        rng: ChaCha20Rng::from_os_rng(),
    };

    Ok((tx, IncrementDetails::default()))
}

/// Initialize tracking state by fetching the current counter value from the node.
async fn initialize_tracking_state(
    rpc_client: &mut RpcClient,
    counter_account: &Account,
    expected_counter_value: &Arc<AtomicU64>,
    details: &mut CounterTrackingDetails,
) {
    match fetch_counter_value(rpc_client, counter_account.id()).await {
        Ok(Some(initial_value)) => {
            expected_counter_value.store(initial_value, Ordering::Relaxed);
            details.current_value = Some(initial_value);
            details.expected_value = Some(initial_value);
            details.last_updated = Some(current_unix_timestamp_secs());
            info!("Initialized counter tracking with value: {}", initial_value);
        },
        Ok(None) => {
            expected_counter_value.store(0, Ordering::Relaxed);
            warn!("Counter account not found, initializing expected value to 0");
        },
        Err(e) => {
            expected_counter_value.store(0, Ordering::Relaxed);
            error!("Failed to fetch initial counter value, initializing to 0: {:?}", e);
        },
    }
}

// STATUS BUILDERS
// ================================================================================================

/// Build a `ServiceStatus` snapshot from the current increment details and last error.
fn build_increment_status(details: &IncrementDetails, last_error: Option<String>) -> ServiceStatus {
    let service_details = ServiceDetails::NtxIncrement(details.clone());

    if let Some(err) = last_error {
        ServiceStatus::unhealthy("Local Transactions", err, service_details)
    } else if details.success_count == 0 && details.failure_count > 0 {
        ServiceStatus::unhealthy(
            "Local Transactions",
            format!("no successful increments ({} failures)", details.failure_count),
            service_details,
        )
    } else {
        ServiceStatus::healthy("Local Transactions", service_details)
    }
}

/// Build a `ServiceStatus` snapshot from the current tracking details and last error.
fn build_tracking_status(
    details: &CounterTrackingDetails,
    last_error: Option<String>,
) -> ServiceStatus {
    let service_details = ServiceDetails::NtxTracking(details.clone());

    if let Some(err) = last_error {
        ServiceStatus::unhealthy("Network Transactions", err, service_details)
    } else if details.current_value.is_some() {
        ServiceStatus::healthy("Network Transactions", service_details)
    } else {
        ServiceStatus::unknown("Network Transactions", service_details)
    }
}

/// Update expected and pending counters based on the latest observed value.
fn update_expected_and_pending(
    details: &mut CounterTrackingDetails,
    expected_counter_value: &Arc<AtomicU64>,
    observed_value: u64,
) {
    let expected = expected_counter_value.load(Ordering::Relaxed);
    details.expected_value = Some(expected);

    if expected >= observed_value {
        details.pending_increments = Some(expected - observed_value);
    } else {
        warn!(
            "Expected counter value ({}) is less than current value ({}), setting pending to 0",
            expected, observed_value
        );
        details.pending_increments = Some(0);
    }
}

// RPC HELPERS
// ================================================================================================

/// Get the genesis block header.
async fn get_genesis_block_header(rpc_client: &mut RpcClient) -> Result<BlockHeader> {
    let block_header_request = BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    };

    let response = rpc_client
        .get_block_header_by_number(block_header_request)
        .await
        .context("Failed to get genesis block header from RPC")?
        .into_inner();

    let genesis_block_header = response
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    let block_header: BlockHeader =
        genesis_block_header.try_into().context("Failed to convert block header")?;

    Ok(block_header)
}

/// Fetch the storage header of the given account from RPC.
///
/// Returns `None` if the account does not exist or has no details available.
async fn fetch_account_storage_header(
    rpc_client: &mut RpcClient,
    account_id: AccountId,
) -> Result<Option<miden_node_proto::generated::account::AccountStorageHeader>> {
    let request = build_account_request(account_id, false);
    let resp = rpc_client.get_account(request).await?.into_inner();

    let Some(details) = resp.details else {
        return Ok(None);
    };

    let storage_details = details.storage_details.context("missing storage details")?;
    let storage_header = storage_details.header.context("missing storage header")?;

    Ok(Some(storage_header))
}

/// Fetch the latest nonce of the given account from RPC.
async fn fetch_counter_value(
    rpc_client: &mut RpcClient,
    account_id: AccountId,
) -> Result<Option<u64>> {
    let Some(storage_header) = fetch_account_storage_header(rpc_client, account_id).await? else {
        return Ok(None);
    };

    let counter_slot = storage_header
        .slots
        .iter()
        .find(|slot| slot.slot_name == COUNTER_SLOT_NAME.as_str())
        .context(format!("counter slot '{}' not found", COUNTER_SLOT_NAME.as_str()))?;

    // The counter value is stored as a Word, with the actual u64 value in the first element
    let slot_value: Word = counter_slot
        .commitment
        .as_ref()
        .context("missing storage slot value")?
        .try_into()
        .context("failed to convert slot value to word")?;

    let value = slot_value
        .as_elements()
        .first()
        .expect("Word has 4 elements")
        .as_canonical_u64();

    Ok(Some(value))
}

/// Build an account request for the given account ID.
///
/// If `include_code_and_vault` is true, uses dummy commitments to force the server
/// to return code and vault data (server only returns data when our commitment differs).
fn build_account_request(
    account_id: AccountId,
    include_code_and_vault: bool,
) -> miden_node_proto::generated::rpc::AccountRequest {
    let id_bytes: [u8; 15] = account_id.into();
    let account_id_proto =
        miden_node_proto::generated::account::AccountId { id: id_bytes.to_vec() };

    let (code_commitment, asset_vault_commitment) = if include_code_and_vault {
        let dummy: miden_node_proto::generated::primitives::Digest = Word::default().into();
        (Some(dummy), Some(dummy))
    } else {
        (None, None)
    };

    miden_node_proto::generated::rpc::AccountRequest {
        account_id: Some(account_id_proto),
        block_num: None,
        details: Some(miden_node_proto::generated::rpc::account_request::AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_maps: vec![],
        }),
    }
}

/// Fetch an account from RPC and reconstruct the full Account.
///
/// Uses dummy commitments to force the server to return all data (code, vault, storage header).
/// Only supports accounts with value slots; returns an error if storage maps are present.
async fn fetch_wallet_account(
    rpc_client: &mut RpcClient,
    account_id: AccountId,
) -> Result<Option<Account>> {
    let request = build_account_request(account_id, true);

    let response = match rpc_client.get_account(request).await {
        Ok(response) => response.into_inner(),
        Err(e) => {
            warn!(account.id = %account_id, err = %e, "failed to fetch wallet account via RPC");
            return Ok(None);
        },
    };

    let Some(details) = response.details else {
        if response.witness.is_some() {
            info!(
                account.id = %account_id,
                "account found on-chain but cannot reconstruct full account from RPC response"
            );
        }
        return Ok(None);
    };

    let header = details.header.context("missing account header")?;
    let nonce: u64 = header.nonce;

    let code = details
        .code
        .map(|code_bytes| AccountCode::read_from_bytes(&code_bytes))
        .transpose()
        .context("failed to deserialize account code")?
        .context("server did not return account code")?;

    let vault = match details.vault_details {
        Some(vault_details) if vault_details.too_many_assets => {
            anyhow::bail!("account {account_id} has too many assets, cannot fetch full account");
        },
        Some(vault_details) => {
            let assets: Vec<miden_protocol::asset::Asset> = vault_details
                .assets
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()
                .context("failed to convert assets")?;
            AssetVault::new(&assets).context("failed to create vault")?
        },
        None => anyhow::bail!("server did not return asset vault for account {account_id}"),
    };

    let storage_details = details.storage_details.context("missing storage details")?;
    let storage = build_account_storage(storage_details)?;

    let account = Account::new(account_id, vault, storage, code, Felt::new(nonce), None)
        .context("failed to create account")?;

    // Sanity check: verify reconstructed account matches header commitments
    let expected_code_commitment: Word = header
        .code_commitment
        .context("missing code commitment in header")?
        .try_into()
        .context("invalid code commitment")?;
    let expected_vault_root: Word = header
        .vault_root
        .context("missing vault root in header")?
        .try_into()
        .context("invalid vault root")?;
    let expected_storage_commitment: Word = header
        .storage_commitment
        .context("missing storage commitment in header")?
        .try_into()
        .context("invalid storage commitment")?;

    anyhow::ensure!(
        account.code().commitment() == expected_code_commitment,
        "code commitment mismatch: rebuilt={:?}, expected={:?}",
        account.code().commitment(),
        expected_code_commitment
    );
    anyhow::ensure!(
        account.vault().root() == expected_vault_root,
        "vault root mismatch: rebuilt={:?}, expected={:?}",
        account.vault().root(),
        expected_vault_root
    );
    anyhow::ensure!(
        account.storage().to_commitment() == expected_storage_commitment,
        "storage commitment mismatch: rebuilt={:?}, expected={:?}",
        account.storage().to_commitment(),
        expected_storage_commitment
    );

    info!(account.id = %account_id, "fetched wallet account from RPC");
    Ok(Some(account))
}

/// Build account storage from the storage details returned by the server.
///
/// This function only supports accounts with value slots. If any storage map slots
/// are encountered, an error is returned since the monitor only uses simple accounts.
fn build_account_storage(
    storage_details: miden_node_proto::generated::rpc::AccountStorageDetails,
) -> Result<miden_protocol::account::AccountStorage> {
    use miden_protocol::account::{AccountStorage, StorageSlot};

    let storage_header = storage_details.header.context("missing storage header")?;

    let mut slots = Vec::new();
    for slot in storage_header.slots {
        let slot_name = miden_protocol::account::StorageSlotName::new(slot.slot_name.clone())
            .context("invalid slot name")?;
        let value: Word = slot
            .commitment
            .context("missing slot value")?
            .try_into()
            .context("invalid slot value")?;

        // slot_type: 0 = Value, 1 = Map
        anyhow::ensure!(
            slot.slot_type == 0,
            "storage map slots are not supported for this account"
        );

        slots.push(StorageSlot::with_value(slot_name, value));
    }

    AccountStorage::new(slots).context("failed to create account storage")
}

/// Load counter account from file.
fn load_counter_account(file_path: &Path) -> Result<Account> {
    let account_file =
        AccountFile::read(file_path).context("Failed to read counter account file")?;

    Ok(account_file.account.clone())
}

/// Create the increment procedure script.
fn create_increment_script() -> Result<NoteScript> {
    let script =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/assets/counter_program.masm"));

    let script_builder = CodeBuilder::new()
        .with_linked_module("external_contract::counter_contract", script)
        .context("Failed to create script builder with library")?;

    let note_script = script_builder
        .compile_note_script(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/assets/increment_counter.masm"
        )))
        .context("Failed to compile note script")?;

    Ok(note_script)
}

/// Create a network note that targets the counter account.
fn create_network_note(
    wallet_account: &Account,
    counter_account: &Account,
    script: NoteScript,
    rng: &mut ChaCha20Rng,
) -> Result<(Note, NoteRecipient)> {
    let target = NetworkAccountTarget::new(counter_account.id(), NoteExecutionHint::Always)
        .context("Failed to create NetworkAccountTarget for counter account")?;
    let attachment: NoteAttachment = target.into();
    let attachments = NoteAttachments::from(attachment);

    let partial_metadata = PartialNoteMetadata::new(wallet_account.id(), NoteType::Public);

    let serial_num = Word::new([
        Felt::new(rng.random()),
        Felt::new(rng.random()),
        Felt::new(rng.random()),
        Felt::new(rng.random()),
    ]);

    let recipient = NoteRecipient::new(serial_num, script, NoteStorage::new(vec![])?);

    let network_note = Note::with_attachments(
        NoteAssets::new(vec![])?,
        partial_metadata,
        recipient.clone(),
        attachments,
    );
    Ok((network_note, recipient))
}

/// Fetch the current chain tip height from RPC status.
async fn fetch_chain_tip(rpc_client: &mut RpcClient) -> Result<u32> {
    let status = rpc_client.status(()).await?.into_inner();

    if let Some(block_producer_status) = status.block_producer {
        Ok(block_producer_status.chain_tip)
    } else if let Some(store_status) = status.store {
        Ok(store_status.chain_tip)
    } else {
        anyhow::bail!("RPC status response did not include a chain tip")
    }
}
