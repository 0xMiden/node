//! Counter increment task functionality.
//!
//! This module contains the implementation for periodically incrementing the counter
//! of the network account deployed at startup by creating and submitting network notes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_node_proto::generated::transaction::ProvenTransaction;
use miden_node_utils::spawn::spawn_blocking_in_current_span;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountCode, AccountHeader, AccountId};
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
use tokio::sync::{Mutex, watch};
use tracing::{error, info, instrument, warn};

use crate::config::MonitorConfig;
use crate::deploy::counter::COUNTER_SLOT_NAME;
use crate::deploy::{
    MonitorDataStore,
    create_and_deploy_accounts,
    create_genesis_aware_rpc_client,
};
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

/// Number of consecutive polls observing the pending-increments gap above
/// [`MonitorConfig::counter_pending_unhealthy_threshold`] before flipping the Network Transactions
/// card to unhealthy. Buffers against a single in-flight batch of notes flapping the card.
const PENDING_UNHEALTHY_CONFIRMATION_POLLS: u32 = 3;

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
    /// Publishes the current counter account to [`CounterTrackingService`]. A new value is sent
    /// whenever the increment task regenerates accounts after persistent failures, so the tracker
    /// can switch to the new account ID without polling disk.
    counter_sender: watch::Sender<Account>,
}

impl IncrementService {
    pub async fn new(
        config: MonitorConfig,
        wallet_account: Account,
        secret_key: SecretKey,
        counter_account: Account,
        counter_sender: watch::Sender<Account>,
        expected_counter_value: Arc<AtomicU64>,
        latency_state: Arc<Mutex<LatencyState>>,
    ) -> Result<Self> {
        let mut rpc_client =
            create_genesis_aware_rpc_client(&config.rpc_url, config.request_timeout).await?;
        let (tx, details) =
            setup_increment_task(wallet_account, secret_key, counter_account, &mut rpc_client)
                .await?;
        Ok(Self {
            config,
            rpc_client,
            tx,
            failures: FailureTracker::default(),
            details,
            expected_counter_value,
            latency_state,
            counter_sender,
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
        Ok(())
    }

    /// Regenerate accounts from scratch when re-sync is ineffective.
    ///
    /// Builds a fresh wallet/counter pair in memory, deploys the counter to the network, swaps
    /// the local [`TxBuilder`] state, and publishes the new counter on [`Self::counter_sender`]
    /// so the tracker switches over without polling disk.
    #[instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.counter.try_regenerate_accounts",
        skip_all,
        level = "warn",
        err,
    )]
    async fn try_regenerate_accounts(&mut self) -> Result<()> {
        let (wallet_account, secret_key, counter_account) =
            create_and_deploy_accounts(&self.config.rpc_url)
                .await
                .context("failed to regenerate accounts")?;

        let (tx, details) = setup_increment_task(
            wallet_account,
            secret_key,
            counter_account.clone(),
            &mut self.rpc_client,
        )
        .await?;
        self.tx = tx;
        self.details = details;

        self.counter_sender
            .send(counter_account)
            .context("counter tracker dropped before regeneration completed")?;

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
        let account_interface = AccountInterface::from_account(&self.tx.wallet_account);

        let (network_note, note_recipient) = create_network_note(
            &self.tx.wallet_account,
            &self.tx.counter_account,
            self.tx.increment_script.clone(),
            &mut self.tx.rng,
        )?;
        let script = account_interface.build_send_notes_script(&[network_note.into()], None)?;

        let mut tx_args = TransactionArgs::default().with_tx_script(script);
        tx_args.add_output_note_recipient(Box::new(note_recipient));

        let wallet_account = self.tx.wallet_account.clone();
        let counter_account = self.tx.counter_account.clone();
        let block_header = self.tx.block_header.clone();
        let secret_key = self.tx.secret_key.clone();
        let handle = tokio::runtime::Handle::current();
        let (proven_tx, tx_inputs, final_account) = spawn_blocking_in_current_span(move || {
            let account_id = wallet_account.id();
            let block_num = block_header.block_num();
            let mut data_store = MonitorDataStore::new(block_header, PartialBlockchain::default());
            data_store.add_account(wallet_account);
            data_store.add_account(counter_account);

            let authenticator =
                BasicAuthenticator::new(&[AuthSecretKey::Falcon512Poseidon2(secret_key)]);
            let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

            let executed_tx = handle
                .block_on(executor.execute_transaction(
                    account_id,
                    block_num,
                    InputNotes::default(),
                    tx_args,
                ))
                .context("Failed to execute transaction")?;

            let tx_inputs = executed_tx.tx_inputs().to_bytes();
            let final_account = executed_tx.final_account().clone();
            let proven_tx = handle
                .block_on(LocalTransactionProver::default().prove(executed_tx))
                .context("Failed to prove transaction")?;

            Ok::<_, anyhow::Error>((proven_tx, tx_inputs, final_account))
        })
        .await
        .context("counter increment task failed")??;

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
    /// Observes regenerations of the counter account from [`IncrementService`].
    counter_receiver: watch::Receiver<Account>,
    details: CounterTrackingDetails,
    expected_counter_value: Arc<AtomicU64>,
    latency_state: Arc<Mutex<LatencyState>>,
    /// Consecutive polls that observed `pending_increments > counter_pending_unhealthy_threshold`.
    /// Used to confirm a real backlog before flipping the card to unhealthy.
    over_threshold_streak: u32,
}

impl CounterTrackingService {
    pub async fn new(
        config: MonitorConfig,
        counter_receiver: watch::Receiver<Account>,
        expected_counter_value: Arc<AtomicU64>,
        latency_state: Arc<Mutex<LatencyState>>,
    ) -> Result<Self> {
        let mut rpc_client =
            create_genesis_aware_rpc_client(&config.rpc_url, config.request_timeout).await?;
        let counter_account = counter_receiver.borrow().clone();

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
            counter_receiver,
            details,
            expected_counter_value,
            latency_state,
            over_threshold_streak: 0,
        })
    }

    /// If [`IncrementService`] regenerated accounts and published a new counter, adopt it and reset
    /// tracking state.
    async fn reload_counter_account_if_changed(&mut self) {
        if !self.counter_receiver.has_changed().unwrap_or(false) {
            return;
        }
        let reloaded = self.counter_receiver.borrow_and_update().clone();
        if reloaded.id() == self.counter_account.id() {
            return;
        }

        info!(
            old.id = %self.counter_account.id(),
            new.id = %reloaded.id(),
            "counter account changed, resetting tracking state",
        );
        self.counter_account = reloaded;
        self.details = CounterTrackingDetails::default();
        self.over_threshold_streak = 0;
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
        self.update_over_threshold_streak();
        build_tracking_status(
            &self.details,
            last_error,
            self.over_threshold_streak,
            self.config.counter_pending_unhealthy_threshold,
        )
    }
}

impl CounterTrackingService {
    /// Update the over-threshold streak using the most recent pending-increments observation.
    ///
    /// - A fresh observation strictly above the threshold extends the streak.
    /// - A fresh observation at or below the threshold resets it.
    /// - No fresh observation (RPC error, counter not yet observed) leaves the streak unchanged
    ///   so a single missing tick doesn't paper over a real backlog.
    fn update_over_threshold_streak(&mut self) {
        let Some(pending) = self.details.pending_increments else {
            return;
        };
        if pending > self.config.counter_pending_unhealthy_threshold {
            self.over_threshold_streak = self.over_threshold_streak.saturating_add(1);
        } else {
            self.over_threshold_streak = 0;
        }
    }
}

// SETUP
// ================================================================================================

/// Fetch the genesis block header and build the data store + increment script needed to produce
/// network notes from a freshly-created wallet/counter pair. The accounts are passed in already
/// constructed by [`create_and_deploy_accounts`]; there is no file I/O.
async fn setup_increment_task(
    wallet_account: Account,
    secret_key: SecretKey,
    counter_account: Account,
    rpc_client: &mut RpcClient,
) -> Result<(TxBuilder, IncrementDetails)> {
    let block_header = get_genesis_block_header(rpc_client).await?;

    let increment_script = create_increment_script()?;

    let tx = TxBuilder {
        wallet_account,
        counter_account,
        secret_key,
        increment_script,
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
///
/// Health priority:
/// 1. Explicit RPC errors from this poll flip the card to unhealthy immediately.
/// 2. A sustained backlog (the pending-increments gap exceeded the configured threshold for at
///    least [`PENDING_UNHEALTHY_CONFIRMATION_POLLS`] polls in a row) flips the card to
///    unhealthy. A single in-flight batch of notes won't hit this; a network silently dropping
///    notes will.
/// 3. Otherwise healthy if we have observed a counter value, unknown if we haven't yet.
fn build_tracking_status(
    details: &CounterTrackingDetails,
    last_error: Option<String>,
    over_threshold_streak: u32,
    threshold: u64,
) -> ServiceStatus {
    let service_details = ServiceDetails::NtxTracking(details.clone());

    if let Some(err) = last_error {
        return ServiceStatus::unhealthy("Network Transactions", err, service_details);
    }

    if over_threshold_streak >= PENDING_UNHEALTHY_CONFIRMATION_POLLS {
        let pending = details.pending_increments.unwrap_or(0);
        let err = format!(
            "counter trailing expected by {pending} (> {threshold}) for {over_threshold_streak} \
             consecutive polls",
        );
        return ServiceStatus::unhealthy("Network Transactions", err, service_details);
    }

    if details.current_value.is_some() {
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
            storage_request: None,
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

    let account = Account::new(account_id, vault, storage, code, Felt::new_unchecked(nonce), None)
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

/// Create the increment procedure script.
pub(crate) fn create_increment_script() -> Result<NoteScript> {
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
        Felt::new_unchecked(rng.random()),
        Felt::new_unchecked(rng.random()),
        Felt::new_unchecked(rng.random()),
        Felt::new_unchecked(rng.random()),
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
    } else {
        Ok(status.chain_tip)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::counter::{PENDING_UNHEALTHY_CONFIRMATION_POLLS, build_tracking_status};
    use crate::status::{CounterTrackingDetails, Status};

    const THRESHOLD: u64 = 5;

    fn details(current: u64, expected: u64) -> CounterTrackingDetails {
        let pending = expected.saturating_sub(current);
        CounterTrackingDetails {
            current_value: Some(current),
            expected_value: Some(expected),
            last_updated: Some(1),
            pending_increments: Some(pending),
        }
    }

    #[test]
    fn healthy_when_pending_under_threshold() {
        // When pending sits at or below the threshold, `update_over_threshold_streak` keeps the
        // streak at zero, so the card stays green regardless of how long we have been polling.
        let status = build_tracking_status(&details(100, 102), None, 0, THRESHOLD);
        assert_eq!(status.status, Status::Healthy);
        assert!(status.error.is_none());
    }

    #[test]
    fn healthy_while_streak_below_confirmation_window() {
        // Pending is over threshold this tick (8 > 5) but the streak hasn't crossed the window yet,
        // so we keep the card green until we've confirmed sustained backlog.
        let streak = PENDING_UNHEALTHY_CONFIRMATION_POLLS - 1;
        let status = build_tracking_status(&details(10, 18), None, streak, THRESHOLD);
        assert_eq!(status.status, Status::Healthy);
    }

    #[test]
    fn unhealthy_when_streak_reaches_window() {
        let status = build_tracking_status(
            &details(10, 20),
            None,
            PENDING_UNHEALTHY_CONFIRMATION_POLLS,
            THRESHOLD,
        );
        assert_eq!(status.status, Status::Unhealthy);
        let err = status.error.expect("error message should be set");
        assert!(err.contains("10"), "should mention pending count, got: {err}");
        assert!(err.contains('5'), "should mention threshold, got: {err}");
    }

    #[test]
    fn rpc_error_wins_over_streak() {
        let status = build_tracking_status(
            &details(10, 20),
            Some("fetch counter value failed".to_string()),
            PENDING_UNHEALTHY_CONFIRMATION_POLLS,
            THRESHOLD,
        );
        assert_eq!(status.status, Status::Unhealthy);
        let err = status.error.expect("error message should be set");
        assert!(err.contains("fetch counter value failed"));
    }

    #[test]
    fn unknown_when_no_observation_yet() {
        let blank = CounterTrackingDetails {
            current_value: None,
            expected_value: None,
            last_updated: None,
            pending_increments: None,
        };
        let status = build_tracking_status(&blank, None, 0, THRESHOLD);
        assert_eq!(status.status, Status::Unknown);
    }
}
