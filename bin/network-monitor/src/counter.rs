//! Counter increment task functionality.
//!
//! This module contains the implementation for periodically incrementing the counter
//! of the network account deployed at startup by creating and submitting network notes.

use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use miden_node_proto::clients::RpcClient;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{debug, error, info, miden_instrument, warn};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountCode, AccountId, AccountPatch};
use miden_protocol::asset::{AssetId, AssetVault};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::transaction::{InputNote, InputNotes, TransactionArgs, TransactionScript};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{LocalTransactionProver, TransactionExecutor};
use tokio::sync::{Mutex, watch};

use crate::config::MonitorConfig;
use crate::deploy::counter::COUNTER_SLOT_NAME;
use crate::deploy::wallet::WALLET_COUNTER_SLOT_NAME;
use crate::deploy::{
    CounterAnchor,
    DeployedMonitorAccounts,
    MonitorDataStore,
    TransactionSubmissionClient,
    create_and_deploy_accounts,
    create_genesis_aware_rpc_client,
};
use crate::funding::{FaucetClient, FeeFunder, wallet_funding_amount, wallet_topup_threshold};
use crate::service::Service;
use crate::status::{
    CounterTrackingDetails,
    IncrementDetails,
    PendingLatencyDetails,
    ServiceDetails,
    ServiceStatus,
};
use crate::{COMPONENT, LOG_TARGET, current_unix_timestamp_secs};

/// Number of consecutive increment failures before re-syncing the wallet account from the RPC.
const RESYNC_FAILURE_THRESHOLD: usize = 3;

/// Number of consecutive increment failures before regenerating accounts from scratch.
const REGENERATE_FAILURE_THRESHOLD: usize = 10;

/// Minimum time between account regeneration attempts once one has succeeded.
const REGENERATE_COOLDOWN: Duration = Duration::from_hours(1);

/// Minimum time before retrying a regeneration attempt that *failed*.
const REGENERATE_RETRY_COOLDOWN: Duration = Duration::from_mins(1);

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

/// The wallet/counter pair shared from [`IncrementService`] to [`CounterTrackingService`].
///
/// Republished whenever the increment task regenerates accounts after persistent failures, so the
/// tracker switches to the new pair without polling disk. The tracker reads `expected` from the
/// wallet's on-chain counter slot and `observed` from the counter account's slot.
#[derive(Clone)]
pub struct TrackedAccounts {
    pub wallet: Account,
    pub counter: Account,
}

// TX BUILDER
// ================================================================================================

/// Everything needed to build and submit one increment network note.
///
/// Produced by [`setup_increment_task`].
struct TxBuilder {
    wallet_account: Account,
    counter_id: AccountId,
    secret_key: SecretKey,
    increment_script: NoteScript,
    counter_anchor: Arc<CounterAnchor>,
    rng: RandomCoin,
}

// FAILURE TRACKER
// ================================================================================================

/// Tracks consecutive increment failures and gates re-sync / regeneration actions.
struct FailureTracker {
    consecutive_failures: usize,
    resynced_this_streak: bool,
    last_regeneration_attempt: Option<Instant>,
    regeneration_cooldown: Duration,
}

impl Default for FailureTracker {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            resynced_this_streak: false,
            last_regeneration_attempt: None,
            regeneration_cooldown: REGENERATE_COOLDOWN,
        }
    }
}

impl FailureTracker {
    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
    }

    fn reset(&mut self) {
        self.consecutive_failures = 0;
        self.resynced_this_streak = false;
    }

    fn should_resync(&self) -> bool {
        self.consecutive_failures >= RESYNC_FAILURE_THRESHOLD && !self.resynced_this_streak
    }

    fn mark_resynced(&mut self) {
        self.resynced_this_streak = true;
    }

    fn should_regenerate(&self) -> bool {
        self.consecutive_failures >= REGENERATE_FAILURE_THRESHOLD
            && self
                .last_regeneration_attempt
                .is_none_or(|t| t.elapsed() >= self.regeneration_cooldown)
    }

    /// Records that a regeneration attempt is starting.
    fn mark_regeneration_attempt(&mut self) {
        self.last_regeneration_attempt = Some(Instant::now());
        self.regeneration_cooldown = REGENERATE_COOLDOWN;
    }

    /// Records that the regeneration attempt failed: shorten its cooldown and re-arm the re-sync
    /// path, so the streak is not left with both recovery paths disabled.
    fn mark_regeneration_failed(&mut self) {
        self.regeneration_cooldown = REGENERATE_RETRY_COOLDOWN;
        self.resynced_this_streak = false;
    }
}

// INCREMENT SERVICE
// ================================================================================================

/// Periodically submits a network note that increments the counter account.
pub struct IncrementService {
    config: MonitorConfig,
    rpc_client: RpcClient,
    tx: TxBuilder,
    prover: LocalTransactionProver,
    failures: FailureTracker,
    details: IncrementDetails,
    latency_state: Arc<Mutex<LatencyState>>,
    /// Publishes the current wallet/counter pair to [`CounterTrackingService`]. A new value is sent
    /// whenever the increment task regenerates accounts after persistent failures, so the tracker
    /// can switch to the new account IDs without polling disk.
    accounts_sender: watch::Sender<TrackedAccounts>,
    /// Shared client for attestation verification, sealing, and transaction submission.
    submission_client: TransactionSubmissionClient,
    /// Faucet access for fee funding; `None` when no faucet is configured (zero-fee chains only).
    funding: Option<FaucetClient>,
    /// Committed faucet note to be consumed by the next increment. Cleared once consumed.
    pending_funding_note: Option<Note>,
}

impl IncrementService {
    /// Display name of the service, shared with the bootstrap seeding code in
    /// [`crate::monitor::tasks`].
    pub const NAME: &'static str = "Local Transactions";

    pub fn new(
        config: MonitorConfig,
        accounts: DeployedMonitorAccounts,
        prover: LocalTransactionProver,
        submission_client: TransactionSubmissionClient,
        accounts_sender: watch::Sender<TrackedAccounts>,
        latency_state: Arc<Mutex<LatencyState>>,
        funding: Option<FaucetClient>,
    ) -> Result<Self> {
        let rpc_client = submission_client.rpc_client();
        let pending_funding_note = accounts.wallet_funding_note;
        let (tx, details) = setup_increment_task(
            accounts.wallet,
            accounts.secret_key,
            accounts.counter.id(),
            accounts.counter_anchor,
        )?;
        Ok(Self {
            config,
            rpc_client,
            tx,
            prover,
            failures: FailureTracker::default(),
            details,
            latency_state,
            accounts_sender,
            submission_client,
            funding,
            pending_funding_note,
        })
    }

    /// Applies a successful increment: advances the local wallet by the transaction's account
    /// delta, bumps the success count, and returns the value used as the latency-measurement
    /// target.
    ///
    /// The authoritative `expected` value lives in the wallet's on-chain counter slot (read by
    /// [`CounterTrackingService`]); the returned success count is used purely as a best-effort
    /// latency target — on a fresh wallet/counter pair both start at zero and advance together.
    fn handle_increment_success(&mut self, account_patch: &AccountPatch, tx_id: String) -> u64 {
        if account_patch.is_full_state() {
            // The wallet is created in-memory and never separately deployed, so its first increment
            // doubles as the account-creation transaction. That transaction's patch carries the
            // account code and fully describes the account, so it must be converted into the
            // account rather than applied as a delta (`apply_patch` rejects full-state patches).
            self.tx.wallet_account = Account::try_from(account_patch)
                .expect("full-state patch should convert to a valid account");
        } else {
            self.tx
                .wallet_account
                .apply_patch(account_patch)
                .expect("successful tx should apply patch correctly");
        }
        // The transaction consumed the pending funding note; do not offer it again.
        self.pending_funding_note = None;
        self.details.success_count += 1;
        self.details.last_tx_id = Some(tx_id);

        self.details.success_count
    }

    /// Re-sync the wallet account from the RPC after repeated failures.
    #[miden_instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.counter.try_resync_wallet_account",
        fields(
            account.id = self.tx.wallet_account.id(),
        ),
        level = "warn",
        err,
    )]
    async fn try_resync_wallet_account(&mut self) -> Result<()> {
        let fresh_account = fetch_wallet_account(&mut self.rpc_client, self.tx.wallet_account.id())
            .await
            .inspect_err(|e| {
                error!(
                    e,
                    target: LOG_TARGET,
                    "Failed to re-sync wallet account from RPC",
                    account.id = self.tx.wallet_account.id()
                );
            })?
            .context("wallet account not found on-chain during re-sync")
            .inspect_err(|e| {
                error!(
                    e,
                    target: LOG_TARGET,
                    "Wallet account not found on-chain during re-sync",
                    account.id = self.tx.wallet_account.id()
                );
            })?;

        debug!(
            target: LOG_TARGET,
            "Wallet account re-synced from RPC",
            account.id = self.tx.wallet_account.id()
        );
        self.tx.wallet_account = fresh_account;
        // The pending note may have been consumed by a transaction whose success was missed, and
        // re-offering a spent note fails every increment. Drop it; the top-up check will request a
        // fresh one if needed.
        self.pending_funding_note = None;
        Ok(())
    }

    /// Regenerate accounts from scratch when re-sync is ineffective.
    ///
    /// Builds a fresh wallet/counter pair in memory, deploys the counter to the network, swaps
    /// the local [`TxBuilder`] state, and publishes the new counter on [`Self::counter_sender`]
    /// so the tracker switches over without polling disk.
    #[miden_instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.counter.try_regenerate_accounts",
        level = "warn",
        err,
    )]
    async fn try_regenerate_accounts(&mut self) -> Result<()> {
        let accounts = Box::pin(create_and_deploy_accounts(
            &self.submission_client,
            &self.prover,
            self.funding.as_ref(),
        ))
        .await
        .context("failed to regenerate accounts")?;

        let tracked = TrackedAccounts {
            wallet: accounts.wallet.clone(),
            counter: accounts.counter.clone(),
        };
        self.pending_funding_note = accounts.wallet_funding_note;
        let (tx, details) = setup_increment_task(
            accounts.wallet,
            accounts.secret_key,
            accounts.counter.id(),
            accounts.counter_anchor,
        )?;
        self.tx = tx;
        self.details = details;

        self.accounts_sender
            .send(tracked)
            .context("counter tracker dropped before regeneration completed")?;

        debug!(target: LOG_TARGET, "Account regeneration completed, increment task re-initialized");
        Ok(())
    }

    /// Create and submit a network note that increments the counter account.
    #[miden_instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.counter.submit_increment",
        level = "info",
        ret(level = "debug"),
        err,
    )]
    async fn submit_increment(&mut self) -> Result<(String, AccountPatch, BlockNumber)> {
        let (network_note, note_recipient) = create_network_note(
            &self.tx.wallet_account,
            self.tx.counter_id,
            self.tx.increment_script.clone(),
            &mut self.tx.rng,
        )?;

        // One transaction does two things atomically: it increments the wallet's own on-chain
        // counter slot (the authoritative `expected`) and emits the network note that increments
        // the counter account (`observed`). If the tx is reverted, neither commits.
        let script = create_increment_tx_script(&network_note)?;

        let mut tx_args = TransactionArgs::default().with_tx_script(script);
        let (auth_args, conversion_info_preimage) = fee_conversion_auth_args(
            self.tx.counter_anchor.protocol_config.fee_asset_id().faucet_id(),
            &mut self.tx.rng,
        );
        tx_args = tx_args.with_auth_args(auth_args);
        tx_args.extend_advice_map([(auth_args, conversion_info_preimage)]);
        tx_args.add_output_note_recipient(Box::new(note_recipient));

        // A pending faucet note rides along as an unauthenticated input note; its assets land
        // before the epilogue withdraws the fee.
        let input_notes = match &self.pending_funding_note {
            Some(note) => InputNotes::new(vec![InputNote::unauthenticated(note.clone())])
                .context("failed to build the funding input notes")?,
            None => InputNotes::default(),
        };

        let wallet_account = self.tx.wallet_account.clone();
        let anchor = self.tx.counter_anchor.clone();
        let secret_key = self.tx.secret_key.clone();
        let prover = self.prover.clone();
        let (proven_tx, tx_inputs, account_patch) = spawn_blocking_in_current_span(move || {
            let account_id = wallet_account.id();
            let block_num = anchor.block_header.block_num();
            let mut data_store = MonitorDataStore::new(
                anchor.block_header.clone(),
                anchor.protocol_config.clone(),
                anchor.blockchain.clone(),
            );
            data_store.add_account(wallet_account);
            data_store.add_foreign_account(anchor.counter_account.clone(), anchor.witness.clone());
            // Moving the callback-enabled fee asset loads the issuing faucet.
            if let Some((faucet_account, faucet_witness)) = &anchor.fee_faucet {
                data_store.add_foreign_account(faucet_account.clone(), faucet_witness.clone());
            }

            let authenticator =
                BasicAuthenticator::new(&[AuthSecretKey::Falcon512Poseidon2(secret_key)]);
            let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

            let executed_tx = futures::executor::block_on(executor.execute_transaction(
                account_id,
                block_num,
                input_notes,
                tx_args,
            ))
            .context("Failed to execute transaction")?;

            let tx_inputs = executed_tx.tx_inputs().to_bytes();
            // The patch captures the wallet's nonce bump and counter-slot write; the increment task
            // applies it to keep its local wallet copy in sync with chain.
            let account_patch = executed_tx.account_patch().clone();
            let proven_tx = prover.prove(executed_tx).context("failed to prove transaction")?;

            Ok::<_, anyhow::Error>((proven_tx, tx_inputs, account_patch))
        })
        .await
        .context("counter increment task failed")??;

        let block_height = self.submission_client.submit(&proven_tx, &tx_inputs).await?;

        let tx_id = proven_tx.id().to_hex();
        info!(
            target: LOG_TARGET,
            "Submitted proven transaction to RPC",
            transaction.id = tx_id.as_str()
        );

        Ok((tx_id, account_patch, block_height))
    }

    /// Tracks the wallet's fee balance and requests a faucet top-up when it runs low.
    ///
    /// No-op on zero-fee chains. A top-up failure flips the card instead of failing the
    /// increment: the wallet keeps transacting on its remaining balance.
    async fn maybe_topup_fee_funding(&mut self) {
        let verification_base_fee =
            self.tx.counter_anchor.block_header.fee_parameters().verification_base_fee();
        if verification_base_fee == 0 {
            return;
        }
        let Some(funding) = self.funding.clone() else {
            // `create_and_deploy_accounts` rejects fee-charging chains without a faucet.
            return;
        };

        let fee_faucet_id = self.tx.counter_anchor.protocol_config.fee_asset_id().faucet_id();
        let fee_asset = AssetId::new_fungible(fee_faucet_id);
        let balance = self
            .tx
            .wallet_account
            .vault()
            .get_balance(fee_asset)
            .map_or(0, |amount| amount.as_u64());
        self.details.fee_balance = Some(balance);

        if balance >= wallet_topup_threshold(verification_base_fee) {
            self.details.fee_topup_error = None;
            return;
        }
        if self.pending_funding_note.is_some() {
            // A requested note is waiting to be consumed by the next increment.
            return;
        }

        info!(
            target: LOG_TARGET,
            "Wallet fee balance is low, requesting a faucet top-up",
            account.id = self.tx.wallet_account.id(),
            asset.balance = balance
        );
        let mut funder = FeeFunder::new(funding, self.rpc_client.clone(), fee_faucet_id);
        match funder
            .fund(self.tx.wallet_account.id(), wallet_funding_amount(verification_base_fee))
            .await
        {
            Ok(note) => {
                self.pending_funding_note = Some(note);
                self.details.fee_topup_error = None;
            },
            Err(err) => {
                error!(&err, target: LOG_TARGET, "Faucet top-up failed");
                self.details.fee_topup_error = Some(format!("{err:#}"));
            },
        }
    }
}

impl Service for IncrementService {
    fn name(&self) -> &'static str {
        Self::NAME
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

        self.maybe_topup_fee_funding().await;

        match self.submit_increment().await {
            Ok((tx_id, account_patch, block_height)) => {
                self.failures.reset();
                let target_value = self.handle_increment_success(&account_patch, tx_id);
                let mut guard = self.latency_state.lock().await;
                guard.pending = Some(PendingLatencyDetails {
                    submit_height: block_height.as_u32(),
                    target_value,
                });
                guard.pending_started = Some(Instant::now());
            },
            Err(e) => {
                error!(&e, target: LOG_TARGET, "Failed to create and submit network note");
                self.details.failure_count += 1;
                self.failures.record_failure();
                last_error = Some(format!("create/submit note failed: {e}"));

                let resynced_now =
                    self.failures.should_resync() && self.try_resync_wallet_account().await.is_ok();
                if resynced_now {
                    self.failures.mark_resynced();
                }

                if !resynced_now && self.failures.should_regenerate() {
                    warn!(
                        target: LOG_TARGET,
                        "re-sync ineffective, regenerating accounts from scratch",
                        counter.failures.consecutive = self.failures.consecutive_failures
                    );
                    self.failures.mark_regeneration_attempt();
                    match self.try_regenerate_accounts().await {
                        Ok(()) => self.failures.reset(),
                        Err(regen_err) => {
                            self.failures.mark_regeneration_failed();
                            error!(&regen_err, target: LOG_TARGET, "Account regeneration failed");
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
    /// Source of the `expected` value: the wallet's on-chain counter slot.
    wallet_account: Account,
    /// Source of the `observed` value: the counter account's slot.
    counter_account: Account,
    /// Observes regenerations of the wallet/counter pair from [`IncrementService`].
    accounts_receiver: watch::Receiver<TrackedAccounts>,
    details: CounterTrackingDetails,
    latency_state: Arc<Mutex<LatencyState>>,
    /// Consecutive polls that observed `pending_increments > counter_pending_unhealthy_threshold`.
    /// Used to confirm a real backlog before flipping the card to unhealthy.
    over_threshold_streak: u32,
}

impl CounterTrackingService {
    /// Display name of the service, shared with the bootstrap seeding code in
    /// [`crate::monitor::tasks`].
    pub const NAME: &'static str = "Network Transactions";

    pub async fn new(
        config: MonitorConfig,
        accounts_receiver: watch::Receiver<TrackedAccounts>,
        latency_state: Arc<Mutex<LatencyState>>,
    ) -> Result<Self> {
        let (mut rpc_client, _) =
            create_genesis_aware_rpc_client(&config.rpc_url, config.request_timeout).await?;
        let TrackedAccounts {
            wallet: wallet_account,
            counter: counter_account,
        } = accounts_receiver.borrow().clone();

        let mut details = CounterTrackingDetails::default();
        initialize_tracking_state(&mut rpc_client, &wallet_account, &counter_account, &mut details)
            .await;

        Ok(Self {
            config,
            rpc_client,
            wallet_account,
            counter_account,
            accounts_receiver,
            details,
            latency_state,
            over_threshold_streak: 0,
        })
    }

    /// If [`IncrementService`] regenerated accounts and published a new pair, adopt it and reset
    /// tracking state.
    async fn reload_counter_account_if_changed(&mut self) {
        if !self.accounts_receiver.has_changed().unwrap_or(false) {
            return;
        }
        let reloaded = self.accounts_receiver.borrow_and_update().clone();
        if reloaded.counter.id() == self.counter_account.id()
            && reloaded.wallet.id() == self.wallet_account.id()
        {
            return;
        }

        info!(
            target: LOG_TARGET,
            "monitor accounts changed, resetting tracking state",
            counter.account.id.old = self.counter_account.id(),
            counter.account.id.new = reloaded.counter.id(),
            wallet.account.id.old = self.wallet_account.id(),
            wallet.account.id.new = reloaded.wallet.id()
        );
        self.wallet_account = reloaded.wallet;
        self.counter_account = reloaded.counter;
        self.details = CounterTrackingDetails::default();
        self.over_threshold_streak = 0;
        initialize_tracking_state(
            &mut self.rpc_client,
            &self.wallet_account,
            &self.counter_account,
            &mut self.details,
        )
        .await;
    }

    /// Poll the counter once, updating details and latency tracking state.
    ///
    /// `observed` comes from the counter account's slot; `expected` comes from the wallet's own
    /// on-chain counter slot, which is bumped atomically with each committed increment note.
    async fn poll_counter_once(&mut self) -> Option<String> {
        let mut last_error = None;
        let current_time = current_unix_timestamp_secs();

        let observed = match fetch_slot_value(
            &mut self.rpc_client,
            self.counter_account.id(),
            COUNTER_SLOT_NAME.as_str(),
        )
        .await
        {
            Ok(Some(value)) => value,
            // Counter value not available yet, but not an error.
            Ok(None) => return None,
            Err(e) => {
                error!(&e, target: LOG_TARGET, "Failed to fetch counter value");
                return Some(format!("fetch counter value failed: {e}"));
            },
        };

        self.details.current_value = Some(observed);
        self.details.last_updated = Some(current_time);

        match fetch_slot_value(
            &mut self.rpc_client,
            self.wallet_account.id(),
            WALLET_COUNTER_SLOT_NAME.as_str(),
        )
        .await
        {
            Ok(Some(expected)) => {
                update_expected_and_pending(&mut self.details, expected, observed);
            },
            // Wallet not on-chain yet (no committed increment): leave `expected` unknown.
            Ok(None) => {},
            Err(e) => {
                error!(
                    &e,
                    target: LOG_TARGET,
                    "Failed to fetch expected wallet counter value"
                );
                last_error = Some(format!("fetch expected value failed: {e}"));
            },
        }

        self.handle_latency_tracking(observed, &mut last_error).await;

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
                    target: LOG_TARGET,
                    "Latency measurement timed out",
                    counter.latency.timeout_ms =
                        self.config.counter_latency_timeout.as_millis() as u64,
                    counter.value.target = pending.target_value
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
        Self::NAME
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

/// Build the increment script and transaction state needed to produce network notes from a
/// freshly-created wallet/counter pair. The accounts and the counter's FPI anchor are passed in
/// already constructed by [`create_and_deploy_accounts`]; there is no file I/O.
fn setup_increment_task(
    wallet_account: Account,
    secret_key: SecretKey,
    counter_id: AccountId,
    counter_anchor: CounterAnchor,
) -> Result<(TxBuilder, IncrementDetails)> {
    let increment_script = create_increment_script()?;

    let tx = TxBuilder {
        wallet_account,
        counter_id,
        secret_key,
        increment_script,
        counter_anchor: Arc::new(counter_anchor),
        rng: RandomCoin::new(Word::from(rand::random::<[u32; 4]>())),
    };

    Ok((tx, IncrementDetails::default()))
}

/// Initialize tracking state by fetching the current observed (counter) and expected (wallet slot)
/// values from the node.
async fn initialize_tracking_state(
    rpc_client: &mut RpcClient,
    wallet_account: &Account,
    counter_account: &Account,
    details: &mut CounterTrackingDetails,
) {
    match fetch_slot_value(rpc_client, counter_account.id(), COUNTER_SLOT_NAME.as_str()).await {
        Ok(Some(observed)) => {
            details.current_value = Some(observed);
            details.last_updated = Some(current_unix_timestamp_secs());
            info!(
                target: LOG_TARGET,
                "Initialized counter tracking",
                counter.value.observed = observed
            );
        },
        Ok(None) => warn!(target: LOG_TARGET, "Counter account not found at init"),
        Err(e) => error!(&e, target: LOG_TARGET, "Failed to fetch initial counter value"),
    }

    match fetch_slot_value(rpc_client, wallet_account.id(), WALLET_COUNTER_SLOT_NAME.as_str()).await
    {
        Ok(Some(expected)) => details.expected_value = Some(expected),
        Ok(None) => {},
        Err(e) => {
            error!(&e, target: LOG_TARGET, "Failed to fetch initial expected wallet value");
        },
    }

    if let (Some(expected), Some(observed)) = (details.expected_value, details.current_value) {
        update_expected_and_pending(details, expected, observed);
    }
}

// STATUS BUILDERS
// ================================================================================================

/// Build a `ServiceStatus` snapshot from the current increment details and last error.
///
/// A failed top-up flips the card even while increments succeed: it only happens when the
/// balance is low, so it is the early warning.
fn build_increment_status(details: &IncrementDetails, last_error: Option<String>) -> ServiceStatus {
    let service_details = ServiceDetails::NtxIncrement(details.clone());

    if let Some(err) = last_error {
        ServiceStatus::unhealthy(IncrementService::NAME, err, service_details)
    } else if details.success_count == 0 && details.failure_count > 0 {
        ServiceStatus::unhealthy(
            IncrementService::NAME,
            format!("no successful increments ({} failures)", details.failure_count),
            service_details,
        )
    } else if let Some(topup_error) = &details.fee_topup_error {
        ServiceStatus::unhealthy(
            IncrementService::NAME,
            format!("fee balance is low and the faucet top-up failed: {topup_error}"),
            service_details,
        )
    } else {
        ServiceStatus::healthy(IncrementService::NAME, service_details)
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
        return ServiceStatus::unhealthy(CounterTrackingService::NAME, err, service_details);
    }

    if over_threshold_streak >= PENDING_UNHEALTHY_CONFIRMATION_POLLS {
        let pending = details.pending_increments.unwrap_or(0);
        let err = format!(
            "counter trailing expected by {pending} (> {threshold}) for {over_threshold_streak} \
             consecutive polls",
        );
        return ServiceStatus::unhealthy(CounterTrackingService::NAME, err, service_details);
    }

    if details.current_value.is_some() {
        ServiceStatus::healthy(CounterTrackingService::NAME, service_details)
    } else {
        ServiceStatus::unknown(CounterTrackingService::NAME, service_details)
    }
}

/// Update expected and pending counters from the latest on-chain expected (wallet slot) and
/// observed (counter) values.
fn update_expected_and_pending(
    details: &mut CounterTrackingDetails,
    expected: u64,
    observed_value: u64,
) {
    details.expected_value = Some(expected);

    if expected >= observed_value {
        details.pending_increments = Some(expected - observed_value);
    } else {
        warn!(
            target: LOG_TARGET,
            "Expected counter value is less than current value, setting pending to 0",
            counter.value.expected = expected,
            counter.value.observed = observed_value
        );
        details.pending_increments = Some(0);
    }
}

// RPC HELPERS
// ================================================================================================

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

/// Fetch the u64 value held in the named value slot of the given account from RPC.
///
/// Returns `None` if the account is not yet available on-chain. The value is stored as a `Word`,
/// with the actual u64 in the first element.
async fn fetch_slot_value(
    rpc_client: &mut RpcClient,
    account_id: AccountId,
    slot_name: &str,
) -> Result<Option<u64>> {
    let Some(storage_header) = fetch_account_storage_header(rpc_client, account_id).await? else {
        return Ok(None);
    };

    let slot = storage_header
        .slots
        .iter()
        .find(|slot| slot.slot_name == slot_name)
        .context(format!("slot '{slot_name}' not found"))?;

    let slot_value: Word = slot
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
        let dummy: miden_node_proto::generated::primitives::Word = Word::default().into();
        (Some(dummy.clone()), Some(dummy))
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
            warn!(
                &e,
                target: LOG_TARGET,
                "Failed to fetch wallet account via RPC",
                account.id = account_id
            );
            return Ok(None);
        },
    };

    let Some(details) = response.details else {
        if response.witness.is_some() {
            info!(
                target: LOG_TARGET,
                "account found on-chain but cannot reconstruct full account from RPC response",
                account.id = account_id
            );
        }
        return Ok(None);
    };

    let header = details.header.context("missing account header")?;
    let nonce: u64 = header.nonce;

    let code: AccountCode = details
        .code
        .context("server did not return account code")?
        .try_into()
        .context("failed to decode account code")?;

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

    info!(target: LOG_TARGET, "Fetched wallet account from RPC", account.id = account_id);
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

/// Build the transaction script for one increment.
///
/// The whole transaction is a single `call` into the wallet's `increment_and_create_note` account
/// procedure, which atomically (1) creates the network note targeting the counter account (the
/// `observed` value) and (2) bumps the wallet's own on-chain counter slot (the authoritative
/// `expected` value).
///
/// The note attachments (the `NetworkAccountTarget`) are added afterwards with
/// `output_note::add_attachment`, which is not account-restricted, mirroring `miden_standards`'
/// `SendNotesTransactionScript`. The `wallet_self_increment_tx` test exercises this end-to-end.
fn create_increment_tx_script(network_note: &Note) -> Result<TransactionScript> {
    let wallet_component = crate::deploy::wallet::wallet_counter_component_code()
        .context("failed to compile wallet counter component code")?;

    let partial: PartialNote = network_note.clone().into();
    let recipient = partial.recipient_digest();
    let note_type = Felt::from(partial.metadata().note_type());
    let tag = Felt::from(partial.metadata().tag());

    // The wallet's own account procedure creates the note *and* bumps the counter atomically, so
    // the whole transaction is a single `call` into the wallet component.
    // `increment_and_create_note` shares `create_note`'s stack contract: it consumes `[tag,
    // note_type, RECIPIENT, pad(10)]` and returns `[note_idx, pad(15)]`. We build the padded input
    // explicitly and reduce the trailing pads back to `[note_idx]`, otherwise the extra pads
    // survive on the overflow stack and `main` returns with the wrong depth ("stack depth must be
    // 16, but was 21").
    let increment_and_create_note = format!(
        "::{}::increment_and_create_note",
        crate::deploy::wallet::WALLET_COUNTER_COMPONENT_PATH
    );
    let mut note_section = format!(
        "
        padw padw push.0.0
        push.{recipient}
        push.{note_type}
        push.{tag}
        # => [tag, note_type, RECIPIENT, pad(10)]
        call.{increment_and_create_note}
        # => [note_idx, pad(15)]
        movdn.15 dropw dropw dropw drop drop drop
        # => [note_idx]
        "
    );
    for attachment in partial.attachments().iter() {
        let scheme = attachment.attachment_scheme().as_u16();
        let commitment = attachment.content().to_commitment();
        // `add_attachment` consumes `[attachment_scheme, ATTACHMENT_COMMITMENT, note_idx]`, so dup
        // the note index for it to consume and keep our own copy for the next attachment / drop.
        write!(
            note_section,
            "
        dup
        push.{commitment}
        push.{scheme}
        # => [attachment_scheme, ATTACHMENT_COMMITMENT, note_idx, note_idx]
        exec.::miden::protocol::output_note::add_attachment
        # => [note_idx]
        "
        )
        .expect("writing to a String cannot fail");
    }
    note_section.push_str("        drop\n");

    let script_src = format!(
        "@transaction_script
        pub proc main
{note_section}
        end"
    );

    let mut code_builder = CodeBuilder::new()
        .with_dynamically_linked_package(&wallet_component)
        .context("Failed to dynamically link wallet counter component")?;

    // The note's attachments (e.g. the network-account target) are resolved at runtime from the
    // advice map keyed by their commitment, matching `build_send_notes_script`.
    for attachment in partial.attachments().iter() {
        code_builder.add_advice_map_entry(attachment.to_commitment(), attachment.to_elements());
    }

    let tx_script = code_builder
        .compile_tx_script(script_src)
        .context("Failed to compile increment transaction script")?;

    Ok(tx_script)
}

/// Build the auth args committing to paying the transaction fee in the chain's native fee asset at
/// rate 1/1, together with the advice-map preimage `miden::standards::fee::load_conversion_info`
/// verifies against them in-VM.
fn fee_conversion_auth_args(fee_faucet_id: AccountId, rng: &mut RandomCoin) -> (Word, Vec<Felt>) {
    // The salt keeps the auth args usable as a per-transaction unique value for replay protection.
    let salt = rng.draw_word();
    commit_fee_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id), salt)
}

/// Create a network note that targets the counter account.
fn create_network_note(
    wallet_account: &Account,
    counter_account_id: AccountId,
    script: NoteScript,
    rng: &mut RandomCoin,
) -> Result<(Note, NoteRecipient)> {
    let target = NetworkAccountTarget::new(counter_account_id, NoteExecutionHint::Always)
        .context("Failed to create NetworkAccountTarget for counter account")?;
    let attachment: NoteAttachment = target.into();
    let attachments = NoteAttachments::from(attachment);

    let partial_metadata = PartialNoteMetadata::new(wallet_account.id(), NoteType::Public);

    let serial_num = rng.draw_word();

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
    use miden_protocol::Word;
    use miden_protocol::account::auth::AuthSecretKey;
    use miden_protocol::account::{Account, AccountId};
    use miden_protocol::asset::{AssetAmount, AssetId, FungibleAsset, TokenSymbol};
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::note::{Note, NoteType};
    use miden_protocol::transaction::{InputNote, InputNotes, TransactionArgs};
    use miden_standards::account::access::AccessControl;
    use miden_standards::account::faucets::{
        FungibleFaucet as FungibleFaucetComponent,
        TokenName,
        create_network_fungible_faucet,
    };
    use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
    use miden_standards::account::policies::{
        BurnPolicy,
        MintPolicy,
        TokenPolicyManager,
        TransferPolicy,
    };
    use miden_standards::note::{BurnNote, MintNote, P2idNote};
    use miden_testing::MockChain;
    use miden_tx::TransactionExecutor;
    use miden_tx::auth::BasicAuthenticator;

    use crate::counter::{
        FailureTracker,
        PENDING_UNHEALTHY_CONFIRMATION_POLLS,
        REGENERATE_FAILURE_THRESHOLD,
        RESYNC_FAILURE_THRESHOLD,
        build_tracking_status,
        create_increment_script,
        create_increment_tx_script,
        create_network_note,
        fee_conversion_auth_args,
    };
    use crate::deploy::counter::create_counter_account;
    use crate::deploy::wallet::{WALLET_COUNTER_SLOT_NAME, create_wallet_account};
    use crate::deploy::{MonitorDataStore, execute_counter_genesis_tx};
    use crate::funding::{counter_funding_amount, max_fee_per_transaction, wallet_funding_amount};
    use crate::status::{CounterTrackingDetails, Status};

    const THRESHOLD: u64 = 5;

    /// Builds the public P2ID note the faucet would mint for the given recipient.
    fn funding_note(fee_faucet_id: AccountId, target: AccountId, amount: u64) -> Note {
        P2idNote::builder()
            .sender(fee_faucet_id)
            .target(target)
            .serial_number(Word::from([42u32; 4]))
            .note_type(NoteType::Public)
            .asset(FungibleAsset::new(fee_faucet_id, amount).expect("amount is a valid asset"))
            .build()
            .expect("the funding note should build")
            .into()
    }

    /// Executes one increment transaction end to end against a chain that holds the deployed
    /// counter account.
    #[tokio::test]
    async fn increment_transaction_executes_against_the_committed_counter() -> anyhow::Result<()> {
        let fee_faucet_id = FungibleAsset::mock_issuer();
        let (wallet, secret_key) = create_wallet_account()?;
        let counter = create_counter_account(wallet.id(), fee_faucet_id, 0)?;

        // The counter reaches the chain through its own creation transaction, so the chain must
        // hold the committed (post-creation) state, exactly as `resolve_counter_anchor` requires
        // on-chain.
        let bootstrap_chain = MockChain::builder().fee_faucet_id(fee_faucet_id).build()?;
        let creation_tx = execute_counter_genesis_tx(
            &counter,
            bootstrap_chain.latest_block_header(),
            bootstrap_chain.protocol_config().clone(),
            bootstrap_chain.latest_partial_blockchain(),
            None,
            None,
        )
        .await?;
        let committed_counter = Account::try_from(creation_tx.account_patch())?;

        let mut builder = MockChain::builder().fee_faucet_id(fee_faucet_id);
        builder.add_account(committed_counter.clone())?;
        let chain = builder.build()?;

        let block_header = chain.latest_block_header();
        let witness = chain
            .account_witnesses([committed_counter.id()])
            .remove(&committed_counter.id())
            .expect("a witness was requested for the counter");
        assert_eq!(
            witness.state_commitment(),
            committed_counter.to_commitment(),
            "the chain must hold the counter in the state fed to the executor"
        );

        let increment_script = create_increment_script()?;
        let mut rng = RandomCoin::new(Word::from([11u32; 4]));
        let (network_note, note_recipient) =
            create_network_note(&wallet, committed_counter.id(), increment_script, &mut rng)?;
        let script = create_increment_tx_script(&network_note)?;

        let mut tx_args = TransactionArgs::default().with_tx_script(script);
        let (auth_args, preimage) =
            fee_conversion_auth_args(chain.protocol_config().fee_asset_id().faucet_id(), &mut rng);
        tx_args = tx_args.with_auth_args(auth_args);
        tx_args.extend_advice_map([(auth_args, preimage)]);
        tx_args.add_output_note_recipient(Box::new(note_recipient));

        let mut data_store = MonitorDataStore::new(
            block_header.clone(),
            chain.protocol_config().clone(),
            chain.latest_partial_blockchain(),
        );
        data_store.add_account(wallet.clone());
        data_store.add_foreign_account(committed_counter, witness);

        let authenticator =
            BasicAuthenticator::new(&[AuthSecretKey::Falcon512Poseidon2(secret_key)]);
        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let executed_tx = executor
            .execute_transaction(
                wallet.id(),
                block_header.block_num(),
                InputNotes::default(),
                tx_args,
            )
            .await?;

        // The wallet's own procedure emits the increment note and bumps its counter slot
        // atomically, so a successful execution must show both.
        assert_eq!(
            executed_tx.output_notes().num_notes(),
            1,
            "the increment transaction must emit exactly the network note"
        );
        let updated_wallet = Account::try_from(executed_tx.account_patch())?;
        let counter_slot = updated_wallet.storage().get_item(&WALLET_COUNTER_SLOT_NAME)?;
        assert_eq!(
            counter_slot.as_elements()[0].as_canonical_u64(),
            1,
            "the wallet's expected-value slot must be bumped by the same transaction"
        );

        Ok(())
    }

    /// Builds a network fungible faucet shaped like the genesis native faucet. Its asset triggers
    /// the kernel's asset callbacks, which `FungibleAsset::mock_issuer()` does not.
    fn genesis_style_network_faucet(operator: AccountId) -> anyhow::Result<Account> {
        let faucet_component = FungibleFaucetComponent::builder()
            .name(TokenName::new("MIDEN").expect("valid token name"))
            .symbol(TokenSymbol::new("MIDEN").expect("valid token symbol"))
            .decimals(6)
            .max_supply(AssetAmount::new(100_000_000_000_000_000).expect("valid supply"))
            .build()?;
        let policies = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::owner_only())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(TransferPolicy::allow_all())
            .active_receive_policy(TransferPolicy::allow_all())
            .build();
        let fee_policy = BasicConstantFeePolicy::new()
            .with_fees([
                (MintNote::script_root(), AssetAmount::ZERO),
                (BurnNote::script_root(), AssetAmount::ZERO),
            ])
            .into();
        let fee_policy_manager = FeePolicyManager::builder()
            .fee_faucet_id(operator)
            .active_fee_policy(fee_policy)
            .build();
        let mut faucet = create_network_fungible_faucet(
            [7u8; 32],
            faucet_component,
            AccessControl::Ownable2Step { owner: operator },
            policies,
            fee_policy_manager,
        )?;
        // Mark the faucet as deployed, the same way genesis does, so the mock chain accepts it.
        faucet.set_nonce(miden_protocol::Felt::ONE)?;
        Ok(faucet)
    }

    /// The native faucet issues a callback-enabled asset: moving it loads the issuing faucet in a
    /// foreign context. The creation transaction must fail without the provisioned faucet and
    /// succeed with it.
    #[tokio::test]
    async fn creation_with_callback_asset_requires_the_provisioned_faucet() -> anyhow::Result<()> {
        const BASE_FEE: u32 = 500;
        let (wallet, _secret_key) = create_wallet_account()?;
        let faucet = genesis_style_network_faucet(wallet.id())?;
        let fee_faucet_id = faucet.id();

        let counter = create_counter_account(wallet.id(), fee_faucet_id, BASE_FEE)?;
        let mut builder = MockChain::builder()
            .fee_faucet_id(fee_faucet_id)
            .verification_base_fee(BASE_FEE);
        builder.add_account(faucet.clone())?;
        let chain = builder.build()?;

        let note = funding_note(fee_faucet_id, counter.id(), counter_funding_amount(BASE_FEE));

        // Without the faucet provisioned the kernel cannot start the callback context.
        let err = execute_counter_genesis_tx(
            &counter,
            chain.latest_block_header(),
            chain.protocol_config().clone(),
            chain.latest_partial_blockchain(),
            Some(note.clone()),
            None,
        )
        .await
        .expect_err("moving a callback-enabled asset requires the issuing faucet");
        assert!(
            format!("{err:#}").contains("foreign account"),
            "expected a foreign-account failure, got: {err:#}"
        );

        // With the committed faucet state and witness the creation transaction succeeds.
        let committed_faucet = chain
            .committed_account(fee_faucet_id)
            .expect("the faucet is part of the chain")
            .clone();
        let witness = chain
            .account_witnesses([fee_faucet_id])
            .remove(&fee_faucet_id)
            .expect("a witness was requested for the faucet");
        let creation_tx = execute_counter_genesis_tx(
            &counter,
            chain.latest_block_header(),
            chain.protocol_config().clone(),
            chain.latest_partial_blockchain(),
            Some(note),
            Some((committed_faucet, witness)),
        )
        .await?;
        let committed_counter = Account::try_from(creation_tx.account_patch())?;
        let balance = committed_counter
            .vault()
            .get_balance(AssetId::new_fungible(fee_faucet_id))?
            .as_u64();
        assert!(
            balance > 0 && balance < counter_funding_amount(BASE_FEE),
            "the creation fee must have been paid from the funding note, got {balance}"
        );
        Ok(())
    }

    /// The full fee flow: the counter's creation transaction pays its fee from a consumed faucet
    /// note, and the wallet's increment pays its fee and the sponsorship from another one. Both
    /// vaults start empty, since input-note assets land before the epilogue withdraws the fee.
    #[tokio::test]
    async fn increment_pays_fees_from_a_consumed_funding_note() -> anyhow::Result<()> {
        const BASE_FEE: u32 = 500;
        let fee_faucet_id = FungibleAsset::mock_issuer();
        let fee_asset = AssetId::new_fungible(fee_faucet_id);
        let (wallet, secret_key) = create_wallet_account()?;
        let counter = create_counter_account(wallet.id(), fee_faucet_id, BASE_FEE)?;

        // The counter's creation transaction consumes its funding note and pays a non-zero fee.
        let bootstrap_chain = MockChain::builder()
            .fee_faucet_id(fee_faucet_id)
            .verification_base_fee(BASE_FEE)
            .build()?;
        let counter_funding =
            funding_note(fee_faucet_id, counter.id(), counter_funding_amount(BASE_FEE));
        let creation_tx = execute_counter_genesis_tx(
            &counter,
            bootstrap_chain.latest_block_header(),
            bootstrap_chain.protocol_config().clone(),
            bootstrap_chain.latest_partial_blockchain(),
            Some(counter_funding),
            None,
        )
        .await?;
        let committed_counter = Account::try_from(creation_tx.account_patch())?;
        let counter_balance = committed_counter.vault().get_balance(fee_asset)?.as_u64();
        assert!(
            counter_balance > 0 && counter_balance < counter_funding_amount(BASE_FEE),
            "the creation fee must have been paid out of the funding note, got {counter_balance}"
        );

        let mut builder = MockChain::builder()
            .fee_faucet_id(fee_faucet_id)
            .verification_base_fee(BASE_FEE);
        builder.add_account(committed_counter.clone())?;
        let chain = builder.build()?;

        let block_header = chain.latest_block_header();
        let witness = chain
            .account_witnesses([committed_counter.id()])
            .remove(&committed_counter.id())
            .expect("a witness was requested for the counter");

        let increment_script = create_increment_script()?;
        let mut rng = RandomCoin::new(Word::from([11u32; 4]));
        let (network_note, note_recipient) =
            create_network_note(&wallet, committed_counter.id(), increment_script, &mut rng)?;
        let script = create_increment_tx_script(&network_note)?;

        let mut tx_args = TransactionArgs::default().with_tx_script(script);
        let (auth_args, preimage) =
            fee_conversion_auth_args(chain.protocol_config().fee_asset_id().faucet_id(), &mut rng);
        tx_args = tx_args.with_auth_args(auth_args);
        tx_args.extend_advice_map([(auth_args, preimage)]);
        tx_args.add_output_note_recipient(Box::new(note_recipient));

        let mut data_store = MonitorDataStore::new(
            block_header.clone(),
            chain.protocol_config().clone(),
            chain.latest_partial_blockchain(),
        );
        data_store.add_account(wallet.clone());
        data_store.add_foreign_account(committed_counter, witness);

        let authenticator =
            BasicAuthenticator::new(&[AuthSecretKey::Falcon512Poseidon2(secret_key)]);
        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let funded = wallet_funding_amount(BASE_FEE);
        let wallet_funding = funding_note(fee_faucet_id, wallet.id(), funded);
        let input_notes = InputNotes::new(vec![InputNote::unauthenticated(wallet_funding)])?;

        let executed_tx = executor
            .execute_transaction(wallet.id(), block_header.block_num(), input_notes, tx_args)
            .await?;

        // Fee payment adds the sponsorship note and the public TX_FEE note.
        assert_eq!(
            executed_tx.output_notes().num_notes(),
            3,
            "expected the increment, fee-sponsorship, and tx-fee notes"
        );

        let updated_wallet = Account::try_from(executed_tx.account_patch())?;
        let balance = updated_wallet.vault().get_balance(fee_asset)?.as_u64();
        let sponsorship = max_fee_per_transaction(BASE_FEE);
        assert!(
            balance < funded - sponsorship,
            "the wallet must have paid the sponsorship and its own fee, got {balance}"
        );
        assert!(balance > 0, "the funding must cover far more than one increment");

        let counter_slot = updated_wallet.storage().get_item(&WALLET_COUNTER_SLOT_NAME)?;
        assert_eq!(
            counter_slot.as_elements()[0].as_canonical_u64(),
            1,
            "the wallet's expected-value slot must still be bumped under fees"
        );

        Ok(())
    }

    /// A failed regeneration must not park the service with both recovery paths disabled: the full
    /// cooldown only applies once an attempt has succeeded, and the re-sync path is re-armed so the
    /// streak keeps trying to recover.
    #[test]
    fn failed_regeneration_leaves_a_recovery_path_open() {
        let mut failures = FailureTracker::default();
        for _ in 0..REGENERATE_FAILURE_THRESHOLD {
            failures.record_failure();
        }
        failures.mark_resynced();
        assert!(failures.should_regenerate());

        failures.mark_regeneration_attempt();
        failures.mark_regeneration_failed();

        assert!(
            failures.should_resync(),
            "a failed regeneration must re-arm the cheaper re-sync path"
        );
        assert_eq!(
            failures.regeneration_cooldown,
            super::REGENERATE_RETRY_COOLDOWN,
            "a failed regeneration must be retried on the short cooldown, not the hourly one"
        );
    }

    /// A successful regeneration keeps the hourly cooldown: it deploys a new counter account and
    /// restarts the on-chain count, so it must not be repeated while its accounts are settling.
    #[test]
    fn successful_regeneration_keeps_the_full_cooldown() {
        let mut failures = FailureTracker::default();
        for _ in 0..REGENERATE_FAILURE_THRESHOLD {
            failures.record_failure();
        }

        failures.mark_regeneration_attempt();
        failures.reset();

        assert_eq!(failures.regeneration_cooldown, super::REGENERATE_COOLDOWN);
        assert!(!failures.should_regenerate(), "a cleared streak must not regenerate");

        for _ in 0..REGENERATE_FAILURE_THRESHOLD {
            failures.record_failure();
        }
        assert!(
            !failures.should_regenerate(),
            "a fresh failure streak must still wait out the hourly cooldown"
        );
    }

    /// Recovery must escalate: re-sync the wallet, then regenerate if failures keep coming. A
    /// re-sync that reset the counter would cap it below the regeneration threshold forever,
    /// leaving no recovery path for a counter account or FPI anchor invalidated by a chain reset.
    #[test]
    fn recovery_escalates_from_resync_to_regeneration() {
        let mut failures = FailureTracker::default();

        for _ in 0..RESYNC_FAILURE_THRESHOLD {
            failures.record_failure();
        }
        assert!(failures.should_resync(), "a re-sync should be attempted at the threshold");
        assert!(!failures.should_regenerate());

        // A re-sync that succeeded must not repeat, so the counter can climb.
        failures.mark_resynced();
        failures.record_failure();
        assert!(!failures.should_resync(), "a successful re-sync must not repeat");

        while failures.consecutive_failures < REGENERATE_FAILURE_THRESHOLD {
            failures.record_failure();
        }
        assert!(failures.should_regenerate(), "regeneration must become reachable");

        // A successful increment clears the escalation.
        failures.reset();
        assert!(!failures.should_resync());
        assert!(!failures.should_regenerate());
    }

    /// A re-sync that *fails* must be retried, since the transient RPC errors that make a re-sync
    /// fail are the same ones that make increments fail. Gating on the attempt rather than on its
    /// success would forfeit re-sync for the whole streak after one blip.
    #[test]
    fn failed_resync_is_retried_on_the_next_failure() {
        let mut failures = FailureTracker::default();

        for _ in 0..RESYNC_FAILURE_THRESHOLD {
            failures.record_failure();
        }
        assert!(failures.should_resync());

        // The re-sync attempt errored, so nothing is marked.
        failures.record_failure();
        assert!(failures.should_resync(), "a failed re-sync must be retried");

        failures.mark_resynced();
        assert!(!failures.should_resync());
    }

    /// The wallet's self-counter component, the increment note script, and the combined increment
    /// transaction script must all assemble, and the tx script must link against the wallet's
    /// `increment` procedure. This guards the hand-authored MASM (which mirrors `miden-standards`
    /// note-emission internals) against silent breakage on dependency bumps.
    #[test]
    fn increment_masm_assembles_and_links() {
        let (wallet, _secret_key) = create_wallet_account().expect("wallet account should build");
        let counter = create_counter_account(wallet.id(), FungibleAsset::mock_issuer(), 0)
            .expect("counter account should build");
        let note_script = create_increment_script().expect("note script should compile");

        let mut rng = RandomCoin::new(Word::from([7u32; 4]));
        let (network_note, _recipient) =
            create_network_note(&wallet, counter.id(), note_script, &mut rng)
                .expect("network note should build");

        create_increment_tx_script(&network_note)
            .expect("combined increment tx script should compile and link the wallet procedure");
    }

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
