//! The funding worker.
//!
//! One task owns the funding account and submits one transaction at a time.
//! It periodically loads pending requests from SQLite, refreshes the wallet, and retries pending work.

use std::collections::VecDeque;
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_proto::clients::UsdcxFaucet;
use miden_node_tracing::{ErrorSpanExt, Span, info_v2, instrument_v2, miden_span_record, warn_v2};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::Nullifier;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{PartialBlockchain, TransactionId};
use miden_protocol::utils::serde::Serializable;

use crate::account::FundingWallet;
use crate::db::{FundingDatabase, TransactionAttempt};
use crate::node::{RpcNodeClient, SubmissionOutcome, TransactionStatus};
use crate::prover::Prover;
use crate::status::StatusSnapshot;
use crate::tx::{self, ExecutionInputs};

#[cfg(test)]
mod recovery_tests;

// CONSTANTS
// ================================================================================================

/// Upper bound on the fee formula's cycle multiplier: the kernel charges `verification_base_fee *
/// (ilog2(total_cycles) + 1)` with cycles capped at `2^29`.
pub const MAX_FEE_VERIFICATION_CYCLES: u64 = 30;

// CONFIGURATION
// ================================================================================================

/// The limits the worker applies to every transaction.
#[derive(Debug, Clone, Copy)]
pub struct WorkerConfig {
    /// The largest number of notes one transaction creates.
    pub max_notes_per_tx: NonZeroUsize,
    /// The largest number of deposits one transaction consumes.
    pub max_deposits_per_tx: NonZeroUsize,
    /// How many blocks after its reference block a funding transaction expires.
    pub expiration_delta: NonZeroU16,
    /// The delay between funding attempts or checks of a submitted transaction.
    pub poll_interval: Duration,
}

// FUNDER
// ================================================================================================

/// What the worker needs besides its node and prover.
pub struct FunderSetup {
    /// Durable pending requests and delivery records.
    pub database: Arc<FundingDatabase>,
    /// The funding wallet and its deposit scan cursor.
    pub wallet: FundingWallet,
    /// The native asset, which pays the fee.
    pub fee_asset_id: AssetId,
    /// The loaded fee faucet, synchronized to each transaction's reference block.
    pub fee_faucet: UsdcxFaucet,
    /// The protocol configuration of the chain, which names the fee asset.
    pub protocol_config: ProtocolConfig,
    /// The limits applied to every transaction.
    pub config: WorkerConfig,
    /// Where the worker publishes the funding account's balance.
    pub status: StatusSnapshot,
}

/// The funding account and chain state at one reference block.
struct ChainState {
    reference_header: BlockHeader,
    blockchain: PartialBlockchain,
}

/// Combines stored deposits with queued funding requests.
pub struct Funder {
    node: RpcNodeClient,
    prover: Prover,
    setup: FunderSetup,
    rng: RandomCoin,
}

impl Funder {
    /// Creates a worker for the given funding account.
    ///
    /// The wallet's deposit cursor must not be ahead of the database's, so that every deposit the
    /// wallet has scanned past is stored.
    pub fn new(node: RpcNodeClient, prover: Prover, setup: FunderSetup) -> Self {
        Self {
            node,
            prover,
            setup,
            rng: RandomCoin::new(Word::from(rand::random::<[u32; 4]>())),
        }
    }

    /// Runs the worker until the service shuts down.
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        shutdown.run_until_cancelled(self.run_loop()).await.unwrap_or(Ok(()))
    }

    /// Processes pending requests on startup and waits between funding attempts.
    async fn run_loop(mut self) -> Result<()> {
        loop {
            // Transaction execution requires a large future.
            let _ = Box::pin(self.process_batch()).await;
            tokio::time::sleep(self.setup.config.poll_interval).await;
        }
    }

    /// Loads the oldest pending notes up to the transaction's batch limit.
    async fn pending_requests(&self) -> Result<VecDeque<UsdcxP2Id>> {
        self.setup
            .database
            .pending_requests(self.setup.config.max_notes_per_tx)
            .await?
            .into_iter()
            .map(|request| {
                UsdcxP2Id::from_note(request.note, self.setup.fee_asset_id)
                    .context("a stored funding request is not a valid native-asset note")
            })
            .collect()
    }

    /// Selects affordable notes and completes one funding attempt.
    #[instrument_v2(
        parent = None,
        name = "funding.process_batch",
        fields(
            account.id = self.account_id(),
            queued.count,
            deposit.count,
        ),
        err,
    )]
    async fn process_batch(&mut self) -> Result<()> {
        if let Some(attempt) = self.setup.database.active_attempt().await? {
            miden_span_record!(queued.count = attempt.note_ids.len());
            self.resolve_attempt(attempt, None).await?;
            return Ok(());
        }
        let queued = self.pending_requests().await?;
        miden_span_record!(queued.count = queued.len());
        let inputs = self.read_chain_state().await?;
        let reference_block = inputs.reference_header.block_num();

        let balance = self.fee_balance(self.setup.wallet.account());
        self.setup.status.update(
            balance,
            reference_block,
            inputs.reference_header.fee_parameters().verification_base_fee(),
        );

        let reserve = u64::from(inputs.reference_header.fee_parameters().verification_base_fee())
            * MAX_FEE_VERIFICATION_CYCLES;
        miden_span_record!(
            asset.balance = balance,
            asset.reserve = reserve,
            transaction.reference_block.number = reference_block
        );
        let deposit_count = self.setup.database.deposit_count().await?;
        miden_span_record!(deposit.count = deposit_count);
        let deposits = self
            .setup
            .database
            .largest_deposits(self.setup.config.max_deposits_per_tx)
            .await?;
        let Some(selection) = Selection::choose(deposits, &queued, balance, reserve) else {
            miden_span_record!(funding.selection = "unaffordable" #[nonstandard]);
            return Ok(());
        };

        miden_span_record!(funding.selection = "selected" #[nonstandard]);
        Box::pin(self.submit(inputs, selection)).await
    }

    /// Submits one transaction and resolves its outcome.
    #[instrument_v2(
        name = "funding.transaction",
        fields(
            account.id = self.account_id(),
            note.count = selection.notes.len(),
            deposit.count = selection.deposits.len(),
        ),
        err,
    )]
    async fn submit(&mut self, inputs: ChainState, selection: Selection) -> Result<()> {
        let ChainState { reference_header, blockchain } = inputs;
        let reference_block = reference_header.block_num();
        let note_ids: Vec<_> = selection.notes.iter().map(|note| note.note().id()).collect();
        miden_span_record!(note.ids = note_ids, transaction.reference_block.number = reference_block,
                           deposit.note.ids = selection.deposits.iter().map(|deposit| deposit.note().id()).collect::<Vec<_>>() #[nonstandard]);
        self.setup
            .fee_faucet
            .sync_to(&mut self.node.rpc_client(), reference_block)
            .await
            .context("failed to sync the fee faucet account")?;
        let inputs = ExecutionInputs {
            rpc_client: self.node.rpc_client(),
            funder: Arc::clone(self.setup.wallet.account()),
            secret_key: self.setup.wallet.secret_key().clone(),
            fee_faucet: self.setup.fee_faucet.clone(),
            protocol_config: self.setup.protocol_config.clone(),
            reference_header,
            blockchain,
            expiration_delta: self.setup.config.expiration_delta,
        };

        let deposits = selection.deposits.iter().map(|deposit| deposit.note().clone()).collect();
        let outputs = selection.notes.iter().map(|note| note.note().clone()).collect();
        let executed_tx = Box::pin(tx::execute(inputs, deposits, outputs, &mut self.rng))
            .await
            .context("failed to execute the funding transaction")?;
        miden_span_record!(
            transaction.id = executed_tx.id(),
            transaction.expires_at = executed_tx.expiration_block_num()
        );
        let transaction_inputs = executed_tx.tx_inputs().to_bytes();
        let transaction = Box::pin(self.prover.prove(executed_tx))
            .await
            .context("failed to prove the funding transaction")?;

        let transaction_id = transaction.id();
        let expiration_block = transaction.expiration_block_num();
        let attempt = TransactionAttempt {
            transaction_id,
            reference_block,
            expiration_block,
            deposit_nullifiers: selection.deposits.iter().map(UsdcxP2Id::nullifier).collect(),
            note_ids: selection.notes.iter().map(|note| note.note().id()).collect(),
        };
        self.setup.database.start_attempt(attempt.clone()).await?;
        let outcome = match self.node.submit(&transaction, &transaction_inputs).await {
            Ok(outcome) => outcome,
            Err(err) => {
                self.setup.database.release_attempt(transaction_id, Vec::new()).await?;
                return Err(err);
            },
        };
        miden_span_record!(funding.submission_outcome = outcome.as_str() #[nonstandard]);
        let resolution = self.resolve_attempt(attempt, Some(outcome)).await?;
        miden_span_record!(funding.outcome = resolution.as_str() #[nonstandard]);
        if resolution != Resolution::Committed {
            Span::current()
                .set_error(anyhow::anyhow!("funding transaction {}", resolution.as_str()).as_ref());
        }
        Ok(())
    }

    /// Waits until we know whether a transaction committed, expired, or was rejected.
    ///
    /// A missing `outcome` means this attempt was loaded from the database. We cannot resubmit it
    /// because we do not store the transaction payload.
    #[instrument_v2(
        name = "funding.resolve_attempt",
        fields(
            account.id = self.account_id(),
            transaction.id = attempt.transaction_id,
            transaction.reference_block.number = attempt.reference_block,
            transaction.expires_at = attempt.expiration_block,
        ),
        err,
    )]
    async fn resolve_attempt(
        &mut self,
        attempt: TransactionAttempt,
        outcome: Option<SubmissionOutcome>,
    ) -> Result<Resolution> {
        let TransactionAttempt {
            transaction_id,
            reference_block,
            expiration_block,
            deposit_nullifiers,
            note_ids,
        } = attempt;
        miden_span_record!(funding.submission_outcome = outcome.as_ref().map_or("recovered", SubmissionOutcome::as_str) #[nonstandard]);
        match outcome {
            Some(SubmissionOutcome::Accepted) => {
                info_v2!(
                    "Submitted a funding transaction",
                    transaction.id = transaction_id,
                    transaction.expires_at = expiration_block
                );
            },
            Some(SubmissionOutcome::Rejected(status)) => {
                Span::current().set_error(&status);
                // On a state conflict, discard the deposits it is blamed on and retain the payouts
                // for retry. Any other rejection retains everything.
                let state_conflict =
                    status.code() == tonic::Code::InvalidArgument && status.details() == [2];
                let discarded = if state_conflict && !deposit_nullifiers.is_empty() {
                    match self.conflicting_deposits(&deposit_nullifiers).await {
                        Ok(discarded) => discarded,
                        Err(err) => {
                            self.setup.database.release_attempt(transaction_id, Vec::new()).await?;
                            return Err(err.context(
                                "failed to identify the deposits of a conflicting transaction",
                            ));
                        },
                    }
                } else {
                    Vec::new()
                };
                let discarded_count = discarded.len();
                self.setup.database.release_attempt(transaction_id, discarded).await?;
                if discarded_count > 0 {
                    warn_v2!(
                        &status,
                        "Discarded deposits rejected by the node",
                        transaction.id = transaction_id,
                        deposit.count = discarded_count
                    );
                    miden_span_record!(funding.outcome = "deposit_discarded" #[nonstandard]);
                    return Ok(Resolution::DepositDiscarded);
                }
                miden_span_record!(funding.outcome = "rejected" #[nonstandard]);
                return Err(status).context("the node rejected the funding transaction");
            },
            Some(SubmissionOutcome::Unknown(err)) => {
                warn_v2!(
                    &err,
                    "The submission outcome is unknown; waiting for commitment or expiration",
                    transaction.id = transaction_id,
                    transaction.expires_at = expiration_block
                );
            },
            None => {
                info_v2!(
                    "Recovering an unresolved funding transaction",
                    transaction.id = transaction_id,
                    transaction.expires_at = expiration_block
                );
            },
        }

        let mut polls = 0_usize;
        let mut errors = 0_usize;
        let resolution = loop {
            polls += 1;
            match self
                .node
                .transaction_status(
                    self.account_id(),
                    transaction_id,
                    reference_block,
                    expiration_block,
                )
                .await
            {
                Ok(TransactionStatus::Committed(block_num)) => {
                    // Keep the known commitment while retrying the audit write, so a database
                    // failure cannot cause this batch to be submitted again.
                    while let Err(err) = self
                        .setup
                        .database
                        .record_delivery(note_ids.clone(), transaction_id, block_num)
                        .await
                    {
                        record_poll_failure(
                            &err.context("failed to persist confirmed funding delivery"),
                            transaction_id,
                        );
                        tokio::time::sleep(self.setup.config.poll_interval).await;
                    }
                    info_v2!("A funding transaction committed", transaction.id = transaction_id);
                    miden_span_record!(funding.outcome = "committed" #[nonstandard]);
                    break Resolution::Committed;
                },
                Ok(TransactionStatus::Expired) => {
                    // Retain the deposits for retry because expiration does not spend them.
                    self.setup.database.release_attempt(transaction_id, Vec::new()).await?;
                    warn_v2!(
                        "A funding transaction expired; its notes remain queued",
                        transaction.id = transaction_id,
                        transaction.expires_at = expiration_block
                    );
                    miden_span_record!(funding.outcome = "expired" #[nonstandard]);
                    Span::current()
                        .set_error(anyhow::anyhow!("funding transaction expired").as_ref());
                    break Resolution::Expired;
                },
                Ok(TransactionStatus::Pending) => {},
                Err(err) => {
                    errors += 1;
                    record_poll_failure(&err, transaction_id);
                },
            }
            tokio::time::sleep(self.setup.config.poll_interval).await;
        };
        miden_span_record!(poll.count = polls, poll.error.count = errors);
        Ok(resolution)
    }

    /// Synchronizes the funding wallet to the current reference block, stores the deposits found
    /// since the last sync, and returns the chain state.
    ///
    /// Storing before transaction selection ensures that every deposit the worker selects is in the
    /// database.
    #[instrument_v2(name = "funding.read_chain_state", err)]
    async fn read_chain_state(&mut self) -> Result<ChainState> {
        let (reference_header, blockchain) =
            self.node.tip_chain_state().await.context("failed to read the chain state")?;
        let reference_block = reference_header.block_num();

        let update = self
            .setup
            .wallet
            .sync_to(&mut self.node.rpc_client(), reference_block)
            .await
            .context("failed to sync the funding wallet")?;
        let scan = self
            .setup
            .wallet
            .apply(update)
            .context("failed to apply the funding wallet update")?;

        // The cursor advances only after the scan is stored, so a failed write is retried by
        // rescanning the same blocks on the next poll.
        let next_sync = scan.next_sync;
        self.setup
            .database
            .record_deposit_scan(next_sync, scan.deposits)
            .await
            .context("failed to store the deposit scan")?;
        self.setup.wallet.complete_deposit_scan(next_sync);

        Ok(ChainState { reference_header, blockchain })
    }

    /// Returns the deposits a state-conflict rejection is blamed on.
    ///
    /// A deposit whose nullifier is on chain is spent, so every such deposit is blamed. When none
    /// is, a lone deposit is still blamed: with one account writer and service-controlled outputs,
    /// it is the only input that can conflict. Several unspent deposits are all kept, because the
    /// conflict cannot be attributed to one of them; a conflict with a transaction still in the
    /// mempool is found once that transaction commits.
    async fn conflicting_deposits(&self, nullifiers: &[Nullifier]) -> Result<Vec<Nullifier>> {
        let tip = self.node.committed_tip().await?;
        let spent =
            FundingWallet::spent_deposits(&mut self.node.rpc_client(), nullifiers, tip).await?;
        if spent.is_empty() && nullifiers.len() == 1 {
            return Ok(nullifiers.to_vec());
        }
        Ok(nullifiers
            .iter()
            .copied()
            .filter(|nullifier| spent.contains(nullifier))
            .collect())
    }

    /// The funding account's balance of the native asset.
    fn fee_balance(&self, funder: &Account) -> u64 {
        funder
            .vault()
            .get_balance(self.setup.fee_asset_id)
            .map_or(0, |amount| amount.as_u64())
    }

    fn account_id(&self) -> AccountId {
        self.setup.wallet.account_id()
    }
}

/// Records a failed confirmation check or database write without changing the transaction's outcome.
///
/// Each failure has a separate span so repeated exceptions cannot exhaust the resolution span's
/// attribute budget.
#[instrument_v2(
    name = "funding.poll_failure",
    fields(transaction.id = transaction_id),
)]
fn record_poll_failure(err: &anyhow::Error, transaction_id: TransactionId) {
    Span::current().set_error(err.as_ref());
    warn_v2!(
        err,
        "Failed to resolve the funding transaction; retrying",
        transaction.id = transaction_id
    );
}

// RESOLUTION
// ================================================================================================

/// The terminal result of a submitted transaction or a handled deposit rejection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Resolution {
    Committed,
    Expired,
    DepositDiscarded,
}

impl Resolution {
    fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Expired => "expired",
            Self::DepositDiscarded => "deposit_discarded",
        }
    }
}

// SELECTION
// ================================================================================================

/// The deposits and the funding notes of one transaction.
#[derive(Debug, PartialEq)]
struct Selection {
    deposits: Vec<UsdcxP2Id>,
    notes: Vec<UsdcxP2Id>,
}

impl Selection {
    /// Consumes every one of `deposits` and admits the queued notes they and the account balance
    /// can fund.
    ///
    /// Consuming several deposits in one transaction shares a single fee between them, so deposits
    /// too small to be worth a transaction on their own are collected together.
    fn choose(
        deposits: Vec<UsdcxP2Id>,
        queued: &VecDeque<UsdcxP2Id>,
        balance: u64,
        reserve: u64,
    ) -> Option<Self> {
        let collected = deposits.iter().map(UsdcxP2Id::amount).fold(0, u64::saturating_add);
        let note_count =
            admit(queued.iter().map(UsdcxP2Id::amount), balance.saturating_add(collected), reserve);
        if note_count == 0 && collected <= reserve {
            return None;
        }

        Some(Self {
            deposits,
            notes: queued.iter().take(note_count).cloned().collect(),
        })
    }
}

// ADMISSION
// ================================================================================================

/// Returns how many of `amounts` the funding account can pay for, in order.
///
/// The transaction pays its own fee out of the same vault, so `reserve` is held back. Admission
/// stops at the first note which does not fit: a later, smaller note is not admitted ahead of it,
/// which keeps the queue first-come-first-served and stops a stream of small notes from starving a
/// large one.
fn admit(amounts: impl IntoIterator<Item = u64>, balance: u64, reserve: u64) -> usize {
    let mut spendable = balance.saturating_sub(reserve);
    let mut admitted = 0;

    for amount in amounts {
        // A zero amount is rejected before a note is built, so every amount here is positive and
        // the balance strictly decreases.
        match spendable.checked_sub(amount) {
            Some(remaining) => spendable = remaining,
            None => break,
        }
        admitted += 1;
    }

    admitted
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::note::NoteType;
    use miden_standards::note::P2idNote;

    use super::*;

    const RESERVE: u64 = 15_000;

    /// The faucet which issues the native asset in these tests.
    fn fee_faucet_id() -> AccountId {
        FungibleAsset::mock_issuer()
    }

    /// The native asset in these tests.
    fn fee_asset_id() -> AssetId {
        AssetId::new_fungible(fee_faucet_id())
    }

    /// Builds a public P2ID note which holds `amount` of the native asset.
    fn note(amount: u64, serial: u32) -> UsdcxP2Id {
        let faucet = fee_faucet_id();

        let note = P2idNote::builder()
            .sender(faucet)
            .target(faucet)
            .asset(FungibleAsset::new(faucet, amount).expect("valid asset"))
            .note_type(NoteType::Public)
            .serial_number(Word::from([serial; 4]))
            .build()
            .expect("the note should build")
            .into();
        UsdcxP2Id::from_note(note, fee_asset_id()).unwrap()
    }

    #[test]
    fn deposits_without_payouts_must_be_worth_more_than_their_fee() {
        let deposits = vec![note(RESERVE / 2, 1), note(RESERVE / 2, 2)];
        assert!(Selection::choose(deposits, &VecDeque::new(), 0, RESERVE).is_none());
    }

    #[test]
    fn small_deposits_are_consumed_together_once_they_outweigh_the_fee() {
        let deposits = vec![note(RESERVE / 2, 1), note(RESERVE / 2, 2), note(1, 3)];
        assert_eq!(
            Selection::choose(deposits.clone(), &VecDeque::new(), 0, RESERVE),
            Some(Selection { deposits, notes: vec![] })
        );
    }

    #[test]
    fn deposits_together_fund_payouts_in_the_same_transaction() {
        let deposits = vec![note(RESERVE, 1), note(1_000, 2), note(1_000, 3)];
        let payouts = [note(1_500, 4), note(500, 5)];
        let queued = VecDeque::from([payouts[0].clone(), payouts[1].clone(), note(1, 6)]);
        assert_eq!(
            Selection::choose(deposits.clone(), &queued, 0, RESERVE),
            Some(Selection { deposits, notes: payouts.to_vec() })
        );
    }

    #[test]
    fn payouts_can_proceed_without_deposits() {
        let payout = note(1_000, 2);
        let queued = VecDeque::from([payout.clone(), note(1, 3)]);
        assert_eq!(
            Selection::choose(vec![], &queued, RESERVE + 1_000, RESERVE),
            Some(Selection { deposits: vec![], notes: vec![payout] })
        );
        assert_eq!(queued.len(), 2);
    }

    #[test]
    fn a_small_deposit_can_fund_payouts_in_the_same_transaction() {
        let deposit = note(1_000, 1);
        let payout = note(1_000, 2);
        let queued = VecDeque::from([payout.clone()]);
        assert_eq!(
            Selection::choose(vec![deposit.clone()], &queued, RESERVE, RESERVE),
            Some(Selection {
                deposits: vec![deposit],
                notes: vec![payout]
            })
        );
    }

    #[test]
    fn admission_holds_back_the_fee_and_preserves_request_order() {
        assert_eq!(admit([100], 100 + RESERVE, RESERVE), 1);
        assert_eq!(admit([100], 99 + RESERVE, RESERVE), 0);
        assert_eq!(admit([100, 100], 100 + RESERVE, RESERVE), 1);
        assert_eq!(admit([500, 5_000, 100], RESERVE + 1_000, RESERVE), 1);
    }
}
