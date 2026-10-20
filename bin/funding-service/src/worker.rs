//! The funding worker.
//!
//! One task owns the funding account and submits one transaction at a time.
//! It holds at most one batch of requests. Other requests stay in the bounded channel.

use std::collections::{HashMap, VecDeque};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_proto::clients::UsdcxFaucet;
use miden_node_tracing::{ErrorSpanExt, Span, info, miden_instrument, miden_span_record, warn};
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::Nullifier;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{PartialBlockchain, TransactionId};
use miden_protocol::utils::serde::Serializable;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::account::FundingWallet;
use crate::node::{RpcNodeClient, SubmissionOutcome, TransactionStatus};
use crate::prover::Prover;
use crate::status::StatusSnapshot;
use crate::tx::{self, ExecutionInputs};
use crate::{COMPONENT, LOG_TARGET};

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
    /// How many blocks after its reference block a funding transaction expires.
    pub expiration_delta: NonZeroU16,
    /// How often the worker syncs the wallet or checks a submitted transaction.
    pub poll_interval: Duration,
}

// FUNDER
// ================================================================================================

/// What the worker needs besides its node and prover.
pub struct FunderSetup {
    /// The funding wallet and its deposit scan progress.
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

/// Combines at most one deposit with queued funding requests.
pub struct Funder {
    node: RpcNodeClient,
    prover: Prover,
    setup: FunderSetup,
    rng: RandomCoin,
    /// The active batch contains at most `max_notes_per_tx` requests.
    queued: VecDeque<UsdcxP2Id>,
}

impl Funder {
    /// Creates a worker for the given funding account.
    pub fn new(node: RpcNodeClient, prover: Prover, setup: FunderSetup) -> Self {
        Self {
            node,
            prover,
            setup,
            rng: RandomCoin::new(Word::from(rand::random::<[u32; 4]>())),
            queued: VecDeque::new(),
        }
    }

    /// Runs the worker until the request channel closes or the service shuts down.
    pub async fn run(
        self,
        requests: mpsc::Receiver<UsdcxP2Id>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        shutdown.run_until_cancelled(self.run_loop(requests)).await.unwrap_or(Ok(()))
    }

    /// Discovers deposits and completes one transaction at a time.
    async fn run_loop(mut self, mut requests: mpsc::Receiver<UsdcxP2Id>) -> Result<()> {
        let mut next_attempt = Instant::now();
        let mut requests_closed = false;

        loop {
            if requests_closed && self.queued.is_empty() {
                return Ok(());
            }

            let process_batch = tokio::select! {
                // Fill the bounded batch before a ready processing deadline.
                biased;
                note = requests.recv(), if !requests_closed && self.queued.len() < self.setup.config.max_notes_per_tx.get() => {
                    match note {
                        Some(note) => self.queued.push_back(note),
                        None => requests_closed = true,
                    }
                    self.queued.len() == self.setup.config.max_notes_per_tx.get()
                },
                () = tokio::time::sleep_until(next_attempt) => true,
            };
            if !process_batch {
                continue;
            }

            // Transaction execution requires a large future.
            let _ = Box::pin(self.process_batch()).await;
            next_attempt = Instant::now() + self.setup.config.poll_interval;
        }
    }

    /// Selects affordable notes and completes one funding attempt.
    #[miden_instrument(
        parent = None,
        target = COMPONENT,
        name = "funding.process_batch",
        fields(
            account.id = self.account_id(),
            queued.count = self.queued.len(),
            deposit.count = self.setup.wallet.deposits().len(),
        ),
        err,
    )]
    async fn process_batch(&mut self) -> Result<()> {
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
        let Some(selection) =
            Selection::choose(self.setup.wallet.deposits(), &self.queued, balance, reserve)
        else {
            miden_span_record!(funding.selection = "unaffordable" #[nonstandard]);
            return Ok(());
        };

        miden_span_record!(funding.selection = "selected" #[nonstandard]);
        Box::pin(self.submit(inputs, selection)).await
    }

    /// Submits one transaction and resolves its outcome.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.transaction",
        fields(
            account.id = self.account_id(),
            note.count = selection.notes.len(),
            deposit.count = usize::from(selection.deposit.is_some()),
        ),
        err,
    )]
    async fn submit(&mut self, inputs: ChainState, selection: Selection) -> Result<()> {
        let ChainState { reference_header, blockchain } = inputs;
        let reference_block = reference_header.block_num();
        let note_ids: Vec<_> = selection.notes.iter().map(|note| note.note().id()).collect();
        miden_span_record!(note.ids = note_ids, transaction.reference_block.number = reference_block,
                           deposit.note.id = selection.deposit.as_ref().map(|deposit| deposit.note().id()) #[nonstandard]);
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

        let deposits = selection.deposit.iter().map(|deposit| deposit.note().clone()).collect();
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
        let outcome = self.node.submit(&transaction, &transaction_inputs).await?;
        miden_span_record!(funding.submission_outcome = outcome.as_str() #[nonstandard]);
        let resolution = self
            .resolve_submission(
                outcome,
                transaction_id,
                reference_block,
                expiration_block,
                selection,
            )
            .await?;
        miden_span_record!(funding.outcome = resolution.as_str() #[nonstandard]);
        if resolution != Resolution::Committed {
            Span::current()
                .set_error(anyhow::anyhow!("funding transaction {}", resolution.as_str()).as_ref());
        }
        Ok(())
    }

    /// Handles rejections immediately. Resolves accepted and uncertain submissions on chain.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.resolve_submission",
        fields(
            account.id = self.account_id(),
            transaction.id = transaction_id,
            transaction.reference_block.number = reference_block,
            transaction.expires_at = expiration_block,
        ),
        err,
    )]
    async fn resolve_submission(
        &mut self,
        outcome: SubmissionOutcome,
        transaction_id: TransactionId,
        reference_block: BlockNumber,
        expiration_block: BlockNumber,
        selection: Selection,
    ) -> Result<Resolution> {
        miden_span_record!(funding.submission_outcome = outcome.as_str() #[nonstandard]);
        match outcome {
            SubmissionOutcome::Accepted => {
                info!(
                    target: LOG_TARGET,
                    "Submitted a funding transaction",
                    transaction.id = transaction_id,
                    transaction.expires_at = expiration_block
                );
            },
            SubmissionOutcome::Rejected(status) => {
                Span::current().set_error(&status);
                // With one writer and controlled outputs, a state conflict identifies the single
                // selected deposit as invalid. Keep the payouts for the next attempt.
                if status.code() == tonic::Code::InvalidArgument
                    && status.details() == [2]
                    && let Some(note) = &selection.deposit
                {
                    self.setup.wallet.remove_deposit(note.nullifier());
                    warn!(
                        &status,
                        target: LOG_TARGET,
                        "Discarded a deposit rejected by the node",
                        note.id = note.note().id()
                    );
                    miden_span_record!(funding.outcome = "deposit_discarded" #[nonstandard]);
                    return Ok(Resolution::DepositDiscarded);
                }
                miden_span_record!(funding.outcome = "rejected" #[nonstandard]);
                return Err(status).context("the node rejected the funding transaction");
            },
            SubmissionOutcome::Unknown(err) => {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "The submission outcome is unknown; waiting for commitment or expiration",
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
                Ok(TransactionStatus::Committed) => {
                    info!(target: LOG_TARGET, "A funding transaction committed", transaction.id = transaction_id);
                    if let Some(note) = selection.deposit {
                        self.setup.wallet.remove_deposit(note.nullifier());
                    }
                    let _ = self.queued.drain(..selection.notes.len());
                    miden_span_record!(funding.outcome = "committed" #[nonstandard]);
                    break Resolution::Committed;
                },
                Ok(TransactionStatus::Expired) => {
                    warn!(
                        target: LOG_TARGET,
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

    /// Reads the funding account and chain state at the current reference block.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.read_chain_state",
        err,
    )]
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
        self.setup
            .wallet
            .apply(update)
            .context("failed to apply the funding wallet update")?;

        Ok(ChainState { reference_header, blockchain })
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

/// Records a failed status poll without changing the enclosing transaction's outcome.
///
/// Each failure has a separate span so repeated exceptions cannot exhaust the resolution span's
/// attribute budget.
#[miden_instrument(
    target = COMPONENT,
    name = "funding.poll_failure",
    fields(transaction.id = transaction_id),
)]
fn record_poll_failure(err: &anyhow::Error, transaction_id: TransactionId) {
    Span::current().set_error(err.as_ref());
    warn!(
        err,
        target: LOG_TARGET,
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

/// At most one deposit and the funding notes of one transaction.
#[derive(Debug, PartialEq)]
struct Selection {
    deposit: Option<UsdcxP2Id>,
    notes: Vec<UsdcxP2Id>,
}

impl Selection {
    /// Selects the largest deposit and the queued notes it can fund with the account balance.
    fn choose(
        deposits: &HashMap<Nullifier, UsdcxP2Id>,
        queued: &VecDeque<UsdcxP2Id>,
        balance: u64,
        reserve: u64,
    ) -> Option<Self> {
        let deposit = deposits.values().max_by_key(|deposit| deposit.amount());
        let collected = deposit.map_or(0, UsdcxP2Id::amount);
        let note_count =
            admit(queued.iter().map(UsdcxP2Id::amount), balance.saturating_add(collected), reserve);
        if note_count == 0 && collected <= reserve {
            return None;
        }

        Some(Self {
            deposit: deposit.cloned(),
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

    fn deposit_pool(notes: impl IntoIterator<Item = UsdcxP2Id>) -> HashMap<Nullifier, UsdcxP2Id> {
        notes.into_iter().map(|note| (note.nullifier(), note)).collect()
    }

    #[test]
    fn a_deposit_without_payouts_must_be_worth_more_than_its_fee() {
        let deposits = deposit_pool([note(RESERVE, 1), note(RESERVE, 2)]);
        assert!(Selection::choose(&deposits, &VecDeque::new(), 0, RESERVE).is_none());
        assert_eq!(deposits.len(), 2);
    }

    #[test]
    fn combined_transaction_selects_only_the_largest_deposit() {
        let largest = note(RESERVE + 2_000, 1);
        let deposits = deposit_pool([note(RESERVE + 1_000, 2), largest.clone()]);
        let queued = VecDeque::from([note(1_000, 3)]);

        assert_eq!(
            Selection::choose(&deposits, &queued, 0, RESERVE),
            Some(Selection {
                deposit: Some(largest),
                notes: queued.iter().cloned().collect()
            })
        );
        assert_eq!(deposits.len(), 2);
        assert_eq!(queued.len(), 1);
    }

    #[test]
    fn payouts_can_proceed_without_deposits() {
        let payout = note(1_000, 2);
        let queued = VecDeque::from([payout.clone(), note(1, 3)]);
        assert_eq!(
            Selection::choose(&HashMap::new(), &queued, RESERVE + 1_000, RESERVE),
            Some(Selection { deposit: None, notes: vec![payout] })
        );
        assert_eq!(queued.len(), 2);
    }

    #[test]
    fn a_small_deposit_can_fund_payouts_in_the_same_transaction() {
        let deposit = note(1_000, 1);
        let payout = note(1_000, 2);
        let deposits = deposit_pool([deposit.clone()]);
        let queued = VecDeque::from([payout.clone()]);
        assert_eq!(
            Selection::choose(&deposits, &queued, RESERVE, RESERVE),
            Some(Selection {
                deposit: Some(deposit),
                notes: vec![payout]
            })
        );
    }

    #[test]
    fn selection_keeps_notes_available_for_retry() {
        let deposit = note(RESERVE + 1_000, 1);
        let payout = note(1_000, 2);
        let deposits = deposit_pool([deposit.clone()]);
        let queued = VecDeque::from([payout.clone()]);
        for _ in 0..2 {
            assert_eq!(
                Selection::choose(&deposits, &queued, 0, RESERVE),
                Some(Selection {
                    deposit: Some(deposit.clone()),
                    notes: vec![payout.clone()]
                })
            );
        }
        assert_eq!(deposits, deposit_pool([deposit]));
        assert_eq!(queued, VecDeque::from([payout]));
    }

    #[test]
    fn admission_holds_back_the_fee_and_preserves_request_order() {
        assert_eq!(admit([100], 100 + RESERVE, RESERVE), 1);
        assert_eq!(admit([100], 99 + RESERVE, RESERVE), 0);
        assert_eq!(admit([100, 100], 100 + RESERVE, RESERVE), 1);
        assert_eq!(admit([500, 5_000, 100], RESERVE + 1_000, RESERVE), 1);
    }
}
