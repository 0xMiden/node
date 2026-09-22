//! The funding worker.
//!
//! One task owns the funding account and submits one transaction at a time.
//! It holds at most one batch of requests. Other requests stay in the bounded channel.

use std::collections::{HashMap, VecDeque};
use std::num::{NonZeroU16, NonZeroUsize};
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_tracing::{info, warn};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, Nullifier};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{PartialBlockchain, TransactionId};
use miden_protocol::utils::serde::Serializable;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};

use crate::LOG_TARGET;
use crate::account::FunderKey;
use crate::deposit::{DepositScanner, native_amount};
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
    /// How many blocks after its reference block a funding transaction expires.
    pub expiration_delta: NonZeroU16,
    /// How often the worker processes pending notes or checks a submitted transaction.
    pub tick_interval: Duration,
    /// How long the worker waits between two scans for deposits.
    pub deposit_scan_interval: Duration,
}

// FUNDER
// ================================================================================================

/// What the worker needs besides its node and prover.
pub struct FunderSetup {
    /// The funding account's ID and signing key.
    pub key: FunderKey,
    /// The faucet which issues the native asset.
    pub fee_faucet_id: AccountId,
    /// The chain's verification base fee. Zero on a chain which does not charge fees.
    pub verification_base_fee: u32,
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
    funder: Account,
}

/// Combines at most one deposit with queued funding requests.
pub struct Funder {
    node: RpcNodeClient,
    prover: Prover,
    setup: FunderSetup,
    rng: RandomCoin,
    account_checked: bool,
    /// The active batch contains at most `max_notes_per_tx` requests.
    queued: VecDeque<Note>,
    /// The deposit pool contains one note per nullifier.
    deposits: HashMap<Nullifier, Note>,
}

impl Funder {
    /// Creates a worker for the given funding account.
    pub fn new(node: RpcNodeClient, prover: Prover, setup: FunderSetup) -> Self {
        Self {
            node,
            prover,
            setup,
            rng: RandomCoin::new(Word::from(rand::random::<[u32; 4]>())),
            account_checked: false,
            queued: VecDeque::new(),
            deposits: HashMap::new(),
        }
    }

    /// Runs the worker until the request channel closes or the service shuts down.
    pub async fn run(
        self,
        requests: mpsc::Receiver<Note>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        shutdown.run_until_cancelled(self.run_loop(requests)).await.unwrap_or(Ok(()))
    }

    /// Discovers deposits and completes one transaction at a time.
    async fn run_loop(mut self, mut requests: mpsc::Receiver<Note>) -> Result<()> {
        let tip = self
            .node
            .committed_tip()
            .await
            .context("failed to read the startup chain tip")?;
        let mut scanner = DepositScanner::new(self.account_id(), self.setup.fee_faucet_id);
        while let Err(err) = self.sync_initial_deposits(&mut scanner, tip).await {
            warn!(&err, target: LOG_TARGET, "Failed to discover historical deposits; retrying");
            tokio::time::sleep(self.setup.config.tick_interval).await;
        }
        let mut next_scan = Instant::now();
        let mut tick = tokio::time::interval(self.setup.config.tick_interval);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tick.tick().await;

            if Instant::now() >= next_scan {
                let scan = async {
                    let tip = self.node.committed_tip().await?;
                    self.discover_deposits(&mut scanner, tip).await
                }
                .await;
                if let Err(err) = scan {
                    warn!(&err, target: LOG_TARGET, "Failed to scan for deposits");
                }
                next_scan = Instant::now() + self.setup.config.deposit_scan_interval;
            }

            while self.queued.len() < self.setup.config.max_notes_per_tx.get() {
                match requests.try_recv() {
                    Ok(note) => self.queued.push_back(note),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        if self.queued.is_empty() {
                            return Ok(());
                        }
                        break;
                    },
                }
            }

            // Transaction execution requires a large future.
            if let Err(err) = Box::pin(self.process_pending_notes()).await {
                warn!(&err, target: LOG_TARGET, "Failed to process pending notes");
            }
        }
    }

    /// Recovers unspent deposits through the startup chain tip.
    async fn sync_initial_deposits(
        &mut self,
        scanner: &mut DepositScanner,
        tip: BlockNumber,
    ) -> Result<()> {
        self.discover_deposits(scanner, tip).await?;
        let nullifiers: Vec<_> = self.deposits.keys().copied().collect();
        for nullifier in self.node.spent_nullifiers(&nullifiers, tip).await? {
            self.deposits.remove(&nullifier);
        }
        Ok(())
    }

    /// Adds every page of deposits through a fixed chain tip.
    async fn discover_deposits(
        &mut self,
        scanner: &mut DepositScanner,
        tip: BlockNumber,
    ) -> Result<()> {
        while !scanner.is_caught_up(tip) {
            let found = scanner.scan(&self.node, tip).await?;
            self.deposits.extend(found.into_iter().map(|note| (note.nullifier(), note)));
        }
        Ok(())
    }

    /// Prepares one transaction and waits for commitment or expiration.
    async fn process_pending_notes(&mut self) -> Result<()> {
        if self.queued.is_empty() && self.deposits.is_empty() {
            return Ok(());
        }

        let inputs = self.read_chain_state().await?;
        let reference_block = inputs.reference_header.block_num();
        self.check_account_code(&inputs.funder)?;

        let balance = self.fee_balance(&inputs.funder);
        self.setup.status.update(
            balance,
            reference_block,
            inputs.reference_header.fee_parameters().verification_base_fee(),
        );

        let reserve = self.fee_reserve();
        let Some(selection) = Selection::choose(
            &self.deposits,
            &self.queued,
            balance,
            self.setup.fee_faucet_id,
            reserve,
        ) else {
            return Ok(());
        };

        Box::pin(self.submit(inputs, selection)).await
    }

    /// Submits one transaction and resolves its outcome.
    async fn submit(&mut self, inputs: ChainState, selection: Selection) -> Result<()> {
        let ChainState { reference_header, blockchain, funder } = inputs;
        let reference_block = reference_header.block_num();
        let fee_faucet = self
            .node
            .public_account(self.setup.fee_faucet_id, reference_header.block_num())
            .await
            .context("failed to read the fee faucet account")?;
        let inputs = ExecutionInputs {
            funder,
            secret_key: self.setup.key.secret_key().clone(),
            fee_faucet,
            protocol_config: self.setup.protocol_config.clone(),
            reference_header,
            blockchain,
            expiration_delta: self.setup.config.expiration_delta,
        };

        let deposits = selection.deposit.iter().cloned().collect();
        let executed_tx =
            Box::pin(tx::execute(inputs, deposits, selection.notes.clone(), &mut self.rng))
                .await
                .context("failed to execute the funding transaction")?;
        let transaction_inputs = executed_tx.tx_inputs().to_bytes();
        let transaction = self
            .prover
            .prove(executed_tx)
            .await
            .context("failed to prove the funding transaction")?;

        let transaction_id = transaction.id();
        let expiration_block = transaction.expiration_block_num();
        let outcome = self.node.submit(&transaction, &transaction_inputs).await?;
        self.resolve_submission(
            outcome,
            transaction_id,
            reference_block,
            expiration_block,
            selection,
        )
        .await
    }

    /// Handles rejections immediately. Resolves accepted and uncertain submissions on chain.
    async fn resolve_submission(
        &mut self,
        outcome: SubmissionOutcome,
        transaction_id: TransactionId,
        reference_block: BlockNumber,
        expiration_block: BlockNumber,
        selection: Selection,
    ) -> Result<()> {
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
                // With one writer and controlled outputs, a state conflict identifies the single
                // selected deposit as invalid. Keep the payouts for the next attempt.
                if status.code() == tonic::Code::InvalidArgument
                    && status.details() == [2]
                    && let Some(note) = &selection.deposit
                {
                    self.deposits.remove(&note.nullifier());
                    warn!(
                        &status,
                        target: LOG_TARGET,
                        "Discarded a deposit rejected by the node",
                        note.id = note.id()
                    );
                    return Ok(());
                }
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

        loop {
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
                        self.deposits.remove(&note.nullifier());
                    }
                    let _ = self.queued.drain(..selection.notes.len());
                    return Ok(());
                },
                Ok(TransactionStatus::Expired) => {
                    warn!(
                        target: LOG_TARGET,
                        "A funding transaction expired; its notes remain queued",
                        transaction.id = transaction_id,
                        transaction.expires_at = expiration_block
                    );
                    return Ok(());
                },
                Ok(TransactionStatus::Pending) => {},
                Err(err) => warn!(
                    &err,
                    target: LOG_TARGET,
                    "Failed to resolve the funding transaction; retrying",
                    transaction.id = transaction_id
                ),
            }
            tokio::time::sleep(self.setup.config.tick_interval).await;
        }
    }

    /// Reads the funding account and chain state at the current reference block.
    async fn read_chain_state(&self) -> Result<ChainState> {
        let (reference_header, blockchain) =
            self.node.tip_chain_state().await.context("failed to read the chain state")?;
        let reference_block = reference_header.block_num();

        let (funder, _funder_witness) = self
            .node
            .public_account(self.account_id(), reference_block)
            .await
            .context("failed to read the funding account")?;

        Ok(ChainState { reference_header, blockchain, funder })
    }

    /// Checks the account on chain against the account file, once.
    fn check_account_code(&mut self, funder: &Account) -> Result<()> {
        if self.account_checked {
            return Ok(());
        }

        anyhow::ensure!(
            funder.code().commitment() == self.setup.key.code_commitment(),
            "the code of account {} on chain does not match the account file: is the account file \
             from another network?",
            funder.id(),
        );
        self.account_checked = true;

        Ok(())
    }

    /// The fee one transaction may cost at worst.
    fn fee_reserve(&self) -> u64 {
        u64::from(self.setup.verification_base_fee) * MAX_FEE_VERIFICATION_CYCLES
    }

    /// The funding account's balance of the native asset.
    fn fee_balance(&self, funder: &Account) -> u64 {
        funder
            .vault()
            .get_balance(AssetId::new_fungible(self.setup.fee_faucet_id))
            .map_or(0, |amount| amount.as_u64())
    }

    fn account_id(&self) -> AccountId {
        self.setup.key.account_id()
    }
}

// SELECTION
// ================================================================================================

/// At most one deposit and the funding notes of one transaction.
#[derive(Debug, PartialEq)]
struct Selection {
    deposit: Option<Note>,
    notes: Vec<Note>,
}

impl Selection {
    /// Selects the largest deposit and the queued notes it can fund with the account balance.
    fn choose(
        deposits: &HashMap<Nullifier, Note>,
        queued: &VecDeque<Note>,
        balance: u64,
        fee_faucet_id: AccountId,
        reserve: u64,
    ) -> Option<Self> {
        let deposit = deposits.values().max_by_key(|note| native_amount(note, fee_faucet_id));
        let collected = deposit.map_or(0, |note| native_amount(note, fee_faucet_id));
        let note_count = admit(
            queued.iter().map(|note| native_amount(note, fee_faucet_id)),
            balance.saturating_add(collected),
            reserve,
        );
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

    /// Builds a public P2ID note which holds `amount` of the native asset.
    fn note(amount: u64, serial: u32) -> Note {
        let faucet = fee_faucet_id();

        P2idNote::builder()
            .sender(faucet)
            .target(faucet)
            .asset(FungibleAsset::new(faucet, amount).expect("valid asset"))
            .note_type(NoteType::Public)
            .serial_number(Word::from([serial; 4]))
            .build()
            .expect("the note should build")
            .into()
    }

    fn deposit_pool(notes: impl IntoIterator<Item = Note>) -> HashMap<Nullifier, Note> {
        notes.into_iter().map(|note| (note.nullifier(), note)).collect()
    }

    #[test]
    fn a_deposit_without_payouts_must_be_worth_more_than_its_fee() {
        let deposits = deposit_pool([note(RESERVE, 1), note(RESERVE, 2)]);
        assert!(
            Selection::choose(&deposits, &VecDeque::new(), 0, fee_faucet_id(), RESERVE).is_none()
        );
        assert_eq!(deposits.len(), 2);
    }

    #[test]
    fn combined_transaction_selects_only_the_largest_deposit() {
        let largest = note(RESERVE + 2_000, 1);
        let deposits = deposit_pool([note(RESERVE + 1_000, 2), largest.clone()]);
        let queued = VecDeque::from([note(1_000, 3)]);

        assert_eq!(
            Selection::choose(&deposits, &queued, 0, fee_faucet_id(), RESERVE),
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
            Selection::choose(&HashMap::new(), &queued, RESERVE + 1_000, fee_faucet_id(), RESERVE),
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
            Selection::choose(&deposits, &queued, RESERVE, fee_faucet_id(), RESERVE),
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
                Selection::choose(&deposits, &queued, 0, fee_faucet_id(), RESERVE),
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
