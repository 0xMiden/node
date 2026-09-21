//! The funding worker.
//!
//! One task owns the funding account and submits one transaction at a time.
//! It holds at most one batch of requests. Other requests stay in the bounded channel.

use std::collections::{HashMap, VecDeque};
use std::num::{NonZeroU16, NonZeroUsize};
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_tracing::{info, warn};
use miden_node_utils::retry::{self, Retryable};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetId;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, Nullifier};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{PartialBlockchain, ProvenTransaction, TransactionId};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Word};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use crate::account::FunderKey;
use crate::deposit::{DepositScanner, native_amount};
use crate::node::{RpcNodeClient, is_transient_error};
use crate::prover::Prover;
use crate::status::StatusSnapshot;
use crate::tx::{self, ExecutionInputs};
use crate::{COMPONENT, LOG_TARGET};

// CONSTANTS
// ================================================================================================

/// How long the worker waits for more notes after the first one arrives.
const BATCH_LINGER: Duration = Duration::from_millis(250);

/// Bounds on the retries of a node request inside one cycle.
const NODE_RETRY_MIN_DELAY: Duration = Duration::from_millis(100);
const NODE_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
const NODE_RETRY_MAX_TIMES: usize = 5;

/// Upper bound on the fee formula's cycle multiplier: the kernel charges `verification_base_fee *
/// (ilog2(total_cycles) + 1)` with cycles capped at `2^29`.
pub const MAX_FEE_VERIFICATION_CYCLES: u64 = 30;

/// The largest number of deposits one transaction consumes.
const MAX_DEPOSITS_PER_TX: usize = 16;

// CONFIGURATION
// ================================================================================================

/// The limits the worker applies to every transaction.
#[derive(Debug, Clone, Copy)]
pub struct WorkerConfig {
    /// The largest number of notes one transaction creates.
    pub max_notes_per_tx: NonZeroUsize,
    /// How many blocks after its reference block a funding transaction expires.
    pub expiration_delta: NonZeroU16,
    /// How often the worker runs a cycle while it has work.
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

/// The chain state one cycle is built against, read at one reference block.
struct CycleInputs {
    reference_header: BlockHeader,
    blockchain: PartialBlockchain,
    funder: Account,
}

/// The transaction which is in flight.
struct Pending {
    transaction_id: TransactionId,
    /// The nonce of the funding account when the transaction was built. The account has one writer,
    /// so a higher nonce on chain means this transaction committed.
    nonce: Felt,
    /// The block at which the transaction expires.
    expiration_block: BlockNumber,
    /// The deposits the transaction consumes. They return to the pool if it does not commit.
    deposits: Vec<Note>,
    /// The notes the transaction creates. They return to the queue if it does not commit.
    notes: Vec<Note>,
}

/// A transaction that is ready for submission.
struct Prepared {
    transaction: ProvenTransaction,
    transaction_inputs: Vec<u8>,
    nonce: Felt,
}

/// Combines funding requests and deposits in one transaction.
pub struct Funder {
    node: RpcNodeClient,
    prover: Prover,
    setup: FunderSetup,
    rng: RandomCoin,
    account_checked: bool,
    scanner: DepositScanner,
    /// The active batch contains at most `max_notes_per_tx` requests.
    queued: VecDeque<Note>,
    /// Each nullifier can enter the deposit pool only once.
    deposits: HashMap<Nullifier, Note>,
    pending: Option<Pending>,
}

impl Funder {
    /// Creates a worker for the given funding account.
    pub fn new(node: RpcNodeClient, prover: Prover, setup: FunderSetup) -> Self {
        let scanner = DepositScanner::new(setup.key.account_id(), setup.fee_faucet_id);

        Self {
            node,
            prover,
            setup,
            rng: RandomCoin::new(Word::from(rand::random::<[u32; 4]>())),
            account_checked: false,
            scanner,
            queued: VecDeque::new(),
            deposits: HashMap::new(),
            pending: None,
        }
    }

    /// Runs the worker until the request channel closes or the service shuts down.
    pub async fn run(
        mut self,
        mut requests: mpsc::Receiver<Note>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let mut poll = tokio::time::interval(self.setup.config.tick_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut scan = tokio::time::interval(self.setup.config.deposit_scan_interval);
        scan.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = scan.tick(), if self.pending.is_none() => {
                    if let Err(err) = self.scan_deposits().await {
                        warn!(&err, target: LOG_TARGET, "Failed to scan for deposits");
                    }
                },
                _ = poll.tick(), if self.pending.is_some() || !self.queued.is_empty() => {},
                note = requests.recv(), if self.pending.is_none() && self.queued.is_empty() => {
                    let Some(note) = note else { break };
                    self.queued.push_back(note);

                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(BATCH_LINGER) => {},
                    }
                },
            };

            if self.pending.is_none() {
                while self.queued.len() < self.setup.config.max_notes_per_tx.get() {
                    match requests.try_recv() {
                        Ok(note) => self.queued.push_back(note),
                        Err(_) => break,
                    }
                }
            }

            // Transaction execution requires a large future.
            if let Err(err) = Box::pin(self.cycle()).await {
                warn!(&err, target: LOG_TARGET, "A funding cycle failed");
            }
        }

        Ok(())
    }

    /// Resolves the pending transaction or prepares one batch of work.
    async fn cycle(&mut self) -> Result<()> {
        if self.pending.is_none() && self.queued.is_empty() && self.deposits.is_empty() {
            return Ok(());
        }

        let CycleInputs { reference_header, blockchain, funder } =
            self.read_cycle_inputs().await.context("failed to read the chain state")?;
        let reference_block = reference_header.block_num();
        self.check_account_code(&funder)?;

        let balance = self.fee_balance(&funder);
        self.setup.status.update(
            balance,
            reference_block,
            reference_header.fee_parameters().verification_base_fee(),
        );

        if self.pending.is_some() {
            self.resolve_pending(&funder, reference_block);
            return Ok(());
        }

        self.remove_spent_deposits().await?;
        let reserve = self.fee_reserve();
        let Some(selection) = select(
            &mut self.deposits,
            &mut self.queued,
            balance,
            self.setup.fee_faucet_id,
            reserve,
        ) else {
            return Ok(());
        };

        let prepared =
            Box::pin(self.prepare(reference_header, blockchain, funder, &selection)).await;
        match prepared {
            Ok(prepared) => self.submit_prepared(prepared, selection).await,
            Err(err) => {
                self.restore(selection.deposits, selection.notes);
                return Err(err).context("failed to prepare the funding transaction");
            },
        }

        Ok(())
    }

    /// Keeps the transaction pending until its commitment or expiration is known.
    fn resolve_pending(&mut self, funder: &Account, reference_block: BlockNumber) {
        let Some(pending) = &self.pending else {
            return;
        };

        if funder.nonce().as_canonical_u64() > pending.nonce.as_canonical_u64() {
            info!(
                target: LOG_TARGET,
                "A funding transaction committed",
                transaction.id = pending.transaction_id,
                note.count = pending.notes.len(),
                deposit.count = pending.deposits.len()
            );
            self.pending = None;

            return;
        }

        if reference_block < pending.expiration_block {
            return;
        }

        warn!(
            target: LOG_TARGET,
            "A funding transaction expired before it committed; its notes are queued again",
            transaction.id = pending.transaction_id,
            transaction.expires_at = pending.expiration_block,
            block.number = reference_block,
            note.count = pending.notes.len(),
            deposit.count = pending.deposits.len()
        );

        let pending = self.pending.take().expect("the pending transaction was read above");
        self.restore(pending.deposits, pending.notes);
    }

    /// Adds new deposits to the pool by nullifier.
    async fn scan_deposits(&mut self) -> Result<()> {
        let found = self.scanner.scan(&self.node).await?;
        self.deposits.extend(found.into_iter().map(|note| (note.nullifier(), note)));
        Ok(())
    }

    /// Removes deposits that the chain has already spent.
    async fn remove_spent_deposits(&mut self) -> Result<()> {
        if self.deposits.is_empty() {
            return Ok(());
        }

        let nullifiers: Vec<_> = self.deposits.keys().copied().collect();
        let spent = self.node.sync_nullifiers(&nullifiers, BlockNumber::GENESIS).await?;
        self.deposits.retain(|nullifier, _| !spent.contains(nullifier));
        Ok(())
    }

    /// Returns the deposits and the notes of a transaction which did not reach the chain.
    fn restore(&mut self, deposits: Vec<Note>, notes: Vec<Note>) {
        self.deposits.extend(deposits.into_iter().map(|note| (note.nullifier(), note)));
        // The notes go back in front of everything which arrived later, which keeps the queue
        // first-come-first-served.
        for note in notes.into_iter().rev() {
            self.queued.push_front(note);
        }
    }

    /// Executes and proves one transaction without submitting it.
    async fn prepare(
        &mut self,
        reference_header: BlockHeader,
        blockchain: PartialBlockchain,
        funder: Account,
        selection: &Selection,
    ) -> Result<Prepared> {
        let nonce = funder.nonce();
        let fee_faucet = self.read_fee_faucet(reference_header.block_num()).await?;
        let inputs = ExecutionInputs {
            funder,
            secret_key: self.setup.key.secret_key().clone(),
            fee_faucet,
            protocol_config: self.setup.protocol_config.clone(),
            reference_header,
            blockchain,
            expiration_delta: self.setup.config.expiration_delta,
        };

        let executed_tx = Box::pin(tx::execute(
            inputs,
            selection.deposits.clone(),
            selection.notes.clone(),
            &mut self.rng,
        ))
        .await
        .context("failed to execute the funding transaction")?;
        let transaction_inputs = executed_tx.tx_inputs().to_bytes();
        let transaction = self
            .prover
            .prove(executed_tx)
            .await
            .context("failed to prove the funding transaction")?;

        Ok(Prepared { transaction, transaction_inputs, nonce })
    }

    /// Records the pending transaction before the submission request can reach the node.
    async fn submit_prepared(&mut self, prepared: Prepared, selection: Selection) {
        let Prepared { transaction, transaction_inputs, nonce } = prepared;
        let transaction_id = transaction.id();
        let expiration_block = transaction.expiration_block_num();
        self.pending = Some(Pending {
            transaction_id,
            nonce,
            expiration_block,
            deposits: selection.deposits,
            notes: selection.notes,
        });

        match self.node.submit(&transaction, &transaction_inputs).await {
            Ok(_) => {
                info!(
                    target: LOG_TARGET,
                    "Submitted a funding transaction",
                    transaction.id = transaction_id,
                    transaction.expires_at = expiration_block
                );
            },
            Err(err) => {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "The submission outcome is unknown; waiting for commitment or expiration",
                    transaction.id = transaction_id,
                    transaction.expires_at = expiration_block
                );
            },
        }
    }

    /// Reads the chain state every cycle needs, at a fresh reference block.
    async fn read_cycle_inputs(&self) -> Result<CycleInputs> {
        let (reference_header, blockchain) = self
            .retry_node_call(|| self.node.tip_chain_state())
            .await
            .context("failed to read the chain state")?;
        let reference_block = reference_header.block_num();

        let (funder, _funder_witness) = self
            .retry_node_call(|| self.node.public_account(self.account_id(), reference_block))
            .await
            .context("failed to read the funding account")?;

        Ok(CycleInputs { reference_header, blockchain, funder })
    }

    /// Reads the fee faucet and its account-tree witness at `reference_block`.
    ///
    /// The native asset is callback-enabled, so the kernel loads the issuing faucet in a foreign
    /// context whenever the asset moves. Every transaction the worker builds moves it.
    async fn read_fee_faucet(
        &self,
        reference_block: BlockNumber,
    ) -> Result<(Account, AccountWitness)> {
        self.retry_node_call(|| self.node.public_account(self.setup.fee_faucet_id, reference_block))
            .await
    }

    /// Retries a node request while it fails for a transient reason.
    async fn retry_node_call<T, F, Fut>(&self, call: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        (|| call())
            .retry(retry::exponential_bounded(
                NODE_RETRY_MIN_DELAY,
                NODE_RETRY_MAX_DELAY,
                NODE_RETRY_MAX_TIMES,
            ))
            .when(is_transient_error)
            .notify(|err: &anyhow::Error, delay: Duration| {
                warn!(
                    err,
                    target: COMPONENT,
                    "A node request failed; retrying after backoff",
                    retry.delay_ms = delay.as_millis() as u64
                );
            })
            .await
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

/// The deposits and the notes of one transaction.
struct Selection {
    deposits: Vec<Note>,
    notes: Vec<Note>,
}

/// Takes the largest deposits and the queued notes they can fund with the account balance.
fn select(
    deposits: &mut HashMap<Nullifier, Note>,
    queued: &mut VecDeque<Note>,
    balance: u64,
    fee_faucet_id: AccountId,
    reserve: u64,
) -> Option<Selection> {
    let mut candidates: Vec<_> = deposits.values().collect();
    candidates.sort_unstable_by_key(|note| std::cmp::Reverse(native_amount(note, fee_faucet_id)));
    candidates.truncate(MAX_DEPOSITS_PER_TX);
    let collected: u64 = candidates.iter().map(|note| native_amount(note, fee_faucet_id)).sum();
    let note_count = admit(
        queued.iter().map(|note| native_amount(note, fee_faucet_id)),
        balance.saturating_add(collected),
        reserve,
    );

    // A transaction with no payouts must collect more than it can spend on its fee.
    if note_count == 0 && collected <= reserve {
        return None;
    }

    let nullifiers: Vec<_> = candidates.into_iter().map(Note::nullifier).collect();
    Some(Selection {
        deposits: nullifiers
            .into_iter()
            .filter_map(|nullifier| deposits.remove(&nullifier))
            .collect(),
        notes: queued.drain(..note_count).collect(),
    })
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
    fn a_deposit_below_the_fee_reserve_is_not_consumed_on_its_own() {
        let mut deposits = deposit_pool([note(1, 1)]);
        let mut queued = VecDeque::new();
        assert!(select(&mut deposits, &mut queued, 0, fee_faucet_id(), RESERVE).is_none());
        assert_eq!(deposits.len(), 1);
    }

    #[test]
    fn a_deposit_above_the_fee_reserve_is_consumed_on_its_own() {
        let mut deposits = deposit_pool([note(RESERVE + 1, 2)]);
        let mut queued = VecDeque::new();
        let selection = select(&mut deposits, &mut queued, 0, fee_faucet_id(), RESERVE).unwrap();
        assert_eq!(selection.deposits.len(), 1);
        assert!(selection.notes.is_empty());
        assert!(deposits.is_empty());
    }

    #[test]
    fn a_small_deposit_pays_for_a_note_in_the_same_transaction() {
        let deposit = note(1_000, 3);
        let payout = note(1_000, 4);
        let mut deposits = deposit_pool([deposit.clone()]);
        let mut queued = VecDeque::from([payout.clone()]);

        let selection = select(&mut deposits, &mut queued, RESERVE, fee_faucet_id(), RESERVE)
            .expect("the deposit covers the payout and the balance covers the fee reserve");

        assert_eq!(selection.deposits, vec![deposit]);
        assert_eq!(selection.notes, vec![payout]);
        assert!(deposits.is_empty());
        assert!(queued.is_empty());
    }

    #[test]
    fn deposits_fund_payouts_from_an_empty_account_and_keep_one_fee_reserve() {
        let deposit = note(RESERVE + 1_000, 5);
        let payout = note(1_000, 6);
        let waiting = note(1, 7);
        let mut deposits = deposit_pool([deposit.clone()]);
        let mut queued = VecDeque::from([payout.clone(), waiting.clone()]);

        let selection = select(&mut deposits, &mut queued, 0, fee_faucet_id(), RESERVE)
            .expect("the deposit covers the first payout and one fee reserve");

        assert_eq!(selection.deposits, vec![deposit]);
        assert_eq!(selection.notes, vec![payout]);
        assert!(deposits.is_empty());
        assert_eq!(queued, VecDeque::from([waiting]));
    }

    #[test]
    fn payouts_can_proceed_without_deposits() {
        let payout = note(1_000, 8);
        let mut deposits = HashMap::new();
        let mut queued = VecDeque::from([payout.clone()]);

        assert!(select(&mut deposits, &mut queued, RESERVE, fee_faucet_id(), RESERVE).is_none());
        assert_eq!(queued, VecDeque::from([payout.clone()]));

        let selection =
            select(&mut deposits, &mut queued, RESERVE + 1_000, fee_faucet_id(), RESERVE)
                .expect("the account balance covers the payout and fee reserve");
        assert!(selection.deposits.is_empty());
        assert_eq!(selection.notes, vec![payout]);
        assert!(queued.is_empty());
    }

    #[test]
    fn admission_stops_at_the_first_note_which_does_not_fit() {
        assert_eq!(admit([500, 5_000, 100], RESERVE + 1_000, RESERVE), 1);
    }

    #[test]
    fn the_largest_deposits_are_taken_up_to_the_cap() {
        let count = u32::try_from(MAX_DEPOSITS_PER_TX).expect("the cap fits in a u32") + 2;
        let mut deposits =
            deposit_pool((0..count).map(|index| note(u64::from(index) + RESERVE, index + 10)));
        let mut queued = VecDeque::new();
        let selection = select(&mut deposits, &mut queued, 0, fee_faucet_id(), RESERVE).unwrap();
        assert_eq!(selection.deposits.len(), MAX_DEPOSITS_PER_TX);
        assert_eq!(deposits.len(), 2);
        let smallest_taken = selection
            .deposits
            .iter()
            .map(|note| native_amount(note, fee_faucet_id()))
            .min()
            .unwrap();
        let largest_left = deposits
            .values()
            .map(|note| native_amount(note, fee_faucet_id()))
            .max()
            .unwrap();
        assert!(smallest_taken > largest_left);
    }

    /// Admission holds back the fee of one transaction, because the transaction pays that fee out
    /// of the same vault the notes are paid from.
    #[test]
    fn admission_holds_back_the_fee_reserve() {
        assert_eq!(admit([100], 100 + RESERVE, RESERVE), 1);
        assert_eq!(admit([100], 99 + RESERVE, RESERVE), 0);
        assert_eq!(admit([100, 100], 100 + RESERVE, RESERVE), 1);
    }
}
