//! The funding worker.
//!
//! One task owns the funding account. It is the only writer of that account, which is what
//! serialises the transactions: the worker keeps a single transaction in flight and collects
//! everything which arrives in the meantime into the next one.

use std::collections::VecDeque;
use std::num::{NonZeroU16, NonZeroUsize};
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_tracing::{error, info, warn};
use miden_node_utils::retry::{self, Retryable};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetId;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::Note;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{PartialBlockchain, TransactionId};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Word};
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};

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
    /// The native asset, which pays the fee.
    pub fee_asset_id: AssetId,
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

/// Turns queued funding notes and collected deposits into transactions.
pub struct Funder {
    node: RpcNodeClient,
    prover: Prover,
    setup: FunderSetup,
    rng: RandomCoin,
    account_checked: bool,
    scanner: DepositScanner,
    /// Notes the service already answered a requester with, which no transaction created yet.
    queued: VecDeque<Note>,
    /// Deposits found on chain which no transaction consumed yet.
    deposits: Vec<Note>,
    /// When the last deposit scan ran. `None` until the first scan.
    last_scan: Option<Instant>,
    /// When the worker tries again after it found nothing worth submitting. Only a deposit raises
    /// the balance, and deposits arrive on their own interval, so an earlier retry would read the
    /// same chain state again.
    idle_until: Option<Instant>,
    pending: Option<Pending>,
}

impl Funder {
    /// Creates a worker for the given funding account.
    pub fn new(node: RpcNodeClient, prover: Prover, setup: FunderSetup) -> Self {
        let scanner = DepositScanner::new(setup.key.account_id(), setup.fee_asset_id);

        Self {
            node,
            prover,
            setup,
            rng: RandomCoin::new(Word::from(rand::random::<[u32; 4]>())),
            account_checked: false,
            scanner,
            queued: VecDeque::new(),
            deposits: Vec::new(),
            last_scan: None,
            idle_until: None,
            pending: None,
        }
    }

    /// Runs the worker until the request channel closes or the service shuts down.
    pub async fn run(
        mut self,
        mut requests: mpsc::Receiver<Note>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(self.setup.config.tick_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            let queued_before = self.queued.len();

            let woke_on_note = tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => false,
                note = requests.recv() => match note {
                    Some(note) => {
                        self.queued.push_back(note);
                        true
                    },
                    None => break,
                },
            };

            // Give the notes which arrive together a chance to share one transaction.
            if woke_on_note {
                tokio::select! {
                    () = tokio::time::sleep(BATCH_LINGER) => {},
                    () = shutdown.cancelled() => break,
                }
            }

            // Take everything else which already waits, so one transaction serves all of it.
            while let Ok(note) = requests.try_recv() {
                self.queued.push_back(note);
            }

            // A new note may be payable even when the queue ahead of it is not, so the worker tries
            // again at once instead of waiting out the idle gate.
            if self.queued.len() > queued_before {
                self.idle_until = None;
            }

            // The future is boxed because it holds the transaction execution, which the
            // `large_futures` lint rejects on the enclosing future's stack.
            if let Err(err) = Box::pin(self.cycle()).await {
                warn!(&err, target: LOG_TARGET, "A funding cycle failed");
            }
        }

        Ok(())
    }

    /// Runs one cycle: resolve the transaction in flight, scan for deposits, and submit the next
    /// transaction.
    async fn cycle(&mut self) -> Result<()> {
        if !self.has_work() {
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

        if self.resolve_pending(&funder, reference_block) {
            return Ok(());
        }

        if self.scan_is_due() {
            if let Err(err) = self.scan_deposits(reference_block).await {
                warn!(&err, target: LOG_TARGET, "Failed to scan for deposits");
            }
        }

        let Some(Selection { deposits, notes }) = self.select(balance) else {
            return Ok(());
        };

        let fee_faucet = match self.read_fee_faucet(reference_block).await {
            Ok(fee_faucet) => fee_faucet,
            Err(err) => {
                self.restore(deposits, notes);

                return Err(err).context("failed to read the fee faucet account");
            },
        };

        let outcome = Box::pin(self.submit(
            reference_header,
            blockchain,
            funder,
            fee_faucet,
            &deposits,
            &notes,
        ))
        .await;

        match outcome {
            Ok(pending) => self.pending = Some(pending),
            Err(err) => {
                error!(&err, target: LOG_TARGET, "Failed to submit a funding transaction");
                self.restore(deposits, notes);
            },
        }

        Ok(())
    }

    /// Reports whether the worker has anything to do.
    fn has_work(&self) -> bool {
        if self.pending.is_some() {
            return true;
        }
        if self.idle_until.is_some_and(|at| Instant::now() < at) {
            return false;
        }

        !self.queued.is_empty() || !self.deposits.is_empty() || self.scan_is_due()
    }

    /// Reports whether the deposit scan interval has passed.
    fn scan_is_due(&self) -> bool {
        self.last_scan
            .is_none_or(|at| at.elapsed() >= self.setup.config.deposit_scan_interval)
    }

    /// Resolves the transaction in flight and reports whether it is still pending.
    fn resolve_pending(&mut self, funder: &Account, reference_block: BlockNumber) -> bool {
        let Some(pending) = &self.pending else {
            return false;
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

            return false;
        }

        if reference_block < pending.expiration_block {
            return true;
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

        false
    }

    /// Scans for deposits up to `reference_block` and adds the new ones to the pool.
    async fn scan_deposits(&mut self, reference_block: BlockNumber) -> Result<()> {
        let found = self.scanner.scan(&self.node, reference_block).await?;
        self.last_scan = Some(Instant::now());

        // A deposit which is already pooled must not enter a transaction twice.
        let pooled: Vec<_> = self.deposits.iter().map(Note::nullifier).collect();
        let new: Vec<Note> =
            found.into_iter().filter(|note| !pooled.contains(&note.nullifier())).collect();

        if new.is_empty() {
            return Ok(());
        }

        let total: u64 = new.iter().map(|note| native_amount(note, self.setup.fee_asset_id)).sum();
        info!(
            target: LOG_TARGET,
            "Found deposits for the funding account",
            account.id = self.account_id(),
            note.count = new.len(),
            asset.amount = total
        );
        self.deposits.extend(new);

        Ok(())
    }

    /// Takes the deposits and the notes of the next transaction out of the queues.
    ///
    /// Returns `None` when there is nothing worth submitting.
    fn select(&mut self, balance: u64) -> Option<Selection> {
        let limits = SelectionLimits {
            balance,
            reserve: self.fee_reserve(),
            fee_asset_id: self.setup.fee_asset_id,
            max_notes: self.setup.config.max_notes_per_tx.get(),
        };
        let selection = select(&mut self.deposits, &mut self.queued, limits);

        if selection.is_some() {
            self.idle_until = None;

            return selection;
        }

        if !self.queued.is_empty() {
            warn!(
                target: LOG_TARGET,
                "The funding account cannot cover the next queued note",
                account.id = self.account_id(),
                asset.balance = balance,
                asset.reserve = limits.reserve,
                note.count = self.queued.len()
            );
        }
        // Only a deposit changes the answer, and deposits arrive on their own interval.
        self.idle_until = Some(Instant::now() + self.setup.config.deposit_scan_interval);

        None
    }

    /// Returns the deposits and the notes of a transaction which did not reach the chain.
    fn restore(&mut self, deposits: Vec<Note>, notes: Vec<Note>) {
        self.deposits.extend(deposits);
        // The notes go back in front of everything which arrived later, which keeps the queue
        // first-come-first-served.
        for note in notes.into_iter().rev() {
            self.queued.push_front(note);
        }
    }

    /// Executes, proves and submits one transaction.
    async fn submit(
        &mut self,
        reference_header: BlockHeader,
        blockchain: PartialBlockchain,
        funder: Account,
        fee_faucet: (Account, AccountWitness),
        deposits: &[Note],
        notes: &[Note],
    ) -> Result<Pending> {
        let reference_block = reference_header.block_num();
        let nonce = funder.nonce();
        let inputs = ExecutionInputs {
            funder,
            secret_key: self.setup.key.secret_key().clone(),
            fee_faucet,
            protocol_config: self.setup.protocol_config.clone(),
            reference_header,
            blockchain,
            expiration_delta: self.setup.config.expiration_delta,
        };

        // The future is boxed because it holds the transaction execution, which the `large_futures`
        // lint rejects on the enclosing future's stack.
        let executed_tx =
            Box::pin(tx::execute(inputs, deposits.to_vec(), notes.to_vec(), &mut self.rng))
                .await
                .context("failed to execute the funding transaction")?;
        let transaction_inputs = executed_tx.tx_inputs().to_bytes();

        let proven_tx = self
            .prover
            .prove(executed_tx)
            .await
            .context("failed to prove the funding transaction")?;
        let transaction_id = proven_tx.id();
        let expiration_block = proven_tx.expiration_block_num();

        self.node
            .submit(&proven_tx, &transaction_inputs)
            .await
            .context("failed to submit the funding transaction")?;

        info!(
            target: LOG_TARGET,
            "Submitted a funding transaction",
            transaction.id = transaction_id,
            transaction.expires_at = expiration_block,
            block.number = reference_block,
            note.count = notes.len(),
            deposit.count = deposits.len()
        );

        Ok(Pending {
            transaction_id,
            nonce,
            expiration_block,
            deposits: deposits.to_vec(),
            notes: notes.to_vec(),
        })
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
        self.retry_node_call(|| {
            self.node.public_account(self.setup.fee_asset_id.faucet_id(), reference_block)
        })
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
            .get_balance(self.setup.fee_asset_id)
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

/// What one selection is bounded by.
#[derive(Debug, Clone, Copy)]
struct SelectionLimits {
    /// The funding account's balance of the native asset.
    balance: u64,
    /// The fee one transaction may cost at worst.
    reserve: u64,
    /// The native asset.
    fee_asset_id: AssetId,
    /// The largest number of notes one transaction creates.
    max_notes: usize,
}

/// Takes the deposits and the notes of the next transaction out of the queues.
///
/// Returns `None` when there is nothing worth submitting, and then leaves both queues untouched. A
/// note which does not fit stays in `queued`: the service already answered a requester with it, so
/// it is created later instead of being dropped.
fn select(
    deposits: &mut Vec<Note>,
    queued: &mut VecDeque<Note>,
    limits: SelectionLimits,
) -> Option<Selection> {
    let amount = |note: &Note| native_amount(note, limits.fee_asset_id);

    // The largest deposits first, so a transaction which is capped still brings in the most.
    deposits.sort_unstable_by_key(|note| std::cmp::Reverse(amount(note)));
    let deposit_count = deposits.len().min(MAX_DEPOSITS_PER_TX);
    let collected: u64 = deposits[..deposit_count].iter().map(&amount).sum();

    let note_count = admit(
        queued.iter().take(limits.max_notes).map(&amount),
        limits.balance.saturating_add(collected),
        limits.reserve,
    );

    // A transaction which creates no note must bring in more than it pays in fees. Anyone can send
    // a note which holds a single base unit, and consuming it on its own would cost the account
    // more than it gains.
    if note_count == 0 && collected <= limits.reserve {
        return None;
    }

    Some(Selection {
        deposits: deposits.drain(..deposit_count).collect(),
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

    /// The native asset in these tests.
    fn fee_asset_id() -> AssetId {
        AssetId::new_fungible(fee_faucet_id())
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

    fn limits(balance: u64) -> SelectionLimits {
        SelectionLimits {
            balance,
            reserve: RESERVE,
            fee_asset_id: fee_asset_id(),
            max_notes: 16,
        }
    }

    /// A deposit which does not cover the fee of the transaction that consumes it is left alone.
    /// Consuming it would cost the account more than it brings in.
    #[test]
    fn a_deposit_below_the_fee_reserve_is_not_consumed_on_its_own() {
        let mut deposits = vec![note(1, 1)];
        let mut queued = VecDeque::new();

        assert!(select(&mut deposits, &mut queued, limits(0)).is_none());
        assert_eq!(deposits.len(), 1, "the deposit stays in the pool");
    }

    /// A deposit worth more than the fee is consumed even when nothing is queued.
    #[test]
    fn a_deposit_above_the_fee_reserve_is_consumed_on_its_own() {
        let mut deposits = vec![note(RESERVE + 1, 2)];
        let mut queued = VecDeque::new();

        let selection =
            select(&mut deposits, &mut queued, limits(0)).expect("the deposit is worth consuming");

        assert_eq!(selection.deposits.len(), 1);
        assert!(selection.notes.is_empty());
        assert!(deposits.is_empty());
    }

    /// A requester already holds the note it was answered with, so a note the balance cannot cover
    /// waits for a deposit instead of being dropped.
    #[test]
    fn a_note_the_balance_cannot_cover_stays_queued() {
        let mut deposits = Vec::new();
        let mut queued = VecDeque::from(vec![note(1_000, 3)]);

        assert!(select(&mut deposits, &mut queued, limits(RESERVE)).is_none());
        assert_eq!(queued.len(), 1, "the note stays queued");
    }

    /// A deposit raises the balance in the same transaction, because the assets of an input note
    /// land before the kernel withdraws the fee.
    #[test]
    fn a_deposit_pays_for_a_note_in_the_same_transaction() {
        let mut deposits = vec![note(1_000, 4)];
        let mut queued = VecDeque::from(vec![note(1_000, 5)]);

        let selection = select(&mut deposits, &mut queued, limits(RESERVE))
            .expect("the deposit covers the note");

        assert_eq!(selection.deposits.len(), 1);
        assert_eq!(selection.notes.len(), 1);
        assert!(queued.is_empty());
    }

    /// Admission is first-come-first-served: a later, smaller note is not created ahead of a note
    /// the balance cannot cover yet.
    #[test]
    fn admission_stops_at_the_first_note_which_does_not_fit() {
        let mut deposits = Vec::new();
        let mut queued = VecDeque::from(vec![note(500, 6), note(5_000, 7), note(100, 8)]);

        let selection = select(&mut deposits, &mut queued, limits(RESERVE + 1_000))
            .expect("the first note fits");

        assert_eq!(selection.notes.len(), 1);
        assert_eq!(queued.len(), 2, "the notes behind the one which does not fit stay queued");
    }

    /// One transaction consumes at most `MAX_DEPOSITS_PER_TX` deposits, and takes the largest ones
    /// so that a capped transaction still brings in the most.
    #[test]
    fn the_largest_deposits_are_taken_up_to_the_cap() {
        let count = u32::try_from(MAX_DEPOSITS_PER_TX).expect("the cap fits in a u32") + 2;
        let mut deposits: Vec<Note> =
            (0..count).map(|index| note(u64::from(index) + RESERVE, index + 10)).collect();
        let mut queued = VecDeque::new();

        let selection = select(&mut deposits, &mut queued, limits(0))
            .expect("the deposits are worth consuming");

        assert_eq!(selection.deposits.len(), MAX_DEPOSITS_PER_TX);
        assert_eq!(deposits.len(), 2, "the smallest deposits stay in the pool");

        let smallest_taken = selection
            .deposits
            .iter()
            .map(|note| native_amount(note, fee_asset_id()))
            .min()
            .expect("the selection holds deposits");
        let largest_left = deposits
            .iter()
            .map(|note| native_amount(note, fee_asset_id()))
            .max()
            .expect("the pool holds deposits");
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
