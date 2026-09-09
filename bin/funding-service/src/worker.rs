//! The funding worker.
//!
//! One task owns the funding account and turns queued requests into transactions. The account's
//! nonce serialises its transactions, so the worker keeps a single transaction in flight and
//! coalesces every request which arrives while one is in progress into the next transaction.

use std::collections::HashMap;
use std::num::{NonZeroU16, NonZeroUsize};
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_tracing::{ErrorReport, error, info, warn};
use miden_node_utils::retry::{self, Retryable};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetId;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteId, NoteInclusionProof};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{PartialBlockchain, ProvenTransaction, TransactionId};
use miden_protocol::utils::serde::Serializable;
use tokio::sync::{mpsc, oneshot};

use crate::account::FunderKey;
use crate::error::RequestFundsError;
use crate::inclusion::{Inclusion, await_inclusion};
use crate::node::{RpcNodeClient, is_transient_error};
use crate::prover::Prover;
use crate::status::StatusSnapshot;
use crate::tx::{self, ExecutionInputs};
use crate::{COMPONENT, LOG_TARGET};

// CONSTANTS
// ================================================================================================

/// How long the worker waits for more requests after the first one arrives.
const BATCH_LINGER: Duration = Duration::from_millis(250);

/// Bounds on the retries of a node request inside one batch.
const NODE_RETRY_MIN_DELAY: Duration = Duration::from_millis(100);
const NODE_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
const NODE_RETRY_MAX_TIMES: usize = 5;

/// Upper bound on the fee formula's cycle multiplier: the kernel charges `verification_base_fee *
/// (ilog2(total_cycles) + 1)` with cycles capped at `2^29`.
const MAX_FEE_VERIFICATION_CYCLES: u64 = 30;

// REQUEST AND RESPONSE
// ================================================================================================

/// One queued funding request.
pub struct FundingRequest {
    /// The account which the note targets.
    pub target: AccountId,
    /// The amount of the native asset, in base units.
    pub amount: u64,
    /// Where the outcome is sent.
    pub reply: oneshot::Sender<Result<FundedNote, RequestFundsError>>,
}

/// A committed funding note.
#[derive(Debug, Clone)]
pub struct FundedNote {
    /// The note in full. The node does not store the details of a private note, so this is the only
    /// copy.
    pub note: Note,
    /// Proof that the note is in a block.
    pub inclusion_proof: NoteInclusionProof,
    /// The transaction which created the note.
    pub transaction_id: TransactionId,
}

// CONFIGURATION
// ================================================================================================

/// The limits the worker applies to every batch.
#[derive(Debug, Clone, Copy)]
pub struct WorkerConfig {
    /// The largest number of notes one transaction creates.
    pub max_notes_per_tx: NonZeroUsize,
    /// How many blocks after its reference block a funding transaction expires.
    pub expiration_delta: NonZeroU16,
    /// How often the worker asks the node whether the notes are committed.
    pub poll_interval: Duration,
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
    /// The limits applied to every batch.
    pub config: WorkerConfig,
    /// Where the worker publishes the funding account's balance.
    pub status: StatusSnapshot,
}

/// The chain state one batch is built against, read at one reference block.
struct BatchInputs {
    reference_header: BlockHeader,
    blockchain: PartialBlockchain,
    funder: Account,
    fee_faucet: (Account, AccountWitness),
}

/// One batch's transaction, proven and ready to submit.
struct PreparedBatch {
    proven_tx: ProvenTransaction,
    /// The encoded transaction inputs, which the submission seals.
    transaction_inputs: Vec<u8>,
    /// The notes the transaction creates, in the order of the requests they answer.
    notes: Vec<Note>,
}

/// Turns funding requests into transactions.
pub struct Funder {
    node: RpcNodeClient,
    prover: Prover,
    setup: FunderSetup,
    rng: RandomCoin,
    account_checked: bool,
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
        }
    }

    /// Runs the worker until the request channel closes or the service shuts down.
    pub async fn run(
        mut self,
        mut requests: mpsc::Receiver<FundingRequest>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        loop {
            let first = tokio::select! {
                () = shutdown.cancelled() => break,
                request = requests.recv() => match request {
                    Some(request) => request,
                    None => break,
                },
            };

            // Collect the requests which arrive while this one waits, so they share a transaction.
            tokio::select! {
                () = tokio::time::sleep(BATCH_LINGER) => {},
                () = shutdown.cancelled() => {},
            }

            let mut batch = vec![first];
            while batch.len() < self.setup.config.max_notes_per_tx.get() {
                match requests.try_recv() {
                    Ok(request) => batch.push(request),
                    Err(_) => break,
                }
            }

            // A requester which gave up must not be funded: the note would be created but never
            // delivered, and its funds would be stranded in a private note nobody holds.
            batch.retain(|request| !request.reply.is_closed());
            if batch.is_empty() {
                continue;
            }

            if shutdown.is_cancelled() {
                fail_all(batch, || RequestFundsError::NotReady("the service is shutting down"));
                break;
            }

            self.process_batch(batch, &shutdown).await;
        }

        // Nothing else will read the queue, so waiting requesters are told to retry elsewhere.
        requests.close();
        while let Ok(request) = requests.try_recv() {
            let _ = request
                .reply
                .send(Err(RequestFundsError::NotReady("the service is shutting down")));
        }

        Ok(())
    }

    /// Reads the funding account at the chain tip and publishes its balance.
    async fn refresh_status(&mut self) -> Result<()> {
        let (reference_header, _blockchain) = self.node.tip_chain_state().await?;
        let block_num = reference_header.block_num();
        let (funder, _witness) = self.node.public_account(self.account_id(), block_num).await?;
        self.check_account_code(&funder)?;
        self.setup.status.update(
            self.fee_balance(&funder),
            block_num,
            reference_header.fee_parameters().verification_base_fee(),
        );
        Ok(())
    }

    /// Runs one batch and replies to every requester in it.
    async fn process_batch(
        &mut self,
        mut batch: Vec<FundingRequest>,
        shutdown: &CancellationToken,
    ) {
        match self.run_batch(&mut batch, shutdown, true).await {
            Ok(()) => {
                if let Err(err) = self.refresh_status().await {
                    warn!(
                        &err,
                        target: LOG_TARGET,
                        "Failed to read the funding account after a funding transaction"
                    );
                }
            },
            Err(failure) => fail_all(batch, || failure.to_error()),
        }
    }

    /// Creates, submits and awaits one funding transaction.
    async fn run_batch(
        &mut self,
        batch: &mut Vec<FundingRequest>,
        shutdown: &CancellationToken,
        allow_retry: bool,
    ) -> Result<(), BatchFailure> {
        let BatchInputs {
            reference_header,
            blockchain,
            funder,
            fee_faucet,
        } = self.read_batch_inputs().await.map_err(|err| {
            error!(&err, target: LOG_TARGET, "Failed to read the chain state for a batch");
            BatchFailure::from_node_error(&err)
        })?;
        let reference_block = reference_header.block_num();

        self.check_account_code(&funder).map_err(|err| {
            error!(&err, target: LOG_TARGET, "The funding account does not match its account file");
            BatchFailure::Internal(err.as_report())
        })?;

        let balance = self.fee_balance(&funder);
        self.setup.status.update(
            balance,
            reference_block,
            reference_header.fee_parameters().verification_base_fee(),
        );

        self.reject_unaffordable(batch, balance);
        if batch.is_empty() {
            return Ok(());
        }

        let targets: Vec<(AccountId, u64)> =
            batch.iter().map(|request| (request.target, request.amount)).collect();

        // The future is boxed because it holds the transaction execution, which the `large_futures`
        // lint rejects on the enclosing future's stack.
        let PreparedBatch { proven_tx, transaction_inputs, notes } = Box::pin(self.prepare_batch(
            reference_header,
            blockchain,
            funder,
            fee_faucet,
            &targets,
        ))
        .await
        .map_err(|err| {
            error!(&err, target: LOG_TARGET, "Failed to prepare the funding transaction");
            BatchFailure::Internal(err.as_report())
        })?;
        let transaction_id = proven_tx.id();
        let expiration_block = proven_tx.expiration_block_num();

        if let Err(err) = self.node.submit(&proven_tx, &transaction_inputs).await {
            if !is_transient_error(&err) && allow_retry {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "The node rejected the funding transaction; retrying from a fresh block",
                    transaction.id = transaction_id
                );
                return Box::pin(self.run_batch(batch, shutdown, false)).await;
            }

            error!(
                &err,
                target: LOG_TARGET,
                "Failed to submit the funding transaction",
                transaction.id = transaction_id
            );
            return Err(BatchFailure::from_submit_error(&err));
        }

        info!(
            target: LOG_TARGET,
            "Submitted a funding transaction",
            transaction.id = transaction_id,
            transaction.expires_at = expiration_block,
            block.number = reference_block,
            note.count = notes.len()
        );

        let note_ids: Vec<_> = notes.iter().map(Note::id).collect();
        let proofs = match await_inclusion(
            &self.node,
            &note_ids,
            expiration_block,
            self.setup.config.poll_interval,
            shutdown,
        )
        .await
        {
            Inclusion::Committed(proofs) => proofs,
            Inclusion::Expired => {
                warn!(
                    target: LOG_TARGET,
                    "The funding transaction expired before it committed",
                    transaction.id = transaction_id,
                    transaction.expires_at = expiration_block,
                    note.count = note_ids.len()
                );
                return Err(BatchFailure::Expired(expiration_block));
            },
            Inclusion::ShuttingDown => return Err(BatchFailure::ShuttingDown),
        };

        reply_with_notes(std::mem::take(batch), notes, proofs, transaction_id);

        Ok(())
    }

    /// Replies to the requests which `balance` cannot cover and removes them from `batch`.
    fn reject_unaffordable(&self, batch: &mut Vec<FundingRequest>, balance: u64) {
        let reserve = u64::from(self.setup.verification_base_fee) * MAX_FEE_VERIFICATION_CYCLES;
        let amounts: Vec<u64> = batch.iter().map(|request| request.amount).collect();
        let admitted_count = admit(&amounts, balance, reserve);

        for request in batch.drain(admitted_count..) {
            let _ = request.reply.send(Err(RequestFundsError::InsufficientFunds {
                requested: request.amount,
                balance,
                reserve,
            }));
        }

        if batch.is_empty() {
            warn!(
                target: LOG_TARGET,
                "The funding account cannot cover any queued request",
                account.id = self.account_id(),
                asset.balance = balance,
                asset.reserve = reserve
            );
        }
    }

    /// Reads the chain state one batch needs, at a fresh reference block.
    async fn read_batch_inputs(&self) -> Result<BatchInputs> {
        let (reference_header, blockchain) = self
            .retry_node_call(|| self.node.tip_chain_state())
            .await
            .context("failed to read the chain state")?;
        let reference_block = reference_header.block_num();

        let (funder, _funder_witness) = self
            .retry_node_call(|| self.node.public_account(self.account_id(), reference_block))
            .await
            .context("failed to read the funding account")?;
        let fee_faucet = self
            .retry_node_call(|| self.node.public_account(self.setup.fee_faucet_id, reference_block))
            .await
            .context("failed to read the fee faucet account")?;

        Ok(BatchInputs {
            reference_header,
            blockchain,
            funder,
            fee_faucet,
        })
    }

    /// Builds the notes for `targets`, then executes and proves the transaction which creates them.
    async fn prepare_batch(
        &mut self,
        reference_header: BlockHeader,
        blockchain: PartialBlockchain,
        funder: Account,
        fee_faucet: (Account, AccountWitness),
        targets: &[(AccountId, u64)],
    ) -> Result<PreparedBatch> {
        let notes = tx::build_funding_notes(
            self.account_id(),
            self.setup.fee_faucet_id,
            targets,
            &mut self.rng,
        )
        .context("failed to build the funding notes")?;

        let inputs = ExecutionInputs {
            funder,
            secret_key: self.setup.key.secret_key().clone(),
            fee_faucet,
            protocol_config: self.setup.protocol_config.clone(),
            reference_header,
            blockchain,
            expiration_delta: self.setup.config.expiration_delta,
        };
        let executed_tx = tx::execute(inputs, notes.clone(), &mut self.rng)
            .await
            .context("failed to execute the funding transaction")?;
        let transaction_inputs = executed_tx.tx_inputs().to_bytes();

        let proven_tx = self
            .prover
            .prove(executed_tx)
            .await
            .context("failed to prove the funding transaction")?;

        Ok(PreparedBatch { proven_tx, transaction_inputs, notes })
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

// ADMISSION
// ================================================================================================

/// Returns how many of `amounts` the funding account can pay for, in order.
///
/// The transaction pays its own fee out of the same vault, so `reserve` is held back. Admission
/// stops at the first request which does not fit: a later, smaller request is not admitted ahead of
/// it, which keeps the queue first-come-first-served and stops a stream of small requests from
/// starving a large one.
fn admit(amounts: &[u64], balance: u64, reserve: u64) -> usize {
    let mut spendable = balance.saturating_sub(reserve);

    for (index, &amount) in amounts.iter().enumerate() {
        // A zero amount is rejected before a request is queued, so every amount here is positive
        // and the balance strictly decreases.
        match spendable.checked_sub(amount) {
            Some(remaining) => spendable = remaining,
            None => return index,
        }
    }

    amounts.len()
}

// BATCH FAILURE
// ================================================================================================

/// Why a batch failed.
#[derive(Debug, Clone)]
enum BatchFailure {
    /// The service failed for a reason the requester cannot act on.
    Internal(String),
    /// The node could not be reached. The cause is logged where the failure is detected.
    NodeUnreachable,
    /// The node rejected the transaction.
    Rejected(String),
    /// The transaction expired without committing.
    Expired(BlockNumber),
    /// The service is shutting down.
    ShuttingDown,
}

impl BatchFailure {
    /// Classifies an error from a node request.
    fn from_node_error(err: &anyhow::Error) -> Self {
        if is_transient_error(err) {
            Self::NodeUnreachable
        } else {
            Self::Internal(err.as_report())
        }
    }

    /// Classifies an error from the transaction submission.
    fn from_submit_error(err: &anyhow::Error) -> Self {
        if is_transient_error(err) {
            Self::NodeUnreachable
        } else {
            Self::Rejected(err.as_report())
        }
    }

    /// The error reported to a requester.
    fn to_error(&self) -> RequestFundsError {
        match self {
            Self::Internal(report) => RequestFundsError::Internal(anyhow::anyhow!(report.clone())),
            Self::NodeUnreachable => RequestFundsError::NotReady("the node is unreachable"),
            Self::Rejected(report) => {
                RequestFundsError::TransactionRejected(anyhow::anyhow!(report.clone()))
            },
            Self::Expired(expiration_block) => {
                RequestFundsError::TransactionExpired { expiration_block: *expiration_block }
            },
            Self::ShuttingDown => RequestFundsError::NotReady("the service is shutting down"),
        }
    }
}

/// Answers every request with the note built for it.
fn reply_with_notes(
    batch: Vec<FundingRequest>,
    notes: Vec<Note>,
    mut proofs: HashMap<NoteId, NoteInclusionProof>,
    transaction_id: TransactionId,
) {
    for (request, note) in batch.into_iter().zip(notes) {
        // `Inclusion::Committed` holds a proof for every note of the transaction, so a missing
        // proof is a broken invariant and not an expired transaction.
        let response = match proofs.remove(&note.id()) {
            Some(inclusion_proof) => Ok(FundedNote { note, inclusion_proof, transaction_id }),
            None => Err(RequestFundsError::Internal(anyhow::anyhow!(
                "no inclusion proof for note {} of committed transaction {transaction_id}",
                note.id(),
            ))),
        };
        let _ = request.reply.send(response);
    }
}

/// Answers every request with the same failure.
fn fail_all(batch: Vec<FundingRequest>, error: impl Fn() -> RequestFundsError) {
    for request in batch {
        let _ = request.reply.send(Err(error()));
    }
}
