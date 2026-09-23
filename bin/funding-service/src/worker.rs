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
use crate::inclusion::{AccountTransition, Inclusion, await_inclusion};
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
    /// Whether the request is answered only once its note is committed in a block.
    ///
    /// A request which does not wait is answered as soon as the node accepts the transaction. Its
    /// note carries no inclusion proof and is not yet on chain, so a transaction which expires
    /// before it commits leaves that note uncreated. A requester which cannot handle that must
    /// wait.
    pub wait_for_commit: bool,
    /// Where the outcome is sent.
    pub reply: oneshot::Sender<Result<FundedNote, RequestFundsError>>,
}

/// A funding note the service created.
#[derive(Debug, Clone)]
pub struct FundedNote {
    pub note: Note,
    /// Proof that the note is in a block. Absent when the requester did not wait for the note to
    /// commit, because the proof exists only once it has.
    pub inclusion_proof: Option<NoteInclusionProof>,
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
    /// How often the worker asks the node whether the funding transaction is committed.
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

            // A requester which gave up must not be funded. The transaction would spend the funding
            // balance and pay a fee for a note which no requester waits for.
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

        let note_count = notes.len();

        // The requests which do not wait are answered here, as soon as the node holds the
        // transaction, and leave the batch. The failure paths below then reach only the requests
        // which are still waiting, which are the ones an expiry can still be reported to.
        let notes = answer_requests_which_do_not_wait(batch, notes, transaction_id);

        // The transaction is awaited even when no request waits for it. The service reads the
        // funding account from the node before every transaction, so the next batch would build on
        // a stale nonce if this one started before its predecessor committed.
        self.await_commit(&proven_tx, note_count, shutdown).await?;

        let proofs = self.proofs_for_waiting_requests(&notes, transaction_id).await;
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

    /// Waits until `proven_tx` commits, and maps every other outcome to a batch failure.
    async fn await_commit(
        &self,
        proven_tx: &ProvenTransaction,
        note_count: usize,
        shutdown: &CancellationToken,
    ) -> Result<(), BatchFailure> {
        let transaction_id = proven_tx.id();
        let expiration_block = proven_tx.expiration_block_num();
        let transition = AccountTransition {
            account_id: self.account_id(),
            initial: proven_tx.account_update().initial_state_commitment(),
            final_: proven_tx.account_update().final_state_commitment(),
            expiration: expiration_block,
        };

        match await_inclusion(&self.node, transition, self.setup.config.poll_interval, shutdown)
            .await
        {
            Inclusion::Committed => Ok(()),
            Inclusion::Expired => {
                warn!(
                    target: LOG_TARGET,
                    "The funding transaction expired before it committed",
                    transaction.id = transaction_id,
                    transaction.expires_at = expiration_block,
                    note.count = note_count
                );
                Err(BatchFailure::Expired(expiration_block))
            },
            Inclusion::Diverged { observed, block } => {
                let err = anyhow::anyhow!(
                    "the funding account is at state {observed} at block {block}, which neither \
                     precedes nor follows funding transaction {transaction_id}"
                );
                error!(
                    &err,
                    target: LOG_TARGET,
                    "The funding account changed outside the funding transaction",
                    transaction.id = transaction_id
                );
                Err(BatchFailure::Internal(err.as_report()))
            },
            Inclusion::ShuttingDown => Err(BatchFailure::ShuttingDown),
        }
    }

    /// Reads the inclusion proofs of `notes`, which belong to the requests that wait for the commit,
    /// from a committed transaction.
    ///
    /// Only the notes of waiting requests are read. A requester which did not wait can consume its
    /// note in the block which creates it, and that block erases the note. A waiting requester
    /// receives its note only after the commit, so its note cannot be erased. A note which is
    /// still missing fails only its own request, in `reply_with_notes`.
    async fn proofs_for_waiting_requests(
        &self,
        notes: &[Note],
        transaction_id: TransactionId,
    ) -> HashMap<NoteId, NoteInclusionProof> {
        if notes.is_empty() {
            return HashMap::new();
        }

        let note_ids: Vec<NoteId> = notes.iter().map(Note::id).collect();
        match self.retry_node_call(|| self.node.committed_notes(&note_ids)).await {
            Ok(proofs) => proofs,
            Err(err) => {
                error!(
                    &err,
                    target: LOG_TARGET,
                    "Failed to read the inclusion proofs of a committed funding transaction",
                    transaction.id = transaction_id
                );
                HashMap::new()
            },
        }
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
/// Answers the requests in `batch` which do not wait for their note to commit and removes them
/// from it, returning the notes of the requests which remain.
///
/// The returned notes keep the position of the request they belong to, which is what pairs a
/// request with its note.
fn answer_requests_which_do_not_wait(
    batch: &mut Vec<FundingRequest>,
    notes: Vec<Note>,
    transaction_id: TransactionId,
) -> Vec<Note> {
    let mut waiting_requests = Vec::with_capacity(batch.len());
    let mut waiting_notes = Vec::with_capacity(notes.len());

    for (request, note) in std::mem::take(batch).into_iter().zip(notes) {
        if request.wait_for_commit {
            waiting_requests.push(request);
            waiting_notes.push(note);
            continue;
        }

        let _ = request.reply.send(Ok(FundedNote {
            note,
            inclusion_proof: None,
            transaction_id,
        }));
    }

    *batch = waiting_requests;

    waiting_notes
}

fn reply_with_notes(
    batch: Vec<FundingRequest>,
    notes: Vec<Note>,
    mut proofs: HashMap<NoteId, NoteInclusionProof>,
    transaction_id: TransactionId,
) {
    for (request, note) in batch.into_iter().zip(notes) {
        // The transaction committed, so a missing proof is not an expiry. It fails only this
        // request.
        let response = match proofs.remove(&note.id()) {
            Some(inclusion_proof) => Ok(FundedNote {
                note,
                inclusion_proof: Some(inclusion_proof),
                transaction_id,
            }),
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::merkle::{MerklePath, SparseMerklePath};
    use miden_protocol::note::NoteType;
    use miden_standards::note::P2idNote;

    use super::*;

    type Reply = oneshot::Receiver<Result<FundedNote, RequestFundsError>>;

    fn note(serial: u32) -> Note {
        let faucet_id = FungibleAsset::mock_issuer();
        P2idNote::builder()
            .sender(faucet_id)
            .target(faucet_id)
            .serial_number(Word::from([serial; 4]))
            .note_type(NoteType::Public)
            .asset(FungibleAsset::new(faucet_id, 42).unwrap())
            .build()
            .unwrap()
            .into()
    }

    fn proof(index: u16) -> NoteInclusionProof {
        NoteInclusionProof::new(
            7.into(),
            index,
            SparseMerklePath::try_from(MerklePath::new(vec![Word::from([1u32; 4])])).unwrap(),
        )
        .unwrap()
    }

    fn request(wait_for_commit: bool) -> (FundingRequest, Reply) {
        let (reply, receiver) = oneshot::channel();
        let request = FundingRequest {
            target: FungibleAsset::mock_issuer(),
            amount: 42,
            wait_for_commit,
            reply,
        };
        (request, receiver)
    }

    fn transaction_id() -> TransactionId {
        TransactionId::from_raw(Word::from([9u32; 4]))
    }

    #[test]
    fn requests_which_do_not_wait_are_answered_without_a_proof() {
        let (waiting, mut waiting_reply) = request(true);
        let (early, mut early_reply) = request(false);
        let mut batch = vec![waiting, early];

        let waiting_notes =
            answer_requests_which_do_not_wait(&mut batch, vec![note(1), note(2)], transaction_id());

        let answer = early_reply.try_recv().unwrap().unwrap();
        assert_eq!(answer.note.id(), note(2).id());
        assert!(answer.inclusion_proof.is_none());

        assert_eq!(batch.len(), 1);
        assert!(waiting_reply.try_recv().is_err(), "a waiting request is not answered yet");
        assert_eq!(waiting_notes.iter().map(Note::id).collect::<Vec<_>>(), vec![note(1).id()]);
    }

    #[test]
    fn a_batch_where_no_request_waits_keeps_no_note_to_prove() {
        let (first, _first_reply) = request(false);
        let (second, _second_reply) = request(false);
        let mut batch = vec![first, second];

        let waiting_notes =
            answer_requests_which_do_not_wait(&mut batch, vec![note(1), note(2)], transaction_id());

        assert!(batch.is_empty());
        assert!(waiting_notes.is_empty());
    }

    #[test]
    fn waiting_requests_receive_their_own_proof() {
        let (first, mut first_reply) = request(true);
        let (second, mut second_reply) = request(true);
        let proofs = HashMap::from([(note(1).id(), proof(1)), (note(2).id(), proof(2))]);

        reply_with_notes(vec![first, second], vec![note(1), note(2)], proofs, transaction_id());

        let first = first_reply.try_recv().unwrap().unwrap();
        let second = second_reply.try_recv().unwrap().unwrap();
        assert_eq!(first.note.id(), note(1).id());
        assert_eq!(first.inclusion_proof.unwrap().location(), proof(1).location());
        assert_eq!(second.note.id(), note(2).id());
        assert_eq!(second.inclusion_proof.unwrap().location(), proof(2).location());
    }

    /// A missing proof must not fail the other requests of the transaction, which committed.
    #[test]
    fn a_missing_proof_fails_only_its_own_request() {
        let (proven, mut proven_reply) = request(true);
        let (unproven, mut unproven_reply) = request(true);
        let proofs = HashMap::from([(note(1).id(), proof(1))]);

        reply_with_notes(vec![proven, unproven], vec![note(1), note(2)], proofs, transaction_id());

        let proven = proven_reply.try_recv().unwrap().unwrap();
        assert_eq!(proven.inclusion_proof.unwrap().location(), proof(1).location());
        assert!(matches!(
            unproven_reply.try_recv().unwrap(),
            Err(RequestFundsError::Internal(_))
        ));
    }
}
