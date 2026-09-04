//! One transaction attempt against one network account.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_tracing::{error, info, miden_instrument};
use miden_node_utils::lru_cache::LruCache;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteScript, Nullifier};
use miden_protocol::transaction::{TransactionArgs, TransactionId};

use crate::candidate::TransactionCandidate;
use crate::chain_state::ChainState;
use crate::clients::{RemoteTransactionProver, RpcClient};
use crate::db::NtxDbReader;
use crate::execute::{NtxError, NtxExecutionResult};
use crate::selection::{
    Selection,
    attribute_failed_notes,
    log_deferred_notes,
    log_oversized_notes,
    select_candidate,
};
use crate::{LOG_TARGET, NoteError, execute};

// ATTEMPT CONTEXT
// ================================================================================================

/// gRPC clients used by an attempt to interact with the node's services.
#[derive(Clone)]
pub struct GrpcClients {
    /// Client for interacting with the RPC service in order to load account state.
    pub rpc: RpcClient,
    /// Client for remote transaction proving.
    pub prover: RemoteTransactionProver,
}

/// Per-attempt configuration knobs.
#[derive(Debug, Clone, Copy)]
pub struct AttemptConfig {
    /// Maximum number of notes per transaction. Sponsorship notes count against this budget.
    pub max_notes_per_tx: NonZeroUsize,
    /// Maximum number of note execution attempts before dropping a note.
    pub max_note_attempts: usize,
    /// Maximum number of VM execution cycles for network transactions.
    pub max_cycles: u32,
    /// Initial sleep applied between per-request retries on transient infrastructure failures
    /// (prover unreachable, RPC transport error, RPC gRPC hiccup). Doubles each retry up to
    /// [`Self::request_backoff_max`].
    pub request_backoff_initial: Duration,
    /// Upper bound on the per-request retry backoff sleep.
    pub request_backoff_max: Duration,
}

/// Resources every attempt shares.
#[derive(Clone)]
pub struct AttemptContext {
    /// gRPC clients used by the attempt.
    pub clients: GrpcClients,
    /// Read-only database handle. An attempt performs no writes.
    pub db: NtxDbReader,
    /// Shared LRU cache for note scripts retrieved over RPC.
    pub script_cache: LruCache<Word, NoteScript>,
    /// [`TransactionArgs`] used by every network transaction. These are constant and are therefore
    /// prebuilt once and cloned per transaction.
    pub tx_args: TransactionArgs,
    /// Per-attempt configuration knobs.
    pub config: AttemptConfig,
}

#[cfg(test)]
impl AttemptContext {
    /// Creates a minimal [`AttemptContext`] for tests.
    pub fn test(db: &NtxDbReader) -> Self {
        use url::Url;

        let url = Url::parse("http://127.0.0.1:1").unwrap();
        let block_header = crate::test_utils::mock_block_header(0_u32.into());
        let trusted_validator_signing_keys = block_header.validator_keys().as_keys().to_vec();

        Self {
            clients: GrpcClients {
                rpc: RpcClient::new(
                    url.clone(),
                    Word::default(),
                    trusted_validator_signing_keys,
                    Duration::from_secs(10),
                    Duration::from_millis(1),
                    Duration::from_millis(10),
                )
                .expect("rpc client should be constructed"),
                prover: RemoteTransactionProver::new(url, Duration::from_secs(10))
                    .expect("prover client should be constructed"),
            },
            db: db.clone(),
            script_cache: LruCache::new(NonZeroUsize::new(1).unwrap()),
            tx_args: crate::selection::build_tx_args(
                std::num::NonZeroU16::new(30).expect("literal is non-zero"),
            ),
            config: AttemptConfig {
                max_notes_per_tx: NonZeroUsize::new(20).expect("literal is non-zero"),
                max_note_attempts: 30,
                max_cycles: 1 << 18,
                request_backoff_initial: Duration::from_millis(1),
                request_backoff_max: Duration::from_millis(10),
            },
        }
    }
}

// ATTEMPT OUTCOME
// ================================================================================================

/// Note bookkeeping an attempt produced. The scheduler persists all of it, whatever the
/// [`AttemptResult`].
#[derive(Default)]
pub struct NoteUpdates {
    /// Notes whose attempt counter must be incremented, keyed by the nullifier the failure is
    /// recorded under.
    pub failed: Vec<(Nullifier, NoteError)>,
    /// Notes that can never be consumed and must be marked permanently unconsumable.
    pub discarded: Vec<Nullifier>,
    /// Corrected eligibility blocks for notes whose stored block was too permissive. Persisting
    /// these is what stops the account being selected again for a note it cannot attempt.
    pub eligibility: Vec<(Nullifier, BlockNumber)>,
    /// Note scripts fetched over RPC that should be persisted to the local cache.
    pub scripts: Vec<(Word, NoteScript)>,
}

/// How an attempt ended.
pub enum AttemptResult {
    /// A transaction was proven and submitted. The account is now in flight and is not retried
    /// until the transaction commits or expires.
    Submitted { tx_id: TransactionId },
    /// Selection produced no candidate. Any note whose stored eligibility was wrong is corrected
    /// through [`NoteUpdates::eligibility`], so the account is not selected again for it.
    NoWork,
    /// The candidate failed for a reason attributed to its notes, which are named in
    /// [`NoteUpdates::failed`].
    Failed,
    /// The attempt could not be attributed to any note: the account or its notes could not be read.
    /// No note is penalized, because the failure is not the notes' fault.
    Aborted(anyhow::Error),
}

/// What an attempt did, and what the scheduler must persist as a result.
pub struct AttemptOutcome {
    /// The account the attempt ran against.
    pub account_id: AccountId,
    /// Reference block of the attempt. Note bookkeeping is recorded against it.
    pub block_num: BlockNumber,
    /// Note bookkeeping to persist, populated on every path.
    pub notes: NoteUpdates,
    /// How the attempt ended.
    pub result: AttemptResult,
}

// ATTEMPT
// ================================================================================================

/// Runs a single transaction attempt for `account_id`.
#[miden_instrument(
    name = "ntx.attempt",
    fields(
        account.id = account_id,
        reference_block.number = chain.chain_tip_header.block_num(),
    ),
)]
pub async fn attempt(
    ctx: AttemptContext,
    account_id: AccountId,
    chain: ChainState,
) -> AttemptOutcome {
    let block_num = chain.chain_tip_header.block_num();
    match run(&ctx, account_id, chain).await {
        Ok(outcome) => outcome,
        Err(err) => AttemptOutcome {
            account_id,
            block_num,
            notes: NoteUpdates::default(),
            result: AttemptResult::Aborted(err),
        },
    }
}

/// The attempt body. Errors here are infrastructure failures that cannot be charged to a note.
async fn run(
    ctx: &AttemptContext,
    account_id: AccountId,
    chain: ChainState,
) -> anyhow::Result<AttemptOutcome> {
    let block_num = chain.chain_tip_header.block_num();

    // The scheduler only picks accounts whose creation is committed, so a missing row means the
    // account state was removed between the query and this read. Report no work rather than an
    // error: there is nothing to penalize.
    let Some(account) = ctx
        .db
        .get_account(account_id)
        .await
        .context("failed to load committed account")?
    else {
        return Ok(AttemptOutcome {
            account_id,
            block_num,
            notes: NoteUpdates::default(),
            result: AttemptResult::NoWork,
        });
    };
    let account = Arc::new(account);

    let Selection { candidate, rejected, stale_eligibility } = select_candidate(
        &ctx.db,
        &account,
        chain,
        ctx.config.max_notes_per_tx,
        ctx.config.max_note_attempts,
    )
    .await?;

    // Notes outside the account's allowlist are penalized, and notes whose stored eligibility was
    // too permissive are corrected, whether or not a candidate was built.
    let mut notes = NoteUpdates {
        failed: rejected,
        eligibility: stale_eligibility,
        ..NoteUpdates::default()
    };

    let Some(candidate) = candidate else {
        return Ok(AttemptOutcome {
            account_id,
            block_num,
            notes,
            result: AttemptResult::NoWork,
        });
    };

    let result = execute_candidate(ctx, account_id, candidate, &mut notes).await;

    Ok(AttemptOutcome { account_id, block_num, notes, result })
}

/// Executes, proves and submits `candidate`, recording the note bookkeeping into `notes`.
async fn execute_candidate(
    ctx: &AttemptContext,
    account_id: AccountId,
    candidate: TransactionCandidate,
    notes: &mut NoteUpdates,
) -> AttemptResult {
    // Failures of a sponsorship note are attributed to the feature note of its bundle: sponsorship
    // notes have no row in the `notes` table, so the feature note carries the attempt tracking for
    // its whole bundle.
    let sponsor_to_feature = candidate.sponsor_to_feature_nullifier();
    let note_ids: Vec<_> = candidate
        .notes
        .iter()
        .flat_map(|sponsored| {
            std::iter::once(sponsored.feature.as_note().id())
                .chain(sponsored.sponsorships.iter().map(Note::id))
        })
        .collect();
    let feature_nullifiers: Vec<_> = candidate
        .notes
        .iter()
        .map(|sponsored| sponsored.feature.as_note().nullifier())
        .collect();

    info!(
        target: LOG_TARGET,
        "executing network transaction",
        account.id = account_id,
        note.ids = note_ids.as_slice(),
        note.count = note_ids.len()
    );

    let context = execute::NtxContext::new(
        ctx.clients.prover.clone(),
        ctx.clients.rpc.clone(),
        ctx.script_cache.clone(),
        ctx.db.clone(),
        ctx.config.max_cycles,
        ctx.tx_args.clone(),
        ctx.config.request_backoff_initial,
        ctx.config.request_backoff_max,
    );

    match context.execute_transaction(candidate).await {
        Ok(NtxExecutionResult {
            tx_id,
            failed_notes,
            deferred_notes,
            oversized_notes,
            fetched_scripts,
        }) => {
            info!(
                target: LOG_TARGET,
                "network transaction executed",
                account.id = account_id,
                transaction.id = tx_id,
                note.failed.count = failed_notes.len(),
                note.deferred.count = deferred_notes.len(),
                note.oversized.count = oversized_notes.len()
            );
            notes.scripts = fetched_scripts;

            log_deferred_notes(deferred_notes);

            let (oversized_sponsorships, oversized_features): (Vec<_>, Vec<_>) = oversized_notes
                .into_iter()
                .partition(|f| sponsor_to_feature.contains_key(&f.note().id()));

            let mut to_penalize = failed_notes;
            to_penalize.extend(oversized_sponsorships);
            notes.failed.extend(attribute_failed_notes(to_penalize, &sponsor_to_feature));
            notes.discarded = log_oversized_notes(oversized_features);

            AttemptResult::Submitted { tx_id }
        },
        Err(err) => {
            error!(
                &err,
                target: LOG_TARGET,
                "network transaction failed",
                account.id = account_id,
                note.ids = note_ids.as_slice()
            );

            let failed = match err {
                NtxError::AllNotesFailed(per_note) => {
                    attribute_failed_notes(per_note, &sponsor_to_feature)
                },
                other => {
                    let error: NoteError = Arc::new(other);
                    feature_nullifiers
                        .into_iter()
                        .map(|nullifier| {
                            info!(
                                error.as_ref(),
                                target: LOG_TARGET,
                                "note failed: transaction execution error",
                                note.nullifier = nullifier
                            );
                            (nullifier, error.clone())
                        })
                        .collect()
                },
            };
            notes.failed.extend(failed);

            AttemptResult::Failed
        },
    }
}
