//! Block-driven scheduler for network transaction attempts.
//!
//! The scheduler owns the attempt tasks and decides which accounts to work on. It keeps no
//! per-account state beyond the in-flight set, which records the transactions it has submitted but
//! not yet seen committed. Everything else that decides "what to work on next" is read from the
//! database on every dispatch.

use std::collections::HashMap;
use std::num::NonZeroU16;

use anyhow::Context;
use miden_node_tracing::{debug, error, info, miden_instrument};
use miden_node_utils::formatting::format_opt;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;
use tokio::task::{Id, JoinSet};

use crate::LOG_TARGET;
use crate::attempt::{AttemptContext, AttemptOutcome, AttemptResult, NoteUpdates, attempt};
use crate::chain_state::ChainState;
use crate::committed_block::CommittedBlockEffects;
use crate::db::NtxDbWriter;

// SCHEDULER STATE
// ================================================================================================

/// A transaction the scheduler submitted and has not yet seen committed.
struct Inflight {
    /// Id of the submitted transaction, compared against each block's committed transactions.
    tx_id: TransactionId,
    /// Chain tip at submission. With the transaction expiration delta this bounds how long the
    /// account stays blocked when the submission never lands.
    submitted_at: BlockNumber,
}

// SCHEDULER
// ================================================================================================

/// Spawns and reaps network transaction attempts.
///
/// The scheduler is driven from the builder's event loop at three moments:
///
/// 1. On every committed block, [`Scheduler::handle_committed_block`] resolves the in-flight set
///    (landed or expired) and [`Scheduler::dispatch`] fills the free attempt slots.
/// 2. Whenever an attempt completes, [`Scheduler::handle_completion`] persists what the attempt
///    reported and says whether the freed slot should be refilled immediately.
/// 3. On shutdown, [`Scheduler::shutdown`] aborts the outstanding attempts.
pub struct Scheduler {
    /// Resources cloned into every spawned attempt.
    ctx: AttemptContext,

    /// The spawned attempt tasks.
    tasks: JoinSet<AttemptOutcome>,

    /// Accounts with a running attempt, keyed by task id. These occupy the attempt slots.
    running: HashMap<Id, AccountId>,

    /// Accounts with a submitted transaction awaiting commitment. These do not occupy an attempt
    /// slot (no work is being computed locally) but are excluded from selection so an account never
    /// has two transactions in flight.
    in_flight: HashMap<AccountId, Inflight>,

    /// Maximum number of attempts computed concurrently.
    max_concurrent_txs: usize,

    /// Number of blocks after which a submitted transaction expires. An in-flight entry older than
    /// this is dropped, which releases the account for a new attempt.
    tx_expiration_delta: NonZeroU16,
}

impl Scheduler {
    pub fn new(
        ctx: AttemptContext,
        max_concurrent_txs: usize,
        tx_expiration_delta: NonZeroU16,
    ) -> Self {
        Self {
            ctx,
            tasks: JoinSet::new(),
            running: HashMap::new(),
            in_flight: HashMap::new(),
            max_concurrent_txs,
            tx_expiration_delta,
        }
    }

    /// Fills the free attempt slots with accounts that have pending notes.
    ///
    /// Accounts with a running attempt or an in-flight transaction are excluded, so an account
    /// never has two attempts or two submitted transactions at once. `chain` fixes the reference
    /// block for every attempt spawned here.
    #[miden_instrument(
        name = "ntx.scheduler.dispatch",
        fields(tip.number = chain.chain_tip_header.block_num()),
        err,
    )]
    pub async fn dispatch(&mut self, chain: &ChainState) -> anyhow::Result<()> {
        let free = self.max_concurrent_txs.saturating_sub(self.running.len());
        if free == 0 {
            return Ok(());
        }

        let busy = self
            .running
            .values()
            .copied()
            .chain(self.in_flight.keys().copied())
            .collect::<Vec<_>>();

        let block_num = chain.chain_tip_header.block_num();
        let ready = self
            .ctx
            .db
            .ready_accounts(self.ctx.config.max_note_attempts, block_num, busy, free)
            .await
            .context("failed to query accounts ready for a transaction attempt")?;
        for account_id in ready {
            let ctx = self.ctx.clone();
            let chain = chain.clone();
            let handle = self.tasks.spawn(attempt(ctx, account_id, chain));
            self.running.insert(handle.id(), account_id);
            debug!(
                target: LOG_TARGET,
                "dispatched a network transaction attempt",
                account.id = account_id,
                reference_block.number = block_num
            );
        }

        Ok(())
    }

    /// Resolves the in-flight set against a committed block.
    ///
    /// An entry is dropped when the block commits its transaction (the account is free to work
    /// again on the state that transaction produced) or when the submission has been outstanding
    /// for longer than the expiration delta, in which case it can no longer land on-chain.
    pub fn handle_committed_block(&mut self, effects: &CommittedBlockEffects) {
        let tip = effects.header.block_num();
        let committed = effects.latest_tx_per_account();
        let expiration_delta = u32::from(self.tx_expiration_delta.get());

        self.in_flight.retain(|account_id, inflight| {
            if committed.get(account_id) == Some(&inflight.tx_id) {
                info!(
                    target: LOG_TARGET,
                    "submitted network transaction landed",
                    account.id = *account_id,
                    transaction.id = inflight.tx_id,
                    block.number = tip
                );
                return false;
            }

            let elapsed = tip.checked_sub(inflight.submitted_at.as_u32()).unwrap_or_default();
            if elapsed.as_u32() >= expiration_delta {
                info!(
                    target: LOG_TARGET,
                    "submitted network transaction expired",
                    account.id = *account_id,
                    transaction.id = inflight.tx_id,
                    transaction.submitted_at = inflight.submitted_at,
                    tip.number = tip,
                    transaction.expiration_delta = expiration_delta
                );
                return false;
            }

            true
        });
    }

    /// Waits for the next attempt to complete.
    ///
    /// Waits indefinitely while no attempt is running, so this is safe to poll in a `select!`
    /// alongside the block stream. An attempt task that does not return an outcome has panicked,
    /// which is a bug rather than a state the scheduler can recover from, so the error is
    /// propagated and ends the event loop.
    pub async fn next_completion(&mut self) -> anyhow::Result<AttemptOutcome> {
        loop {
            match self.tasks.join_next_with_id().await {
                Some(Ok((id, outcome))) => {
                    self.running.remove(&id);
                    return Ok(outcome);
                },
                Some(Err(err)) => {
                    let account_id = self.running.remove(&err.id());
                    // Cancelled tasks were aborted on shutdown.
                    if err.is_cancelled() {
                        continue;
                    }
                    return Err(err).with_context(|| {
                        format!(
                            "network transaction attempt failed for account {}",
                            format_opt(account_id.as_ref())
                        )
                    });
                },
                // No attempt is running. Wait until one is spawned and completes.
                None => std::future::pending().await,
            }
        }
    }

    /// Persists what an attempt reported and returns whether the freed slot should be refilled now.
    ///
    /// A slot is refilled immediately after an attempt that made progress, so a completed
    /// transaction does not leave capacity idle until the next block. An attempt that found no
    /// viable work, or that could not run at all, does not trigger a refill: the state that
    /// selected its account has not changed, so an immediate re-dispatch could pick the same
    /// account again.
    pub async fn handle_completion(
        &mut self,
        db: &NtxDbWriter,
        outcome: AttemptOutcome,
    ) -> anyhow::Result<bool> {
        let AttemptOutcome { account_id, block_num, notes, result } = outcome;
        self.persist_note_updates(db, block_num, notes).await?;

        match result {
            AttemptResult::Submitted { tx_id } => {
                info!(
                    target: LOG_TARGET,
                    "network transaction submitted; account is in flight",
                    account.id = account_id,
                    transaction.id = tx_id,
                    transaction.submitted_at = block_num
                );
                self.in_flight.insert(account_id, Inflight { tx_id, submitted_at: block_num });
                Ok(true)
            },
            AttemptResult::Failed => Ok(true),
            AttemptResult::NoWork => {
                debug!(
                    target: LOG_TARGET,
                    "no viable notes for account",
                    account.id = account_id
                );
                Ok(false)
            },
            AttemptResult::Aborted(err) => {
                error!(
                    &err,
                    target: LOG_TARGET,
                    "network transaction attempt could not run",
                    account.id = account_id
                );
                Ok(false)
            },
        }
    }

    /// Writes the note bookkeeping an attempt produced.
    async fn persist_note_updates(
        &self,
        db: &NtxDbWriter,
        block_num: BlockNumber,
        notes: NoteUpdates,
    ) -> anyhow::Result<()> {
        let NoteUpdates { failed, discarded, scripts, eligibility } = notes;

        // Applied before the failures so a note that is both corrected and penalized keeps the
        // backoff block the penalty computes, which is the later of the two.
        if !eligibility.is_empty() {
            db.update_note_eligibility(eligibility)
                .await
                .context("failed to correct note eligibility")?;
        }
        if !failed.is_empty() {
            db.notes_failed(failed, block_num)
                .await
                .context("failed to persist note failures")?;
        }
        if !discarded.is_empty() {
            db.discard_notes(discarded, block_num, self.ctx.config.max_note_attempts)
                .await
                .context("failed to discard notes")?;
        }
        for (script_root, script) in scripts {
            db.insert_note_scripts(script_root, script)
                .await
                .context("failed to cache note script")?;
        }

        Ok(())
    }

    /// Aborts every outstanding attempt and waits for the tasks to finish.
    ///
    /// An aborted attempt loses its note bookkeeping. Its notes stay pending, and a transaction it
    /// already submitted either lands (its notes are then marked consumed from the committed block)
    /// or expires on-chain.
    pub async fn shutdown(&mut self) {
        self.tasks.shutdown().await;
        self.running.clear();
        self.in_flight.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use miden_protocol::account::AccountUpdateDetails;

    use super::*;
    use crate::NoteError;
    use crate::test_utils::{
        mock_block_header,
        mock_network_account_id,
        mock_network_account_id_seeded,
        mock_transaction_id,
    };

    /// Builds a scheduler backed by a temp database. The attempt context points at unreachable
    /// endpoints, which is enough for the scheduling logic under test (no attempt is spawned).
    async fn test_scheduler() -> (Scheduler, NtxDbWriter, tempfile::TempDir) {
        let (db, dir) = crate::db::test_setup().await;
        let ctx = AttemptContext::test(&db.reader());
        (Scheduler::new(ctx, 4, NonZeroU16::new(30).unwrap()), db, dir)
    }

    /// Effects for a block carrying nothing but its header.
    fn empty_effects(block_num: u32) -> CommittedBlockEffects {
        CommittedBlockEffects {
            header: mock_block_header(block_num.into()),
            network_notes: vec![],
            sponsorship_notes: vec![],
            nullifiers: vec![],
            network_account_updates: vec![],
            account_transactions: vec![],
        }
    }

    #[tokio::test]
    async fn landed_transaction_releases_the_account() {
        let (mut scheduler, _db, _dir) = test_scheduler().await;
        let account_id = mock_network_account_id();
        let tx_id = mock_transaction_id(1);

        scheduler
            .in_flight
            .insert(account_id, Inflight { tx_id, submitted_at: 1_u32.into() });

        let mut effects = empty_effects(2);
        effects.account_transactions = vec![(account_id, tx_id)];
        scheduler.handle_committed_block(&effects);

        assert!(
            scheduler.in_flight.is_empty(),
            "the block committing the submission must release the account",
        );
    }

    /// A block that commits a *different* transaction for the account leaves the entry in place:
    /// the submission may still land in a later block.
    #[tokio::test]
    async fn unrelated_transaction_keeps_the_account_in_flight() {
        let (mut scheduler, _db, _dir) = test_scheduler().await;
        let account_id = mock_network_account_id();

        scheduler.in_flight.insert(
            account_id,
            Inflight {
                tx_id: mock_transaction_id(1),
                submitted_at: 1_u32.into(),
            },
        );

        let mut effects = empty_effects(2);
        effects.account_transactions = vec![(account_id, mock_transaction_id(9))];
        scheduler.handle_committed_block(&effects);

        assert!(scheduler.in_flight.contains_key(&account_id));
    }

    #[tokio::test]
    async fn expired_submission_releases_the_account() {
        let (mut scheduler, _db, _dir) = test_scheduler().await;
        let account_id = mock_network_account_id();

        scheduler.in_flight.insert(
            account_id,
            Inflight {
                tx_id: mock_transaction_id(1),
                submitted_at: 1_u32.into(),
            },
        );

        // One block short of the delta: still waiting.
        scheduler.handle_committed_block(&empty_effects(30));
        assert!(scheduler.in_flight.contains_key(&account_id));

        // The delta has now fully elapsed, so the submission can no longer land.
        scheduler.handle_committed_block(&empty_effects(31));
        assert!(scheduler.in_flight.is_empty());
    }

    /// The slot budget counts running attempts only. An in-flight transaction blocks its own
    /// account but does not consume a slot, because no work is being computed for it locally.
    #[tokio::test]
    async fn in_flight_accounts_are_excluded_but_do_not_occupy_a_slot() {
        let (mut scheduler, db, _dir) = test_scheduler().await;
        let in_flight_account = mock_network_account_id();
        let other_account = mock_network_account_id_seeded(42);

        for account_id in [in_flight_account, other_account] {
            db.upsert_account_for_test(
                account_id,
                crate::test_utils::mock_account(account_id),
                mock_transaction_id(0),
            )
            .await
            .unwrap();
            db.insert_network_notes(vec![crate::test_utils::mock_single_target_note(
                account_id, 1,
            )])
            .await
            .unwrap();
        }

        scheduler.in_flight.insert(
            in_flight_account,
            Inflight {
                tx_id: mock_transaction_id(1),
                submitted_at: 1_u32.into(),
            },
        );

        let ready = db
            .ready_accounts(
                30,
                BlockNumber::from(1),
                vec![in_flight_account],
                scheduler.max_concurrent_txs,
            )
            .await
            .unwrap();

        assert_eq!(ready, vec![other_account], "an in-flight account is not selected again");
    }

    /// An account with pending notes but no committed state is not a candidate. The join against
    /// `accounts` in the query is the only gate on account state.
    #[tokio::test]
    async fn uncommitted_accounts_are_not_ready() {
        let (_scheduler, db, _dir) = test_scheduler().await;
        let account_id = mock_network_account_id();

        db.insert_network_notes(vec![crate::test_utils::mock_single_target_note(account_id, 1)])
            .await
            .unwrap();

        assert!(
            db.ready_accounts(30, BlockNumber::from(1), vec![], 4).await.unwrap().is_empty(),
            "a note targeting an account with no committed state is not dispatchable",
        );

        db.upsert_account_for_test(
            account_id,
            crate::test_utils::mock_account(account_id),
            mock_transaction_id(0),
        )
        .await
        .unwrap();

        assert_eq!(
            db.ready_accounts(30, BlockNumber::from(1), vec![], 4).await.unwrap(),
            vec![account_id],
            "the account becomes dispatchable once its state is committed",
        );
    }

    /// The note bookkeeping an attempt reports is persisted whatever the result, and a submission
    /// puts the account in flight.
    #[tokio::test]
    async fn submitted_outcome_persists_notes_and_records_the_submission() {
        let (mut scheduler, db, _dir) = test_scheduler().await;
        let account_id = mock_network_account_id();
        let failed_note = crate::test_utils::mock_single_target_note(account_id, 1);
        let discarded_note = crate::test_utils::mock_single_target_note(account_id, 2);
        db.insert_network_notes(vec![failed_note.clone(), discarded_note.clone()])
            .await
            .unwrap();

        let tx_id = mock_transaction_id(3);
        let error: NoteError = Arc::new(std::io::Error::other("boom"));
        let outcome = AttemptOutcome {
            account_id,
            block_num: 7_u32.into(),
            notes: NoteUpdates {
                failed: vec![(failed_note.as_note().nullifier(), error)],
                discarded: vec![discarded_note.as_note().nullifier()],
                eligibility: vec![],
                scripts: vec![],
            },
            result: AttemptResult::Submitted { tx_id },
        };

        let refill = scheduler.handle_completion(&db, outcome).await.unwrap();

        assert!(refill, "a submission frees a slot that should be refilled immediately");
        assert!(scheduler.in_flight.contains_key(&account_id));

        let failed = db.get_note_status(failed_note.as_note().id()).await.unwrap().unwrap();
        assert_eq!(failed.attempt_count, 1);
        let discarded = db.get_note_status(discarded_note.as_note().id()).await.unwrap().unwrap();
        assert_eq!(discarded.attempt_count, 30, "a discarded note is pinned to the attempt cap");
    }

    /// An attempt that found no viable work must not trigger an immediate re-dispatch, because
    /// nothing about its account changed.
    #[tokio::test]
    async fn no_work_outcome_does_not_refill_the_slot() {
        let (mut scheduler, db, _dir) = test_scheduler().await;
        let outcome = AttemptOutcome {
            account_id: mock_network_account_id(),
            block_num: 1_u32.into(),
            notes: NoteUpdates::default(),
            result: AttemptResult::NoWork,
        };

        let refill = scheduler.handle_completion(&db, outcome).await.unwrap();

        assert!(!refill);
        assert!(scheduler.in_flight.is_empty());
    }

    /// A block that only updates an account (without a note for it) leaves the in-flight set alone.
    #[tokio::test]
    async fn account_update_alone_does_not_resolve_an_in_flight_entry() {
        let (mut scheduler, _db, _dir) = test_scheduler().await;
        let account_id = mock_network_account_id();
        scheduler.in_flight.insert(
            account_id,
            Inflight {
                tx_id: mock_transaction_id(1),
                submitted_at: 1_u32.into(),
            },
        );

        let mut effects = empty_effects(2);
        effects.network_account_updates = vec![(account_id, AccountUpdateDetails::Private)];
        scheduler.handle_committed_block(&effects);

        assert!(scheduler.in_flight.contains_key(&account_id));
    }
}
