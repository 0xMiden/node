//! Block-driven scheduler for network transactions.
//!
//! The scheduler owns the build tasks and decides which accounts to work on. It keeps no
//! per-account state beyond the in-flight set, which records the transactions it has submitted but
//! not yet seen committed. Everything else that decides "what to work on next" is read from the
//! database on every dispatch.

use std::collections::HashMap;
use std::num::NonZeroU16;

use anyhow::Context;
use miden_node_tracing::{debug, error, info, miden_instrument};
use miden_node_utils::tasks::Tasks;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::TransactionId;

use crate::LOG_TARGET;
use crate::chain_state::ChainState;
use crate::committed_block::CommittedBlockEffects;
use crate::db::NtxDbWriter;
use crate::network_transaction::{
    NetworkTransactionContext,
    NetworkTransactionOutcome,
    NetworkTransactionResult,
    NoteUpdates,
};

// SCHEDULER STATE
// ================================================================================================

/// A transaction the scheduler submitted and has not yet seen committed.
struct Inflight {
    /// Id of the submitted transaction, compared against each block's committed transactions.
    tx_id: TransactionId,
    /// First block at which the transaction can no longer be included in a block. The transaction
    /// carries the same expiration on-chain, so this bounds how long the account stays blocked when
    /// the submission never lands.
    expires_at: BlockNumber,
}

// SCHEDULER CONFIG
// ================================================================================================

/// Configuration knobs of the [`Scheduler`].
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum number of network transactions built concurrently.
    pub max_concurrent_txs: usize,

    /// Number of blocks after which a submitted transaction expires. This sets the expiration block
    /// of an in-flight transaction at submission, and must match the expiration delta the
    /// transaction carries on-chain.
    pub tx_expiration_delta: NonZeroU16,

    /// Accounts served before every other account. Each one still holds at most one slot, because
    /// an account with a running build is excluded from selection.
    pub priority_accounts: Vec<AccountId>,
}

// SCHEDULER
// ================================================================================================

/// Spawns and reaps network transaction builds.
///
/// The scheduler is driven from the builder's event loop at three moments:
///
/// 1. On every committed block, [`Scheduler::handle_committed_block`] resolves the in-flight set
///    (landed or expired) and [`Scheduler::dispatch`] fills the free build slots.
/// 2. Whenever a build completes, [`Scheduler::handle_completion`] persists what the build
///    reported and says whether the freed slot should be refilled immediately.
/// 3. On shutdown, [`Scheduler::shutdown`] aborts the outstanding builds.
pub struct Scheduler {
    /// Resources cloned into every spawned build.
    ctx: NetworkTransactionContext,

    /// The spawned build tasks, each tagged with the account it builds for. These occupy the build
    /// slots.
    tasks: Tasks<NetworkTransactionOutcome, AccountId>,

    /// Accounts with a submitted transaction awaiting commitment. These do not occupy a build slot
    /// (no work is being computed locally) but are excluded from selection so an account never has
    /// two transactions in flight.
    in_flight: HashMap<AccountId, Inflight>,

    /// Configuration knobs of the scheduler.
    config: SchedulerConfig,
}

impl Scheduler {
    pub fn new(ctx: NetworkTransactionContext, config: SchedulerConfig) -> Self {
        Self {
            ctx,
            tasks: Tasks::new(),
            in_flight: HashMap::new(),
            config,
        }
    }

    /// Fills the free build slots with accounts that have pending notes.
    ///
    /// Accounts with a running build or an in-flight transaction are excluded, so an account never
    /// has two builds or two submitted transactions at once. `chain` fixes the reference block for
    /// every build spawned here.
    #[miden_instrument(
        name = "ntx.scheduler.dispatch",
        fields(tip.number = chain.chain_tip_header.block_num()),
        err,
    )]
    pub async fn dispatch(&mut self, chain: &ChainState) -> anyhow::Result<()> {
        let free = self.config.max_concurrent_txs.saturating_sub(self.tasks.len());
        if free == 0 {
            return Ok(());
        }

        let busy = self
            .tasks
            .tags()
            .copied()
            .chain(self.in_flight.keys().copied())
            .collect::<Vec<_>>();

        let block_num = chain.chain_tip_header.block_num();
        let ready = self
            .ctx
            .db
            .ready_accounts(
                self.ctx.config.max_note_attempts,
                block_num,
                busy,
                self.config.priority_accounts.clone(),
                free,
            )
            .await
            .context("failed to query accounts ready for a network transaction")?;
        let dispatched = ready.len();
        for account_id in ready {
            let ctx = self.ctx.clone();
            let chain = chain.clone();
            self.tasks.spawn(account_id, ctx.build(account_id, chain));
            debug!(
                target: LOG_TARGET,
                "dispatched a network transaction build",
                account.id = account_id,
                reference_block.number = block_num
            );
        }

        // Neither the build concurrency nor the submitted-but-uncommitted backlog is otherwise
        // observable from outside the process.
        debug!(
            target: LOG_TARGET,
            "network transaction pipeline",
            reference_block.number = block_num,
            build.dispatched.count = dispatched,
            build.running.count = self.tasks.len(),
            transaction.in_flight.count = self.in_flight.len(),
            build.slots.count = self.config.max_concurrent_txs
        );

        Ok(())
    }

    /// Resolves the in-flight set against a committed block.
    ///
    /// An entry is dropped when the block commits its transaction (the account is free to work
    /// again on the state that transaction produced) or when the transaction has expired, in which
    /// case it can no longer land on-chain.
    pub fn handle_committed_block(&mut self, effects: &CommittedBlockEffects) {
        let tip = effects.header.block_num();
        let committed = effects.latest_tx_per_account();

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

            if tip >= inflight.expires_at {
                info!(
                    target: LOG_TARGET,
                    "submitted network transaction expired",
                    account.id = *account_id,
                    transaction.id = inflight.tx_id,
                    transaction.expires_at = inflight.expires_at,
                    tip.number = tip
                );
                return false;
            }

            true
        });
    }

    /// Waits for the next build to complete.
    ///
    /// Waits indefinitely while no build is running, so this is safe to poll in a `select!`
    /// alongside the block stream. A build task that does not return an outcome has panicked,
    /// which is a bug rather than a state the scheduler can recover from, so the error is
    /// propagated and ends the event loop. A task is only aborted by [`Scheduler::shutdown`], which
    /// consumes the scheduler and joins the tasks itself, so a cancelled task never reaches here.
    pub async fn next_completion(&mut self) -> anyhow::Result<NetworkTransactionOutcome> {
        match self.tasks.join_next().await {
            Some((_, Ok(outcome))) => Ok(outcome),
            Some((account_id, Err(err))) => Err(err).with_context(|| {
                format!("network transaction build failed for account {account_id}")
            }),
            // No build is running. Wait until one is spawned and completes.
            None => std::future::pending().await,
        }
    }

    /// Persists what a build reported. Returns `true` when the slot it freed can be refilled at
    /// once.
    pub async fn handle_completion(
        &mut self,
        db: &NtxDbWriter,
        outcome: NetworkTransactionOutcome,
    ) -> anyhow::Result<bool> {
        let NetworkTransactionOutcome { account_id, block_num, notes, result } = outcome;
        self.persist_note_updates(db, block_num, notes).await?;

        match result {
            NetworkTransactionResult::Submitted { tx_id } => {
                let expires_at = block_num + u32::from(self.config.tx_expiration_delta.get());
                info!(
                    target: LOG_TARGET,
                    "network transaction submitted; account is in flight",
                    account.id = account_id,
                    transaction.id = tx_id,
                    transaction.submitted_at = block_num,
                    transaction.expires_at = expires_at
                );
                self.in_flight.insert(account_id, Inflight { tx_id, expires_at });
                Ok(true)
            },
            NetworkTransactionResult::Failed => Ok(true),
            NetworkTransactionResult::NoWork => {
                debug!(
                    target: LOG_TARGET,
                    "no viable notes for account",
                    account.id = account_id
                );
                // The state which selected this account did not change, so an immediate re-dispatch
                // can pick the same account again.
                Ok(false)
            },
            NetworkTransactionResult::Aborted(err) => {
                error!(
                    &err,
                    target: LOG_TARGET,
                    "network transaction build could not run",
                    account.id = account_id
                );
                // The account was not worked on, so nothing changed which could make an immediate
                // re-dispatch pick a different one.
                Ok(false)
            },
        }
    }

    /// Writes the note bookkeeping a build produced.
    async fn persist_note_updates(
        &self,
        db: &NtxDbWriter,
        block_num: BlockNumber,
        notes: NoteUpdates,
    ) -> anyhow::Result<()> {
        let NoteUpdates { failed, discarded, scripts, eligibility } = notes;

        // A correction moves a note whose stored eligibility block is earlier than the exact rule
        // allows. The account is selected on every block until the correction is written. See
        // `crate::db::eligibility`.
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

    /// Aborts every outstanding build, waits for the tasks to finish and consumes the scheduler.
    ///
    /// An aborted build loses its note bookkeeping. Its notes stay pending, and a transaction it
    /// already submitted either lands (its notes are then marked consumed from the committed block)
    /// or expires on-chain.
    pub async fn shutdown(mut self) {
        self.tasks.shutdown().await;
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

    /// Builds a scheduler backed by a temp database. The context points at unreachable endpoints,
    /// which is enough for the scheduling logic under test (no build is spawned).
    async fn test_scheduler() -> (Scheduler, NtxDbWriter, tempfile::TempDir) {
        let (db, dir) = crate::db::test_setup().await;
        let ctx = NetworkTransactionContext::test(&db.reader());
        let config = SchedulerConfig {
            max_concurrent_txs: 4,
            tx_expiration_delta: NonZeroU16::new(30).unwrap(),
            priority_accounts: Vec::new(),
        };
        (Scheduler::new(ctx, config), db, dir)
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
            .insert(account_id, Inflight { tx_id, expires_at: 31_u32.into() });

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
                expires_at: 31_u32.into(),
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
                expires_at: 31_u32.into(),
            },
        );

        // One block short of the expiration block: still waiting.
        scheduler.handle_committed_block(&empty_effects(30));
        assert!(scheduler.in_flight.contains_key(&account_id));

        // The expiration block is reached, so the submission can no longer land.
        scheduler.handle_committed_block(&empty_effects(31));
        assert!(scheduler.in_flight.is_empty());
    }

    /// The slot budget counts running builds only. An in-flight transaction blocks its own account
    /// but does not consume a slot, because no work is being computed for it locally.
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
                expires_at: 31_u32.into(),
            },
        );

        let ready = db
            .ready_accounts(
                30,
                BlockNumber::from(1),
                vec![in_flight_account],
                Vec::new(),
                scheduler.config.max_concurrent_txs,
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
            db.ready_accounts(30, BlockNumber::from(1), vec![], vec![], 4)
                .await
                .unwrap()
                .is_empty(),
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
            db.ready_accounts(30, BlockNumber::from(1), vec![], vec![], 4).await.unwrap(),
            vec![account_id],
            "the account becomes dispatchable once its state is committed",
        );
    }

    /// The note bookkeeping a build reports is persisted whatever the result, and a submission puts
    /// the account in flight.
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
        let outcome = NetworkTransactionOutcome {
            account_id,
            block_num: 7_u32.into(),
            notes: NoteUpdates {
                failed: vec![(failed_note.as_note().nullifier(), error)],
                discarded: vec![discarded_note.as_note().nullifier()],
                eligibility: vec![],
                scripts: vec![],
            },
            result: NetworkTransactionResult::Submitted { tx_id },
        };

        let refill = scheduler.handle_completion(&db, outcome).await.unwrap();

        assert!(refill, "a submission frees a slot that should be refilled immediately");
        assert!(scheduler.in_flight.contains_key(&account_id));

        let failed = db.get_note_status(failed_note.as_note().id()).await.unwrap().unwrap();
        assert_eq!(failed.attempt_count, 1);
        let discarded = db.get_note_status(discarded_note.as_note().id()).await.unwrap().unwrap();
        assert_eq!(discarded.attempt_count, 30, "a discarded note is pinned to the attempt cap");
    }

    /// A build that found no viable work must not trigger an immediate re-dispatch, because nothing
    /// about its account changed.
    #[tokio::test]
    async fn no_work_outcome_does_not_refill_the_slot() {
        let (mut scheduler, db, _dir) = test_scheduler().await;
        let outcome = NetworkTransactionOutcome {
            account_id: mock_network_account_id(),
            block_num: 1_u32.into(),
            notes: NoteUpdates::default(),
            result: NetworkTransactionResult::NoWork,
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
                expires_at: 31_u32.into(),
            },
        );

        let mut effects = empty_effects(2);
        effects.network_account_updates = vec![(account_id, AccountUpdateDetails::Private)];
        scheduler.handle_committed_block(&effects);

        assert!(scheduler.in_flight.contains_key(&account_id));
    }
}
