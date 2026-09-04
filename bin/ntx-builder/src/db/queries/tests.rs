//! DB-level tests for the committed-block-driven query layer.
//!
//! Each query runs through the [`NtxDb`](crate::db::NtxDb) wrapper (production methods where they
//! exist, test-only helpers otherwise), so every write commits before the following read observes
//! it.

use std::sync::Arc;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use miden_protocol::note::NoteId;
use miden_protocol::transaction::TransactionId;
use miden_standards::note::NoteExecutionHint;

use crate::NoteError;
use crate::committed_block::CommittedBlockEffects;
use crate::db::eligibility::{NEVER_ELIGIBLE, eligible_block_after_failure};
use crate::db::test_setup;
use crate::sponsorship::SponsorshipNote;
use crate::test_utils::*;

// TEST HARNESS
// ================================================================================================

/// Creates a [`NoteError`] from a string message, for use in tests.
fn test_note_error(msg: &str) -> NoteError {
    Arc::new(std::io::Error::other(msg.to_string()))
}

// ACCOUNT UPSERT
// ================================================================================================

#[tokio::test]
async fn upsert_account_replaces_existing_row() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let account = mock_account(account_id);

    db.upsert_account_for_test(account_id, account.clone(), mock_transaction_id(1))
        .await
        .unwrap();
    db.upsert_account_for_test(account_id, account, mock_transaction_id(2))
        .await
        .unwrap();

    assert_eq!(db.count_accounts().await, 1, "second upsert must overwrite, not insert");
    assert!(db.get_account(account_id).await.unwrap().is_some());
}

// NETWORK NOTE INSERT/DELETE
// ================================================================================================

#[tokio::test]
async fn insert_network_notes_is_idempotent() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 7);

    db.insert_network_notes(vec![note.clone()]).await.unwrap();
    // Re-applying the same block (e.g. on a subscription redelivery) must not error or duplicate.
    db.insert_network_notes(vec![note]).await.unwrap();

    assert_eq!(db.count_notes().await, 1);
}

#[tokio::test]
async fn mark_notes_consumed_keeps_rows_and_sets_committed_at() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note_a = mock_single_target_note(account_id, 1);
    let note_b = mock_single_target_note(account_id, 2);

    db.insert_network_notes(vec![note_a.clone(), note_b.clone()]).await.unwrap();
    assert_eq!(db.count_notes().await, 2);

    let consumed_at = BlockNumber::from(42);
    db.mark_notes_consumed(vec![note_a.as_note().nullifier()], consumed_at)
        .await
        .unwrap();

    // Both rows are still present so the gRPC status endpoint can report them.
    assert_eq!(db.count_notes().await, 2);

    let status_a = db.get_note_status(note_a.as_note().id()).await.unwrap().unwrap();
    assert_eq!(status_a.committed_at, Some(i64::from(consumed_at.as_u32())));

    let status_b = db.get_note_status(note_b.as_note().id()).await.unwrap().unwrap();
    assert!(status_b.committed_at.is_none());
}

#[tokio::test]
async fn mark_notes_consumed_is_noop_when_unknown() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 3);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    // A nullifier we never inserted should not affect existing rows.
    let phantom = mock_single_target_note(account_id, 99).as_note().nullifier();
    db.mark_notes_consumed(vec![phantom], BlockNumber::from(5)).await.unwrap();

    assert_eq!(db.count_notes().await, 1);
    let status = db.get_note_status(note.as_note().id()).await.unwrap().unwrap();
    assert!(status.committed_at.is_none());
}

#[tokio::test]
async fn available_notes_excludes_consumed_notes() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 21);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    assert_eq!(
        db.available_notes(account_id, BlockNumber::from(1), 30)
            .await
            .unwrap()
            .eligible
            .len(),
        1
    );

    db.mark_notes_consumed(vec![note.as_note().nullifier()], BlockNumber::from(7))
        .await
        .unwrap();

    assert!(
        db.available_notes(account_id, BlockNumber::from(1000), 30)
            .await
            .unwrap()
            .eligible
            .is_empty()
    );
}

// SPONSORSHIP NOTES
// ================================================================================================

/// Builds a [`SponsorshipNote`](crate::sponsorship::SponsorshipNote) bound to the given feature
/// note id.
fn sponsorship_for(target: AccountId, feature_note_id: NoteId, seed: u8) -> SponsorshipNote {
    let note = mock_sponsorship_note(target, feature_note_id, seed);
    SponsorshipNote::try_from(note).expect("mock sponsorship note must decode")
}

#[tokio::test]
async fn insert_sponsorship_notes_is_idempotent() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let feature = mock_single_target_note(account_id, 1);
    let sponsorship = sponsorship_for(account_id, feature.as_note().id(), 2);

    db.insert_sponsorship_notes(vec![sponsorship.clone()]).await.unwrap();
    // Re-applying the same block (e.g. on a subscription redelivery) must not error or duplicate.
    db.insert_sponsorship_notes(vec![sponsorship]).await.unwrap();

    assert_eq!(db.count_sponsorship_notes().await, 1);
}

/// The binding is resolved at selection time, so insertion order between a sponsorship and its
/// feature note must not matter.
#[tokio::test]
async fn sponsorships_for_pending_notes_resolves_sponsorship_inserted_before_feature_note() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let feature = mock_single_target_note(account_id, 1);
    let sponsorship = sponsorship_for(account_id, feature.as_note().id(), 2);

    // The sponsorship commits first: it is stored, but unresolved (no feature note row to join).
    db.insert_sponsorship_notes(vec![sponsorship]).await.unwrap();
    assert!(db.sponsorships_for_pending_notes(account_id).await.unwrap().is_empty());

    // Once the feature note commits, the join finds the pair.
    db.insert_network_notes(vec![feature.clone()]).await.unwrap();
    let pending = db.sponsorships_for_pending_notes(account_id).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[&feature.as_note().id()].len(), 1);
}

/// A feature note may have any number of sponsorships; all unconsumed ones are returned together.
#[tokio::test]
async fn sponsorships_for_pending_notes_groups_multiple_per_feature_note() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let feature = mock_single_target_note(account_id, 1);
    let feature_id = feature.as_note().id();

    db.insert_network_notes(vec![feature]).await.unwrap();
    db.insert_sponsorship_notes(vec![
        sponsorship_for(account_id, feature_id, 2),
        sponsorship_for(account_id, feature_id, 3),
    ])
    .await
    .unwrap();

    let pending = db.sponsorships_for_pending_notes(account_id).await.unwrap();
    assert_eq!(pending[&feature_id].len(), 2);
}

/// A consumed sponsorship (spent alongside its feature note or reclaimed externally) must never be
/// attached again; a consumed feature note must not pull its sponsorships either.
#[tokio::test]
async fn sponsorships_for_pending_notes_excludes_consumed_rows() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let feature_a = mock_single_target_note(account_id, 1);
    let feature_b = mock_single_target_note(account_id, 2);
    let sponsorship_a = sponsorship_for(account_id, feature_a.as_note().id(), 3);
    let sponsorship_b = sponsorship_for(account_id, feature_b.as_note().id(), 4);

    db.insert_network_notes(vec![feature_a.clone(), feature_b.clone()])
        .await
        .unwrap();
    db.insert_sponsorship_notes(vec![sponsorship_a.clone(), sponsorship_b])
        .await
        .unwrap();
    assert_eq!(db.sponsorships_for_pending_notes(account_id).await.unwrap().len(), 2);

    // Sponsorship A is reclaimed externally: only the pair around feature B remains.
    db.mark_sponsorships_consumed(vec![sponsorship_a.nullifier()], BlockNumber::from(7))
        .await
        .unwrap();
    let pending = db.sponsorships_for_pending_notes(account_id).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending.contains_key(&feature_b.as_note().id()));

    // Feature B is consumed: nothing is pending, but the rows are retained for status reporting.
    db.mark_notes_consumed(vec![feature_b.as_note().nullifier()], BlockNumber::from(8))
        .await
        .unwrap();
    assert!(db.sponsorships_for_pending_notes(account_id).await.unwrap().is_empty());
    assert_eq!(db.count_sponsorship_notes().await, 2);
}

/// A sponsorship bound to a feature note targeting a different account must not leak into this
/// account's pending set: the join goes through `notes.account_id`, not the sponsorship's tag.
#[tokio::test]
async fn sponsorships_for_pending_notes_binds_by_feature_note_not_tag() {
    let (db, _dir) = test_setup().await;
    let alice = mock_network_account_id();
    let bob = mock_network_account_id_seeded(42);
    let feature = mock_single_target_note(bob, 1);
    // Tagged for alice, but bound to a feature note targeting bob.
    let sponsorship = sponsorship_for(alice, feature.as_note().id(), 2);

    db.insert_network_notes(vec![feature.clone()]).await.unwrap();
    db.insert_sponsorship_notes(vec![sponsorship]).await.unwrap();

    assert!(db.sponsorships_for_pending_notes(alice).await.unwrap().is_empty());
    let pending = db.sponsorships_for_pending_notes(bob).await.unwrap();
    assert_eq!(pending[&feature.as_note().id()].len(), 1);
}

// NOTE ELIGIBILITY
// ================================================================================================
//
// Every write path that touches a note must store exactly what `db::eligibility` computes. These
// tests compare the stored column against the helpers, which is what lets the column stand in for
// the read-time check.

#[tokio::test]
async fn ingestion_stores_the_hint_derived_eligibility() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let created_at = BlockNumber::from(40);

    let unconstrained = mock_single_target_note(account_id, 1);
    let windowed = mock_single_target_note_with_hint(
        account_id,
        2,
        NoteExecutionHint::after_block(BlockNumber::from(100)),
    );
    let past_window = mock_single_target_note_with_hint(
        account_id,
        3,
        NoteExecutionHint::after_block(BlockNumber::from(7)),
    );

    db.insert_network_notes_at(
        vec![unconstrained.clone(), windowed.clone(), past_window.clone()],
        created_at,
    )
    .await
    .unwrap();

    assert_eq!(
        db.note_eligibility(unconstrained.as_note().id()).await,
        Some(created_at),
        "a note with no window is eligible in the block that created it",
    );
    assert_eq!(
        db.note_eligibility(windowed.as_note().id()).await,
        Some(BlockNumber::from(100)),
        "a note inside a future window waits for the window to open",
    );
    assert_eq!(
        db.note_eligibility(past_window.as_note().id()).await,
        Some(created_at),
        "a window that already opened does not move the note into the past",
    );
}

#[tokio::test]
async fn failure_stores_the_backoff_derived_eligibility() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 1);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    let failed_at = BlockNumber::from(50);
    for attempt in 1..=3_usize {
        db.notes_failed(vec![(note.as_note().nullifier(), test_note_error("boom"))], failed_at)
            .await
            .unwrap();

        assert_eq!(
            db.note_eligibility(note.as_note().id()).await,
            Some(eligible_block_after_failure(note.execution_hint(), attempt, failed_at)),
            "the stored block must match the backoff for the attempt count after the increment",
        );
    }
}

#[tokio::test]
async fn discard_pins_eligibility_beyond_every_block() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 1);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    db.discard_notes(vec![note.as_note().nullifier()], BlockNumber::from(9), 30)
        .await
        .unwrap();

    assert_eq!(db.note_eligibility(note.as_note().id()).await, Some(NEVER_ELIGIBLE));
}

/// A sponsorship arriving for a backed-off feature note makes the note eligible again.
#[tokio::test]
async fn arriving_sponsorship_clears_the_feature_note_backoff() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let feature = mock_single_target_note(account_id, 1);
    db.insert_network_notes(vec![feature.clone()]).await.unwrap();

    // The feature note failed, so it is waiting out a backoff.
    db.notes_failed(
        vec![(feature.as_note().nullifier(), test_note_error("fee not covered"))],
        BlockNumber::from(10),
    )
    .await
    .unwrap();
    let backed_off = db.note_eligibility(feature.as_note().id()).await.unwrap();
    assert!(backed_off > BlockNumber::from(10));

    let sponsorship_block = BlockNumber::from(11);
    let effects = CommittedBlockEffects {
        header: mock_block_header(sponsorship_block),
        network_notes: vec![],
        sponsorship_notes: vec![mock_sponsorship(account_id, feature.as_note().id(), 2)],
        nullifiers: vec![],
        network_account_updates: vec![],
        account_transactions: vec![],
    };
    db.apply_committed_block(effects, PartialMmr::default()).await.unwrap();

    assert_eq!(
        db.note_eligibility(feature.as_note().id()).await,
        Some(sponsorship_block),
        "the sponsorship is new information, so the note deserves an attempt now",
    );
}

/// A sponsorship for a note that is already consumed changes nothing.
#[tokio::test]
async fn arriving_sponsorship_ignores_consumed_feature_notes() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let feature = mock_single_target_note(account_id, 1);
    db.insert_network_notes(vec![feature.clone()]).await.unwrap();
    db.mark_notes_consumed(vec![feature.as_note().nullifier()], BlockNumber::from(5))
        .await
        .unwrap();

    let effects = CommittedBlockEffects {
        header: mock_block_header(BlockNumber::from(6)),
        network_notes: vec![],
        sponsorship_notes: vec![mock_sponsorship(account_id, feature.as_note().id(), 2)],
        nullifiers: vec![],
        network_account_updates: vec![],
        account_transactions: vec![],
    };
    db.apply_committed_block(effects, PartialMmr::default()).await.unwrap();

    assert_eq!(
        db.note_eligibility(feature.as_note().id()).await,
        Some(BlockNumber::GENESIS),
        "a consumed note keeps the eligibility it was ingested with",
    );
}

/// The stored block can be too permissive: a periodic window that was open when the value was
/// written closes again later. Selection detects that and reports the correction, which
/// `update_note_eligibility` persists so the account stops being selected for the note.
#[tokio::test]
async fn stale_eligibility_is_reported_and_corrected() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let hint = NoteExecutionHint::on_block_slot(8, 4, 0);
    let note = mock_single_target_note_with_hint(account_id, 1, hint);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    assert_eq!(
        db.note_eligibility(note.as_note().id()).await,
        Some(BlockNumber::GENESIS),
        "the window is open at the block that created the note",
    );

    // The window has closed again by block 100, so the stored value is now too permissive.
    let available = db.available_notes(account_id, BlockNumber::from(100), 30).await.unwrap();
    assert!(available.eligible.is_empty(), "the exact check rejects the closed window");
    assert_eq!(
        available.stale_eligibility,
        vec![(note.as_note().nullifier(), BlockNumber::from(256))],
        "selection reports the block at which the window opens again",
    );

    db.update_note_eligibility(available.stale_eligibility).await.unwrap();

    assert!(
        db.ready_accounts(30, BlockNumber::from(100), vec![], vec![], 10)
            .await
            .unwrap()
            .is_empty(),
        "once corrected, the account is no longer selected for this note",
    );
}

/// The eligibility column, not just the attempt cap, keeps a backed-off account out of selection.
#[tokio::test]
async fn ready_accounts_respect_the_eligibility_column() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    db.upsert_account_for_test(account_id, mock_account(account_id), mock_transaction_id(1))
        .await
        .unwrap();
    let note = mock_single_target_note(account_id, 1);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    let failed_at = BlockNumber::from(50);
    db.notes_failed(vec![(note.as_note().nullifier(), test_note_error("boom"))], failed_at)
        .await
        .unwrap();
    let eligible_from = db.note_eligibility(note.as_note().id()).await.unwrap();

    assert!(
        db.ready_accounts(30, eligible_from.parent().unwrap(), vec![], vec![], 10)
            .await
            .unwrap()
            .is_empty(),
        "the account is not selected before its note becomes eligible",
    );
    assert_eq!(
        db.ready_accounts(30, eligible_from, vec![], vec![], 10).await.unwrap(),
        vec![account_id],
        "the account is selected again exactly at the stored block",
    );
}

// AVAILABLE NOTES + BACKOFF
// ================================================================================================

#[tokio::test]
async fn available_notes_returns_unconsumed_under_attempt_cap() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 11);
    db.insert_network_notes(vec![note]).await.unwrap();

    let available = db.available_notes(account_id, BlockNumber::from(1), 30).await.unwrap();
    assert_eq!(available.eligible.len(), 1);
}

#[tokio::test]
async fn available_notes_excludes_attempts_at_cap() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 13);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    // Push attempt_count up to the cap.
    let nullifier = note.as_note().nullifier();
    for _ in 0..30 {
        db.notes_failed(vec![(nullifier, test_note_error("boom"))], BlockNumber::from(5))
            .await
            .unwrap();
    }

    let available = db.available_notes(account_id, BlockNumber::from(1000), 30).await.unwrap();
    assert!(
        available.eligible.is_empty(),
        "notes at the attempt cap should not be available"
    );
}

// CHAIN STATE
// ================================================================================================

#[tokio::test]
async fn update_chain_state_tip_persists_and_roundtrips_mmr() {
    let (db, _dir) = test_setup().await;
    let genesis = mock_block_header(BlockNumber::GENESIS);
    let header = mock_block_header(BlockNumber::from(7));
    let mmr = PartialMmr::default();

    db.insert_genesis_chain_state(genesis.clone(), genesis.commitment())
        .await
        .unwrap();
    db.update_chain_state_tip(header.clone(), mmr).await.unwrap();

    let (loaded_num, loaded_header, _loaded_mmr) = db.select_chain_state().await.unwrap().unwrap();
    assert_eq!(loaded_num, header.block_num());
    assert_eq!(loaded_header.block_num(), header.block_num());
}

#[tokio::test]
async fn update_chain_state_tip_keeps_singleton() {
    let (db, _dir) = test_setup().await;
    let genesis = mock_block_header(BlockNumber::GENESIS);
    let header_1 = mock_block_header(BlockNumber::from(1));
    let header_2 = mock_block_header(BlockNumber::from(2));
    let mmr = PartialMmr::default();

    db.insert_genesis_chain_state(genesis.clone(), genesis.commitment())
        .await
        .unwrap();
    db.update_chain_state_tip(header_1, mmr.clone()).await.unwrap();
    db.update_chain_state_tip(header_2.clone(), mmr).await.unwrap();

    let (loaded_num, ..) = db.select_chain_state().await.unwrap().unwrap();
    assert_eq!(loaded_num, header_2.block_num());

    assert_eq!(db.count_chain_state().await, 1, "chain_state must remain a singleton");
}

#[tokio::test]
async fn select_chain_state_returns_none_on_fresh_db() {
    let (db, _dir) = test_setup().await;
    assert!(db.select_chain_state().await.unwrap().is_none());
}

// NOTE SCRIPT CACHE
// ================================================================================================

#[tokio::test]
async fn note_script_cache_roundtrip() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 17);
    let script = note.as_note().script().clone();
    let root: Word = script.root().into();

    assert!(db.lookup_note_script(root).await.unwrap().is_none());
    db.insert_note_scripts(root, script.clone()).await.unwrap();
    assert!(db.lookup_note_script(root).await.unwrap().is_some());

    // Re-insert is idempotent.
    db.insert_note_scripts(root, script).await.unwrap();
}

// READY ACCOUNTS
// ================================================================================================

#[tokio::test]
async fn ready_accounts_are_distinct_and_exclude_consumed_and_capped_notes() {
    let (db, _dir) = test_setup().await;
    let alice = mock_network_account_id();
    let bob = mock_network_account_id_seeded(42);
    let carol = mock_network_account_id_seeded(99);

    for account_id in [alice, bob, carol] {
        db.upsert_account_for_test(account_id, mock_account(account_id), mock_transaction_id(1))
            .await
            .unwrap();
    }

    let alice_note_1 = mock_single_target_note(alice, 1);
    let alice_note_2 = mock_single_target_note(alice, 2);
    let bob_note = mock_single_target_note(bob, 3);
    let carol_note = mock_single_target_note(carol, 4);

    db.insert_network_notes(vec![alice_note_1, alice_note_2, bob_note.clone(), carol_note.clone()])
        .await
        .unwrap();

    // Alice has two notes and must still appear exactly once. Bob's only note is already consumed,
    // so he is excluded.
    db.mark_notes_consumed(vec![bob_note.as_note().nullifier()], BlockNumber::from(7))
        .await
        .unwrap();
    // Carol's note has hit the attempt cap, so she is excluded.
    for _ in 0..30 {
        db.notes_failed(
            vec![(carol_note.as_note().nullifier(), test_note_error("boom"))],
            BlockNumber::from(5),
        )
        .await
        .unwrap();
    }

    let ready = db
        .ready_accounts(30, BlockNumber::from(1000), vec![], vec![], 10)
        .await
        .unwrap();
    assert_eq!(ready, vec![alice], "only alice has a pending note within its attempt budget");
}

/// The limit caps the returned accounts, and the account whose note has waited longest comes first,
/// so attempt slots rotate over the accounts that have work.
#[tokio::test]
async fn ready_accounts_are_limited_and_least_recently_attempted_first() {
    let (db, _dir) = test_setup().await;
    let recent = mock_network_account_id();
    let stale = mock_network_account_id_seeded(42);

    for account_id in [recent, stale] {
        db.upsert_account_for_test(account_id, mock_account(account_id), mock_transaction_id(1))
            .await
            .unwrap();
    }

    let recent_note = mock_single_target_note(recent, 1);
    let stale_note = mock_single_target_note(stale, 2);
    db.insert_network_notes(vec![recent_note.clone(), stale_note.clone()])
        .await
        .unwrap();

    db.notes_failed(
        vec![(stale_note.as_note().nullifier(), test_note_error("older"))],
        BlockNumber::from(1),
    )
    .await
    .unwrap();
    db.notes_failed(
        vec![(recent_note.as_note().nullifier(), test_note_error("newer"))],
        BlockNumber::from(9),
    )
    .await
    .unwrap();

    assert_eq!(
        db.ready_accounts(30, BlockNumber::from(1000), vec![], vec![], 1).await.unwrap(),
        vec![stale],
        "the least recently attempted account is served first",
    );
    assert_eq!(
        db.ready_accounts(30, BlockNumber::from(1000), vec![stale], vec![], 1)
            .await
            .unwrap(),
        vec![recent],
        "an excluded account is skipped in favour of the next one",
    );
}

/// A priority account is served before every other ready account, whatever the wait ordering says.
#[tokio::test]
async fn ready_accounts_serve_priority_accounts_first() {
    let (db, _dir) = test_setup().await;
    let ordinary = mock_network_account_id();
    let prioritized = mock_network_account_id_seeded(42);

    for account_id in [ordinary, prioritized] {
        db.upsert_account_for_test(account_id, mock_account(account_id), mock_transaction_id(1))
            .await
            .unwrap();
    }

    let ordinary_note = mock_single_target_note(ordinary, 1);
    let prioritized_note = mock_single_target_note(prioritized, 2);
    db.insert_network_notes(vec![ordinary_note, prioritized_note.clone()])
        .await
        .unwrap();

    // The priority account has waited least, so the wait ordering alone would serve it last.
    db.notes_failed(
        vec![(prioritized_note.as_note().nullifier(), test_note_error("boom"))],
        BlockNumber::from(9),
    )
    .await
    .unwrap();

    assert_eq!(
        db.ready_accounts(30, BlockNumber::from(1000), vec![], vec![prioritized], 1)
            .await
            .unwrap(),
        vec![prioritized],
        "the priority account takes the only free slot",
    );
    assert_eq!(
        db.ready_accounts(30, BlockNumber::from(1000), vec![], vec![prioritized], 2)
            .await
            .unwrap(),
        vec![prioritized, ordinary],
        "with room for both, the priority account still comes first",
    );
}

// SUBMITTED-TX LANDING
// ================================================================================================

#[tokio::test]
async fn account_last_tx_roundtrips_and_updates() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let account = mock_account(account_id);

    // The first upsert records its transaction id; a later upsert overwrites it.
    let first = mock_transaction_id(1);
    let second = mock_transaction_id(2);
    db.upsert_account_for_test(account_id, account.clone(), first).await.unwrap();
    assert_eq!(db.account_last_tx(account_id).await.unwrap(), Some(first));
    db.upsert_account_for_test(account_id, account, second).await.unwrap();
    assert_eq!(db.account_last_tx(account_id).await.unwrap(), Some(second));
}

#[tokio::test]
async fn account_last_tx_returns_none_for_untracked_account() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();

    // No row exists for this account.
    assert_eq!(db.account_last_tx(account_id).await.unwrap(), None);
}

// GENESIS APPLICATION
// ================================================================================================

/// Builds genesis-shaped effects: a full-state network-account update with no originating
/// transactions, at [`BlockNumber::GENESIS`].
fn genesis_effects() -> CommittedBlockEffects {
    let (account, details) = mock_network_account_update();
    CommittedBlockEffects {
        header: mock_block_header(BlockNumber::GENESIS),
        network_notes: vec![],
        sponsorship_notes: vec![],
        nullifiers: vec![],
        network_account_updates: vec![(account.id(), details)],
        account_transactions: vec![],
    }
}

#[tokio::test]
async fn apply_committed_block_seeds_genesis_network_account() {
    let (db, _dir) = test_setup().await;
    let effects = genesis_effects();
    let account_id = effects.network_account_updates[0].0;

    // Genesis account updates have no originating transactions. The update must seed the account.
    db.apply_committed_block(effects, PartialMmr::default()).await.unwrap();

    assert!(
        db.get_account(account_id).await.unwrap().is_some(),
        "genesis account should be seeded"
    );
    // The seeded account carries the zero sentinel: no transaction produced it. No submitted
    // transaction has the zero id, so this can never be mistaken for a landed transaction.
    assert_eq!(
        db.account_last_tx(account_id).await.unwrap(),
        Some(TransactionId::from_raw(Word::empty())),
    );
}

#[tokio::test]
async fn apply_committed_block_fails_on_txless_update_after_genesis() {
    let (db, _dir) = test_setup().await;
    // Non-genesis account updates require an originating transaction. The database pool converts a
    // panic in its blocking thread to an error.
    let mut effects = genesis_effects();
    effects.header = mock_block_header(BlockNumber::from(1));

    db.apply_committed_block(effects, PartialMmr::default())
        .await
        .expect_err("a committed account update with no transaction must fail");
}

#[tokio::test]
async fn notes_failed_increments_attempt_and_records_error() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 19);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    let nullifier = note.as_note().nullifier();
    db.notes_failed(vec![(nullifier, test_note_error("nope"))], BlockNumber::from(5))
        .await
        .unwrap();
    db.notes_failed(vec![(nullifier, test_note_error("nope"))], BlockNumber::from(6))
        .await
        .unwrap();

    let row = db.get_note_status(note.as_note().id()).await.unwrap().unwrap();
    assert_eq!(row.attempt_count, 2);
    assert_eq!(row.last_attempt, Some(6));
    assert!(row.last_error.is_some());
}

#[tokio::test]
async fn discard_notes_pins_attempts_to_cap_and_drops_from_pending() {
    let (db, _dir) = test_setup().await;
    let account_id = mock_network_account_id();
    let note = mock_single_target_note(account_id, 23);
    db.insert_network_notes(vec![note.clone()]).await.unwrap();

    let nullifier = note.as_note().nullifier();
    db.discard_notes_with_reason(vec![nullifier], BlockNumber::from(9), 30, "too big".to_string())
        .await
        .unwrap();

    // Pinned to the cap, so it is no longer pending or available for selection.
    let row = db.get_note_status(note.as_note().id()).await.unwrap().unwrap();
    assert_eq!(row.attempt_count, 30);
    assert_eq!(row.last_attempt, Some(9));
    assert_eq!(row.last_error.as_deref(), Some("too big"));

    assert!(
        db.available_notes(account_id, BlockNumber::from(1000), 30)
            .await
            .unwrap()
            .eligible
            .is_empty(),
        "a discarded note must not be selectable",
    );
    assert!(
        !db.ready_accounts(30, BlockNumber::from(1000), vec![], vec![], 10)
            .await
            .unwrap()
            .contains(&account_id),
        "an account whose only note was discarded must not be ready for an attempt",
    );
}
