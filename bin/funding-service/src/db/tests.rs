use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use miden_node_db::DatabaseError;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_WITH_CALLBACKS,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::utils::serde::Serializable;

use super::*;

fn identity() -> DatabaseIdentity {
    DatabaseIdentity {
        genesis_commitment: Word::from([1u32; 4]),
        funding_account_id: ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        fee_asset_id: AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_WITH_CALLBACKS.try_into().unwrap(),
        ),
    }
}

fn note(seed: u32) -> UsdcxP2Id {
    note_for(ACCOUNT_ID_SENDER.try_into().unwrap(), 1_000, seed)
}

fn note_for(target: AccountId, amount: u64, seed: u32) -> UsdcxP2Id {
    let identity = identity();
    crate::test_utils::build_funding_note(
        identity.funding_account_id,
        identity.fee_asset_id,
        target,
        amount,
        &mut RandomCoin::new(Word::from([seed; 4])),
    )
    .unwrap()
}

async fn store_request(database: &FundingDatabase, seed: u32) -> StoredRequest {
    let note = note(seed);
    database
        .store_request(note.target(), note.amount(), note.note().recipient().serial_num())
        .await
        .unwrap()
}

fn transaction(seed: u32) -> TransactionId {
    TransactionId::from_raw(Word::from([seed; 4]))
}

async fn database() -> (tempfile::TempDir, FundingDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let database = FundingDatabase::bootstrap(&dir.path().join("funding.sqlite3"), identity())
        .await
        .unwrap();
    (dir, database)
}

#[tokio::test]
async fn persisted_requests_reopen_with_the_exact_note_and_acceptance_order() {
    let (dir, database) = database().await;
    let first_note = note_for(ACCOUNT_ID_SENDER.try_into().unwrap(), 1, 20);
    let second_note = note_for(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into().unwrap(),
        miden_protocol::asset::FungibleAsset::MAX_AMOUNT.as_u64(),
        10,
    );
    let before = SystemTime::now() - Duration::from_micros(1);
    let first = database
        .store_request(
            first_note.target(),
            first_note.amount(),
            first_note.note().recipient().serial_num(),
        )
        .await
        .unwrap();
    let second = database
        .store_request(
            second_note.target(),
            second_note.amount(),
            second_note.note().recipient().serial_num(),
        )
        .await
        .unwrap();
    assert!(first.sequence < second.sequence);
    assert!((before..=SystemTime::now()).contains(&first.accepted_at));
    assert!(first.delivery.is_none());
    assert_eq!(first.note.to_bytes(), first_note.note().to_bytes());
    assert_eq!(second.note.to_bytes(), second_note.note().to_bytes());
    drop(database);

    let database = FundingDatabase::open_and_verify(
        &dir.path().join("funding.sqlite3"),
        identity().genesis_commitment,
        identity().fee_asset_id,
    )
    .await
    .unwrap();
    assert_eq!(
        database.pending_requests(NonZeroUsize::new(1).unwrap()).await.unwrap(),
        vec![first.clone()]
    );
    assert_eq!(
        database.pending_requests(NonZeroUsize::new(10).unwrap()).await.unwrap(),
        vec![first.clone(), second.clone()]
    );
    let attempt = TransactionAttempt {
        transaction_id: transaction(1),
        reference_block: 10.into(),
        expiration_block: 20.into(),
        deposit_nullifier: None,
        note_ids: vec![first.note.id(), second.note.id()],
    };
    database.start_attempt(attempt.clone()).await.unwrap();
    assert_eq!(database.active_attempt().await.unwrap(), Some(attempt));
}

#[tokio::test]
async fn delivered_requests_are_retained_for_auditing_and_retries_preserve_history() {
    let (dir, database) = database().await;
    let first = store_request(&database, 1).await;
    let second = store_request(&database, 2).await;
    let third = store_request(&database, 3).await;
    let before = SystemTime::now() - Duration::from_micros(1);
    database
        .record_delivery(vec![first.note.id(), second.note.id()], transaction(1), 12.into())
        .await
        .unwrap();
    let delivered = database.request(first.note.id()).await.unwrap().unwrap();
    let delivery = delivered.delivery.unwrap();
    assert_eq!(delivery.transaction_id, transaction(1));
    assert_eq!(delivery.committed_in_block, 12.into());
    assert!((before..=SystemTime::now()).contains(&delivery.confirmed_at));
    assert_eq!(delivered.note, first.note);
    assert_eq!(delivered.sequence, first.sequence);
    assert_eq!(delivered.accepted_at, first.accepted_at);
    assert_eq!(
        database.request(second.note.id()).await.unwrap().unwrap().delivery,
        Some(delivery)
    );

    database
        .record_delivery(vec![first.note.id()], transaction(1), 12.into())
        .await
        .unwrap();
    assert_eq!(store_request(&database, 1).await, delivered);
    assert_eq!(store_request(&database, 3).await, third);
    drop(database);

    let database = FundingDatabase::open_and_verify(
        &dir.path().join("funding.sqlite3"),
        identity().genesis_commitment,
        identity().fee_asset_id,
    )
    .await
    .unwrap();
    assert_eq!(database.request(first.note.id()).await.unwrap(), Some(delivered));
    assert_eq!(
        database.pending_requests(NonZeroUsize::new(10).unwrap()).await.unwrap(),
        vec![third]
    );
}

#[tokio::test]
async fn stored_microsecond_timestamps_reopen_as_absolute_times() {
    let (dir, database) = database().await;
    let cases = [
        (1, 0_i64, 1_i64, Duration::ZERO, Duration::new(0, 1_000)),
        (
            2,
            123_456_789_i64,
            987_654_321_i64,
            Duration::new(123, 456_789_000),
            Duration::new(987, 654_321_000),
        ),
    ];
    for (seed, accepted_at, confirmed_at, ..) in cases {
        let stored = store_request(&database, seed).await;
        database
            .writer
            .write("set stored timestamps", move |tx| {
                tx.execute(
                    "UPDATE requests SET accepted_at = ?1, confirmed_at = ?2,
                     transaction_id = ?3, committed_in_block = 12 WHERE note_id = ?4",
                    &[&accepted_at, &confirmed_at, &transaction(1), &stored.note.id()],
                )?;
                Ok::<_, DatabaseError>(())
            })
            .await
            .unwrap();
    }
    drop(database);

    let database = FundingDatabase::open_and_verify(
        &dir.path().join("funding.sqlite3"),
        identity().genesis_commitment,
        identity().fee_asset_id,
    )
    .await
    .unwrap();
    for (seed, _, _, accepted_at, confirmed_at) in cases {
        let stored = database.request(note(seed).note().id()).await.unwrap().unwrap();
        assert_eq!(stored.accepted_at, UNIX_EPOCH + accepted_at);
        assert_eq!(stored.delivery.unwrap().confirmed_at, UNIX_EPOCH + confirmed_at);
    }
}

#[tokio::test]
async fn failed_delivery_batches_leave_every_request_unchanged() {
    let (_dir, database) = database().await;
    let first = store_request(&database, 1).await;
    let second = store_request(&database, 2).await;

    assert!(
        database
            .record_delivery(vec![first.note.id(), note(3).note().id()], transaction(1), 12.into())
            .await
            .is_err()
    );
    assert_eq!(database.request(first.note.id()).await.unwrap(), Some(first.clone()));

    database
        .record_delivery(vec![second.note.id()], transaction(2), 13.into())
        .await
        .unwrap();
    let second = database.request(second.note.id()).await.unwrap().unwrap();
    assert!(
        database
            .record_delivery(vec![first.note.id(), second.note.id()], transaction(1), 12.into())
            .await
            .is_err()
    );
    assert_eq!(database.request(first.note.id()).await.unwrap(), Some(first));
    assert_eq!(database.request(second.note.id()).await.unwrap(), Some(second));
}

#[tokio::test]
async fn attempts_hold_requests_until_delivery_or_release_and_failed_writes_leave_them_intact() {
    let (_dir, database) = database().await;
    let first = store_request(&database, 1).await;
    let second = store_request(&database, 2).await;
    let waiting = store_request(&database, 3).await;
    let mut attempt = TransactionAttempt {
        transaction_id: transaction(1),
        reference_block: 10.into(),
        expiration_block: 20.into(),
        deposit_nullifier: Some(Nullifier::from_raw(Word::from([4u32; 4]))),
        note_ids: vec![first.note.id(), note(4).note().id()],
    };
    assert!(database.start_attempt(attempt.clone()).await.is_err());
    assert!(database.active_attempt().await.unwrap().is_none());
    assert_eq!(database.pending_requests(3.try_into().unwrap()).await.unwrap().len(), 3);

    attempt.note_ids = vec![first.note.id(), first.note.id()];
    assert!(database.start_attempt(attempt.clone()).await.is_err());
    assert!(database.active_attempt().await.unwrap().is_none());

    attempt.note_ids = vec![first.note.id(), second.note.id()];
    database.start_attempt(attempt.clone()).await.unwrap();
    assert_eq!(database.active_attempt().await.unwrap(), Some(attempt.clone()));
    assert_eq!(
        database.pending_requests(3.try_into().unwrap()).await.unwrap(),
        vec![waiting.clone()]
    );
    assert!(database.start_attempt(attempt.clone()).await.is_err());
    assert!(database.release_attempt(transaction(2), None).await.is_err());

    database
        .writer
        .write("reject attempt deletion", |tx| {
            tx.execute(
                "CREATE TRIGGER reject_attempt_delete BEFORE DELETE ON transaction_attempt
             BEGIN SELECT RAISE(FAIL, 'write failed'); END",
                &[],
            )?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    assert!(
        database
            .record_delivery(attempt.note_ids.clone(), transaction(1), 19.into())
            .await
            .is_err()
    );
    assert_eq!(database.active_attempt().await.unwrap(), Some(attempt.clone()));
    assert_eq!(database.request(first.note.id()).await.unwrap(), Some(first.clone()));
    assert_eq!(database.request(second.note.id()).await.unwrap(), Some(second));
    database
        .writer
        .write("restore attempt deletion", |tx| {
            tx.execute("DROP TRIGGER reject_attempt_delete", &[])?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    database
        .record_delivery(attempt.note_ids.clone(), transaction(1), 19.into())
        .await
        .unwrap();
    assert!(database.active_attempt().await.unwrap().is_none());
    assert_eq!(
        database
            .request(first.note.id())
            .await
            .unwrap()
            .unwrap()
            .delivery
            .unwrap()
            .transaction_id,
        transaction(1)
    );
    assert_eq!(
        database.pending_requests(3.try_into().unwrap()).await.unwrap(),
        vec![waiting.clone()]
    );

    attempt.transaction_id = transaction(2);
    attempt.note_ids = vec![waiting.note.id()];
    database.start_attempt(attempt.clone()).await.unwrap();
    database.release_attempt(attempt.transaction_id, None).await.unwrap();
    assert!(database.active_attempt().await.unwrap().is_none());
    assert_eq!(database.pending_requests(3.try_into().unwrap()).await.unwrap(), vec![waiting]);

    attempt.note_ids.clear();
    database.start_attempt(attempt.clone()).await.unwrap();
    database
        .record_delivery(vec![], attempt.transaction_id, 19.into())
        .await
        .unwrap();
    assert!(database.active_attempt().await.unwrap().is_none());
}

#[tokio::test]
async fn opening_requires_a_matching_database_identity() {
    let (dir, database) = database().await;
    let original = store_request(&database, 1).await;
    drop(database);
    let path = dir.path().join("funding.sqlite3");
    let identities = [
        DatabaseIdentity {
            genesis_commitment: Word::from([2u32; 4]),
            ..identity()
        },
        DatabaseIdentity {
            fee_asset_id: AssetId::new_fungible(
                ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
            ),
            ..identity()
        },
    ];
    for identity in identities {
        assert!(
            FundingDatabase::open_and_verify(
                &path,
                identity.genesis_commitment,
                identity.fee_asset_id
            )
            .await
            .is_err()
        );
    }
    let database = FundingDatabase::open_and_verify(
        &path,
        identity().genesis_commitment,
        identity().fee_asset_id,
    )
    .await
    .unwrap();
    assert_eq!(database.identity(), identity());
    assert_eq!(database.request(original.note.id()).await.unwrap(), Some(original));

    database
        .writer
        .write("remove database identity", |tx| {
            tx.execute("DELETE FROM database_identity", &[])?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    drop(database);
    assert!(
        FundingDatabase::open_and_verify(
            &path,
            identity().genesis_commitment,
            identity().fee_asset_id
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn invalid_funding_requests_are_not_stored() {
    let (_dir, database) = database().await;
    let identity = identity();
    let other: AccountId = ACCOUNT_ID_SENDER.try_into().unwrap();
    for (target, amount) in [(other, 0), (other, u64::MAX), (identity.funding_account_id, 1_000)] {
        assert!(database.store_request(target, amount, Word::from([1u32; 4])).await.is_err());
    }
    assert_eq!(database.pending_requests(1.try_into().unwrap()).await.unwrap(), []);
}

#[tokio::test]
async fn concurrent_retries_store_each_note_once() {
    let (_dir, database) = database().await;
    let database = Arc::new(database);
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..8 {
        let database = Arc::clone(&database);
        tasks.spawn(async move { store_request(&database, index % 4).await });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    let pending = database.pending_requests(NonZeroUsize::new(8).unwrap()).await.unwrap();
    assert_eq!(pending.len(), 4);
    for seed in 0..4 {
        assert_eq!(pending.iter().filter(|stored| stored.note == *note(seed).note()).count(), 1);
    }
}

#[tokio::test]
async fn corrupt_note_data_is_reported_without_discarding_other_requests() {
    let (_dir, database) = database().await;
    let first = store_request(&database, 1).await;
    let second = store_request(&database, 2).await;
    let first_id = first.note.id();
    database
        .writer
        .write("corrupt stored note", move |tx| {
            tx.execute(
                "UPDATE requests SET serial_number = ?1 WHERE note_id = ?2",
                &[&vec![0xff; 32], &first_id],
            )?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    assert!(database.request(first_id).await.is_err());
    assert!(database.pending_requests(NonZeroUsize::new(10).unwrap()).await.is_err());
    assert_eq!(database.request(second.note.id()).await.unwrap(), Some(second));
}

const CRASH_DATABASE_PATH: &str = "MIDEN_FUNDING_TEST_CRASH_DATABASE";

#[tokio::test]
async fn acknowledged_writes_survive_abrupt_process_exit() {
    if let Some(path) = std::env::var_os(CRASH_DATABASE_PATH) {
        let database = FundingDatabase::open_and_verify(
            Path::new(&path),
            identity().genesis_commitment,
            identity().fee_asset_id,
        )
        .await
        .unwrap();
        store_request(&database, 1).await;
        database
            .start_attempt(TransactionAttempt {
                transaction_id: transaction(1),
                reference_block: 10.into(),
                expiration_block: 20.into(),
                deposit_nullifier: None,
                note_ids: vec![note(1).note().id()],
            })
            .await
            .unwrap();
        // Exit without running connection destructors or checkpointing the WAL.
        std::process::exit(0);
    }
    let (dir, database) = database().await;
    drop(database);
    let path = dir.path().join("funding.sqlite3");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "db::tests::acknowledged_writes_survive_abrupt_process_exit"])
        .env(CRASH_DATABASE_PATH, &path)
        .status()
        .unwrap();
    assert!(status.success());
    let database = FundingDatabase::open_and_verify(
        &path,
        identity().genesis_commitment,
        identity().fee_asset_id,
    )
    .await
    .unwrap();
    assert_eq!(
        database.request(note(1).note().id()).await.unwrap().unwrap().note,
        *note(1).note()
    );
    let attempt = database.active_attempt().await.unwrap().unwrap();
    assert_eq!(attempt.transaction_id, transaction(1));
    assert_eq!(attempt.reference_block, BlockNumber::from(10));
    assert_eq!(attempt.expiration_block, BlockNumber::from(20));
    assert_eq!(attempt.note_ids, vec![note(1).note().id()]);
    assert_eq!(database.pending_requests(1.try_into().unwrap()).await.unwrap(), []);
}

// DEPOSIT CHECKPOINT
// ================================================================================================

fn deposit(seed: u32) -> UsdcxP2Id {
    note_for(identity().funding_account_id, 1_000, seed)
}

/// Returns the checkpoint cursor and deposits keyed by nullifier for order-independent comparison.
fn checkpoint_contents(
    checkpoint: DepositCheckpoint,
) -> (BlockNumber, std::collections::HashMap<Nullifier, Note>) {
    (
        checkpoint.next_sync,
        checkpoint
            .deposits
            .into_iter()
            .map(|deposit| (deposit.nullifier(), deposit.into_note()))
            .collect(),
    )
}

fn deposits_of(deposits: &[&UsdcxP2Id]) -> std::collections::HashMap<Nullifier, Note> {
    deposits
        .iter()
        .map(|deposit| (deposit.nullifier(), deposit.note().clone()))
        .collect()
}

async fn save(database: &FundingDatabase, next_sync: u32, deposits: &[&UsdcxP2Id]) {
    database
        .save_deposit_checkpoint(DepositCheckpoint {
            next_sync: next_sync.into(),
            deposits: deposits.iter().map(|deposit| (*deposit).clone()).collect(),
        })
        .await
        .unwrap();
}

async fn reopen(dir: &tempfile::TempDir) -> FundingDatabase {
    FundingDatabase::open_and_verify(
        &dir.path().join("funding.sqlite3"),
        identity().genesis_commitment,
        identity().fee_asset_id,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_new_database_resumes_deposit_discovery_from_genesis() {
    let (_dir, database) = database().await;
    assert_eq!(database.deposit_checkpoint().await.unwrap(), DepositCheckpoint::default());
}

#[tokio::test]
async fn migrating_a_database_keeps_its_requests_and_resumes_deposit_discovery_from_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("funding.sqlite3");
    migrator().unwrap().create_database(&path).unwrap().migrate_to(1).unwrap();
    let request = note(1);
    let (writer, _reader) = miden_node_db::sqlite::open(&path).unwrap();
    let (note_id, target, amount, serial_number) = (
        request.note().id(),
        request.target(),
        request.amount(),
        request.note().recipient().serial_num(),
    );
    writer
        .write("populate a version 1 database", move |tx| {
            queries::insert_database_identity(tx, &identity())?;
            queries::insert_request(tx, note_id, target, amount, serial_number, UNIX_EPOCH)
        })
        .await
        .unwrap();
    drop(writer);

    assert!(
        FundingDatabase::open_and_verify(
            &path,
            identity().genesis_commitment,
            identity().fee_asset_id
        )
        .await
        .is_err()
    );
    FundingDatabase::migrate(&path).unwrap();
    let database = reopen(&dir).await;
    assert_eq!(database.deposit_checkpoint().await.unwrap(), DepositCheckpoint::default());
    assert_eq!(
        database
            .pending_requests(NonZeroUsize::new(10).unwrap())
            .await
            .unwrap()
            .into_iter()
            .map(|stored| stored.note)
            .collect::<Vec<_>>(),
        vec![request.into_note()]
    );
}

#[tokio::test]
async fn a_saved_deposit_checkpoint_reopens_with_its_cursor_and_notes() {
    let (dir, database) = database().await;
    let (first, second) = (deposit(1), deposit(2));
    save(&database, 13, &[&first, &second]).await;
    drop(database);

    let database = reopen(&dir).await;
    assert_eq!(
        checkpoint_contents(database.deposit_checkpoint().await.unwrap()),
        (13.into(), deposits_of(&[&first, &second]))
    );

    save(&database, 20, &[&second]).await;
    assert_eq!(
        checkpoint_contents(database.deposit_checkpoint().await.unwrap()),
        (20.into(), deposits_of(&[&second]))
    );
}

#[tokio::test]
async fn a_deposit_checkpoint_cannot_move_backwards_or_hold_another_accounts_note() {
    let (_dir, database) = database().await;
    let kept = deposit(1);
    save(&database, 20, &[&kept]).await;

    let earlier = DepositCheckpoint { next_sync: 19.into(), deposits: vec![] };
    assert!(database.save_deposit_checkpoint(earlier).await.is_err());
    let foreign = DepositCheckpoint {
        next_sync: 21.into(),
        deposits: vec![note(2)],
    };
    assert!(database.save_deposit_checkpoint(foreign).await.is_err());

    assert_eq!(
        checkpoint_contents(database.deposit_checkpoint().await.unwrap()),
        (20.into(), deposits_of(&[&kept]))
    );
}

#[tokio::test]
async fn delivery_removes_the_consumed_deposit_together_with_the_attempt() {
    let (_dir, database) = database().await;
    let request = store_request(&database, 1).await;
    let (consumed, other) = (deposit(1), deposit(2));
    save(&database, 11, &[&consumed, &other]).await;
    let attempt = TransactionAttempt {
        transaction_id: transaction(1),
        reference_block: 10.into(),
        expiration_block: 20.into(),
        deposit_nullifier: Some(consumed.nullifier()),
        note_ids: vec![request.note.id()],
    };
    database.start_attempt(attempt.clone()).await.unwrap();

    database
        .writer
        .write("reject deposit deletion", |tx| {
            tx.execute(
                "CREATE TRIGGER reject_deposit_delete BEFORE DELETE ON deposits
             BEGIN SELECT RAISE(FAIL, 'write failed'); END",
                &[],
            )?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();
    assert!(
        database
            .record_delivery(attempt.note_ids.clone(), transaction(1), 15.into())
            .await
            .is_err()
    );
    assert_eq!(database.active_attempt().await.unwrap(), Some(attempt.clone()));
    assert_eq!(database.request(request.note.id()).await.unwrap(), Some(request.clone()));
    assert_eq!(
        checkpoint_contents(database.deposit_checkpoint().await.unwrap()),
        (11.into(), deposits_of(&[&consumed, &other]))
    );
    database
        .writer
        .write("restore deposit deletion", |tx| {
            tx.execute("DROP TRIGGER reject_deposit_delete", &[])?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();

    database
        .record_delivery(attempt.note_ids.clone(), transaction(1), 15.into())
        .await
        .unwrap();
    assert!(database.active_attempt().await.unwrap().is_none());
    assert_eq!(
        checkpoint_contents(database.deposit_checkpoint().await.unwrap()),
        (11.into(), deposits_of(&[&other]))
    );

    let payout = store_request(&database, 2).await;
    database
        .start_attempt(TransactionAttempt {
            transaction_id: transaction(2),
            deposit_nullifier: None,
            note_ids: vec![payout.note.id()],
            ..attempt
        })
        .await
        .unwrap();
    database
        .record_delivery(vec![payout.note.id()], transaction(2), 15.into())
        .await
        .unwrap();
    assert_eq!(
        checkpoint_contents(database.deposit_checkpoint().await.unwrap()),
        (11.into(), deposits_of(&[&other]))
    );
}

#[tokio::test]
async fn releasing_an_attempt_keeps_its_deposit_unless_the_node_rejected_it() {
    let (_dir, database) = database().await;
    let selected = deposit(1);
    save(&database, 11, &[&selected]).await;
    let attempt = TransactionAttempt {
        transaction_id: transaction(1),
        reference_block: 10.into(),
        expiration_block: 20.into(),
        deposit_nullifier: Some(selected.nullifier()),
        note_ids: vec![],
    };

    database.start_attempt(attempt.clone()).await.unwrap();
    database.release_attempt(attempt.transaction_id, None).await.unwrap();
    assert_eq!(
        checkpoint_contents(database.deposit_checkpoint().await.unwrap()),
        (11.into(), deposits_of(&[&selected]))
    );

    database.start_attempt(attempt.clone()).await.unwrap();
    database
        .release_attempt(attempt.transaction_id, Some(selected.nullifier()))
        .await
        .unwrap();
    assert!(database.active_attempt().await.unwrap().is_none());
    assert_eq!(database.deposit_checkpoint().await.unwrap().deposits, vec![]);
}

#[tokio::test]
async fn a_stored_deposit_the_account_cannot_consume_is_reported() {
    let (_dir, database) = database().await;
    let request = store_request(&database, 1).await;
    let foreign = note(2).into_note();
    database
        .writer
        .write("store a foreign note as a deposit", move |tx| {
            tx.execute(
                "INSERT INTO deposits (nullifier, note) VALUES (?1, ?2)",
                &[&foreign.nullifier(), &foreign],
            )?;
            Ok::<_, DatabaseError>(())
        })
        .await
        .unwrap();

    assert!(database.deposit_checkpoint().await.is_err());
    assert_eq!(
        database.pending_requests(NonZeroUsize::new(10).unwrap()).await.unwrap(),
        vec![request]
    );
}
