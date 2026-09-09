use std::time::{Duration, SystemTime, UNIX_EPOCH};

use assert_matches::assert_matches;
use diesel::connection::SimpleConnection;
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl};
use miden_node_db::migration::{SchemaHash, SchemaHashes};
use miden_protocol::account::AccountId;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
};
use tempfile::TempDir;

use super::schema::account_allowlist;
use super::{
    AccountAllowlist,
    AllowlistError,
    InvitationCode,
    InvitationEntry,
    InvitationStatus,
    RegistrationOutcome,
};
use crate::DataDirectory;

fn setup() -> (TempDir, AccountAllowlist) {
    let dir = tempfile::tempdir().unwrap();
    AccountAllowlist::bootstrap(data_directory(&dir).allowlist_database_path()).unwrap();
    let registry = reopen(&dir);
    (dir, registry)
}

fn reopen(dir: &TempDir) -> AccountAllowlist {
    AccountAllowlist::load(data_directory(dir).allowlist_database_path()).unwrap()
}

fn data_directory(dir: &TempDir) -> DataDirectory {
    DataDirectory::load(dir.path().to_path_buf()).unwrap()
}

fn account(index: usize) -> AccountId {
    [
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ][index]
        .try_into()
        .unwrap()
}

fn invitation(value: u8) -> InvitationCode {
    InvitationCode::new(&[value; 16]).unwrap()
}

fn entry(value: u8, account_id: Option<AccountId>) -> InvitationEntry {
    InvitationEntry {
        invitation_code: invitation(value),
        account_id,
    }
}

#[test]
fn migration_schema_hashes_are_stable() {
    const EXPECTED: [SchemaHash; 1] = [SchemaHash::from_hex(
        "971987e041689ebe3eff6d54ec93110bb78bed40c169488a7e09c538f1f509ad",
    )];
    let migrator = super::migrations::migrator().unwrap();
    pretty_assertions::assert_eq!(migrator.schema_hashes(), SchemaHashes(&EXPECTED));
}

#[tokio::test]
async fn registrations_and_creation_times_persist() {
    const CREATED_AT: i64 = 946_684_800;

    let (dir, registry) = setup();
    let before =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
    let entries = vec![entry(1, None), entry(2, Some(account(1)))];
    registry.import_invitations(entries.clone()).await.unwrap();
    registry.add_accounts(vec![account(2)]).await.unwrap();
    let after =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();

    let path = data_directory(&dir).allowlist_database_path();
    let mut conn = diesel::SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    let timestamps: Vec<i64> = account_allowlist::table
        .select(account_allowlist::created_at)
        .load(&mut conn)
        .unwrap();
    assert_eq!(timestamps.len(), 3);
    assert!(timestamps.iter().all(|timestamp| (before..=after).contains(timestamp)));
    // An earlier timestamp detects replacement without a clock delay.
    diesel::update(account_allowlist::table)
        .set(account_allowlist::created_at.eq(CREATED_AT))
        .execute(&mut conn)
        .unwrap();
    drop(conn);

    registry.register_account(invitation(1), account(0)).await.unwrap();
    registry.import_invitations(entries).await.unwrap();
    assert_eq!(
        registry.add_accounts(vec![account(0), account(1), account(2)]).await.unwrap(),
        0
    );
    drop(registry);

    AccountAllowlist::migrate(&path).unwrap();
    let registry = reopen(&dir);
    for index in 0..3 {
        assert!(registry.contains_account(account(index)).await.unwrap());
    }
    for (code, id) in [(1, account(0)), (2, account(1))] {
        assert_eq!(
            registry.invitation_status(invitation(code)).await.unwrap(),
            InvitationStatus::Registered(id)
        );
    }
    let mut conn = diesel::SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    let timestamps: Vec<i64> = account_allowlist::table
        .select(account_allowlist::created_at)
        .load(&mut conn)
        .unwrap();
    assert_eq!(timestamps, vec![CREATED_AT; 3]);
}

#[tokio::test]
async fn registry_writes_complete_while_block_database_is_write_locked() {
    let (dir, registry) = setup();
    let store_path = data_directory(&dir).database_path();
    crate::db::bootstrap_database(&store_path).unwrap();
    let mut conn = diesel::SqliteConnection::establish(store_path.to_str().unwrap()).unwrap();
    miden_node_db::configure_connection_on_creation(&mut conn).unwrap();
    conn.batch_execute(
        "BEGIN IMMEDIATE;
         INSERT INTO account_codes (code_commitment, code) VALUES (X'01', X'02');",
    )
    .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), async {
        registry.import_invitations(vec![entry(1, None)]).await.unwrap();
        assert_eq!(
            registry.register_account(invitation(1), account(0)).await.unwrap(),
            RegistrationOutcome::Registered
        );
        assert_eq!(registry.add_accounts(vec![account(1)]).await.unwrap(), 1);
    })
    .await;
    conn.batch_execute("ROLLBACK;").unwrap();
    result.expect("registry writes must not wait for the block database write lock");

    let registry = reopen(&dir);
    assert_eq!(
        registry.invitation_status(invitation(1)).await.unwrap(),
        InvitationStatus::Registered(account(0))
    );
    assert!(registry.contains_account(account(1)).await.unwrap());
}

#[tokio::test]
async fn registration_rules() {
    let (_dir, registry) = setup();
    let reader = registry.reader();

    assert!(!reader.contains_account(account(0)).await.unwrap());
    assert_eq!(
        reader.invitation_status(invitation(1)).await.unwrap(),
        InvitationStatus::Unknown
    );
    assert_matches!(
        registry.register_account(invitation(1), account(0)).await,
        Err(AllowlistError::InvitationNotFound)
    );

    registry.import_invitations(vec![entry(1, None), entry(2, None)]).await.unwrap();
    assert_eq!(reader.invitation_status(invitation(1)).await.unwrap(), InvitationStatus::Unused);
    assert!(!reader.contains_account(account(0)).await.unwrap());

    assert_eq!(
        registry.register_account(invitation(1), account(0)).await.unwrap(),
        RegistrationOutcome::Registered
    );
    assert_eq!(
        registry.register_account(invitation(1), account(0)).await.unwrap(),
        RegistrationOutcome::AlreadyRegistered
    );
    assert_matches!(
        registry.register_account(invitation(1), account(1)).await,
        Err(AllowlistError::InvitationAlreadyUsed)
    );
    assert_matches!(
        registry.register_account(invitation(2), account(0)).await,
        Err(AllowlistError::AccountAlreadyRegistered(id)) if id == account(0)
    );
    assert!(!registry.contains_account(account(1)).await.unwrap());
    assert_eq!(
        registry.add_accounts(vec![account(0), account(1), account(1)]).await.unwrap(),
        1
    );
    assert_eq!(registry.add_accounts(vec![account(1)]).await.unwrap(), 0);
    assert_matches!(
        registry.register_account(invitation(2), account(1)).await,
        Err(AllowlistError::AccountAlreadyRegistered(id)) if id == account(1)
    );
    assert_eq!(
        reader.invitation_status(invitation(1)).await.unwrap(),
        InvitationStatus::Registered(account(0))
    );
    assert_eq!(reader.invitation_status(invitation(2)).await.unwrap(), InvitationStatus::Unused);
    assert!(reader.contains_account(account(0)).await.unwrap());
    assert!(reader.contains_account(account(1)).await.unwrap());
}

#[tokio::test]
async fn conflicting_invitation_import_rolls_back_inserts_and_registrations() {
    let (_dir, registry) = setup();
    registry
        .import_invitations(vec![entry(1, None), entry(2, Some(account(0)))])
        .await
        .unwrap();

    assert_matches!(
        registry
            .import_invitations(vec![
                entry(3, Some(account(1))),
                entry(1, Some(account(2))),
                entry(2, Some(account(1))),
            ])
            .await,
        Err(AllowlistError::InvitationAlreadyUsed)
    );

    assert_eq!(
        registry.invitation_status(invitation(1)).await.unwrap(),
        InvitationStatus::Unused
    );
    assert_eq!(
        registry.invitation_status(invitation(2)).await.unwrap(),
        InvitationStatus::Registered(account(0))
    );
    assert_eq!(
        registry.invitation_status(invitation(3)).await.unwrap(),
        InvitationStatus::Unknown
    );
    assert!(!registry.contains_account(account(1)).await.unwrap());
    assert!(!registry.contains_account(account(2)).await.unwrap());

    let entries = vec![entry(1, Some(account(2))), entry(3, Some(account(1)))];
    registry.import_invitations(entries.clone()).await.unwrap();
    registry.import_invitations(entries).await.unwrap();
    assert_eq!(
        registry.invitation_status(invitation(1)).await.unwrap(),
        InvitationStatus::Registered(account(2))
    );
    assert_eq!(
        registry.invitation_status(invitation(3)).await.unwrap(),
        InvitationStatus::Registered(account(1))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_accounts_cannot_claim_the_same_invitation() {
    let (dir, registry) = setup();
    registry.import_invitations(vec![entry(1, None)]).await.unwrap();
    let other = reopen(&dir);

    let (first, second) = tokio::join!(
        registry.register_account(invitation(1), account(0)),
        other.register_account(invitation(1), account(1)),
    );
    let winner = match (first, second) {
        (Ok(RegistrationOutcome::Registered), Err(AllowlistError::InvitationAlreadyUsed)) => 0,
        (Err(AllowlistError::InvitationAlreadyUsed), Ok(RegistrationOutcome::Registered)) => 1,
        results => panic!("expected one successful registration, got {results:?}"),
    };
    assert_eq!(
        registry.invitation_status(invitation(1)).await.unwrap(),
        InvitationStatus::Registered(account(winner))
    );
    assert!(registry.contains_account(account(winner)).await.unwrap());
    assert!(!registry.contains_account(account(1 - winner)).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_invitations_cannot_register_the_same_account() {
    let (dir, registry) = setup();
    registry.import_invitations(vec![entry(1, None), entry(2, None)]).await.unwrap();
    let other = reopen(&dir);

    let (first, second) = tokio::join!(
        registry.register_account(invitation(1), account(0)),
        other.register_account(invitation(2), account(0)),
    );
    let winner = match (first, second) {
        (Ok(RegistrationOutcome::Registered), Err(AllowlistError::AccountAlreadyRegistered(_))) => {
            1
        },
        (Err(AllowlistError::AccountAlreadyRegistered(_)), Ok(RegistrationOutcome::Registered)) => {
            2
        },
        results => panic!("expected one successful registration, got {results:?}"),
    };
    assert_eq!(
        registry.invitation_status(invitation(winner)).await.unwrap(),
        InvitationStatus::Registered(account(0))
    );
    assert_eq!(
        registry.invitation_status(invitation(3 - winner)).await.unwrap(),
        InvitationStatus::Unused
    );
}

#[test]
fn invitation_codes_reject_empty_input_and_hide_debug_values() {
    assert!(InvitationCode::new(&[]).is_err());
    let invitation = InvitationCode::new(b"private invitation code").unwrap();
    let debug = format!("{invitation:?}");
    assert!(!debug.contains("private invitation code"));
    assert!(!debug.contains(&hex::encode(invitation.digest())));
}
