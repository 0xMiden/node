use miden_protocol::ONE;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{Account, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::note::Note;
use miden_standards::account::auth::Approver;
use miden_standards::account::wallets::create_basic_wallet;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::node::tests::{TestChain, TestServer};
use crate::test_utils::{Fixture, TEST_BASE_FEE};

fn fee_asset_id() -> AssetId {
    AssetId::new_fungible(FungibleAsset::mock_issuer())
}

/// Builds a wallet the way the genesis configuration does, so the test covers the file the service
/// actually loads.
fn genesis_wallet(account_type: AccountType) -> (Account, SecretKey) {
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let secret_key = SecretKey::with_rng(&mut rng);
    let auth = Approver::new(secret_key.public_key().into(), AuthScheme::Falcon512Poseidon2);
    let init_seed: [u8; 32] = rng.random();
    let mut account =
        create_basic_wallet(init_seed, auth, account_type).expect("wallet should build");
    account.set_nonce(ONE).expect("nonce should be settable");
    (account, secret_key)
}

fn write_account_file(
    dir: &Path,
    account: &Account,
    keys: Vec<AuthSecretKey>,
) -> std::path::PathBuf {
    let path = dir.join("funding_service.mac");
    AccountFile::new(account.clone(), keys)
        .write(&path)
        .expect("file should be written");
    path
}

#[test]
fn loads_a_public_wallet_with_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let (account, secret_key) = genesis_wallet(AccountType::Public);
    let path = write_account_file(
        dir.path(),
        &account,
        vec![AuthSecretKey::Falcon512Poseidon2(secret_key.clone())],
    );

    let funder =
        FundingWallet::load(&path, fee_asset_id()).expect("a public wallet with a key should load");

    assert_eq!(funder.account_id(), account.id());
    assert_eq!(funder.account().code().commitment(), account.code().commitment());
    assert_eq!(
        funder.secret_key().public_key().to_commitment(),
        AuthSecretKey::Falcon512Poseidon2(secret_key).public_key().to_commitment()
    );
}

/// The service reads the funder's vault from the node, which is only possible for a public account.
#[test]
fn rejects_a_private_account() {
    let dir = tempfile::tempdir().unwrap();
    let (account, secret_key) = genesis_wallet(AccountType::Private);
    let path = write_account_file(
        dir.path(),
        &account,
        vec![AuthSecretKey::Falcon512Poseidon2(secret_key)],
    );

    let err = FundingWallet::load(&path, fee_asset_id())
        .err()
        .expect("a private account must be rejected");
    assert!(err.to_string().contains("is not public"), "unexpected error: {err}");
}

/// Replaces the account served by the fixture with an authenticated state.
fn serve_account(server: &TestServer, account: Account) -> Result<()> {
    let witness = miden_protocol::block::account_tree::AccountTree::with_entries([(
        account.id(),
        account.to_commitment(),
    )])?
    .open(account.id());
    server.chain.lock().unwrap().account = Some((account, witness));
    Ok(())
}

#[tokio::test]
async fn sync_updates_are_applied_atomically() -> Result<()> {
    let fixture = Fixture::new(1_000_000, TEST_BASE_FEE)?;
    let mut wallet = fixture.wallet;
    let original = wallet.account().as_ref().clone();
    let mut updated = original.clone();
    updated.set_nonce(updated.nonce() + ONE)?;
    let note: Note = miden_standards::note::P2idNote::builder()
        .sender(fixture.fee_faucet_id)
        .target(wallet.account_id())
        .asset(FungibleAsset::new(fixture.fee_faucet_id, 1_000)?)
        .note_type(miden_protocol::note::NoteType::Public)
        .serial_number(Word::from([1u32; 4]))
        .build()?
        .into();
    let mut chain = TestChain::new(12);
    chain.notes = vec![(10, note.clone())];
    let server = TestServer::start(chain).await;
    serve_account(&server, updated.clone())?;
    let mut rpc = server.node.rpc_client();

    let update = wallet.sync_to(&mut rpc, 12.into()).await?;
    assert_eq!(wallet.account().as_ref(), &original);
    assert!(wallet.deposits().is_empty());
    assert_eq!(wallet.next_sync, BlockNumber::GENESIS);

    let shared_account = Arc::clone(wallet.account());
    assert!(wallet.apply(update).is_err());
    assert_eq!(wallet.account().as_ref(), &original);
    assert!(wallet.deposits().is_empty());
    assert_eq!(wallet.next_sync, BlockNumber::GENESIS);
    drop(shared_account);

    let update = wallet.sync_to(&mut rpc, 12.into()).await?;
    wallet.apply(update)?;
    assert_eq!(wallet.account().as_ref(), &updated);
    assert_eq!(wallet.deposits().len(), 1);
    assert_eq!(wallet.deposits()[&note.nullifier()].note(), &note);
    assert_eq!(wallet.next_sync, 13.into());
    Ok(())
}

#[tokio::test]
async fn sync_updates_state_and_preserves_key_and_deposit_progress() -> Result<()> {
    let fixture = Fixture::new(1_000_000, TEST_BASE_FEE)?;
    let block = fixture.chain.lock().await.latest_block_header().block_num();
    let mut wallet = fixture.wallet;
    let original = wallet.account().as_ref().clone();
    let signing_key = wallet.secret_key().public_key().to_commitment();
    let mut updated = original.clone();
    updated.set_nonce(updated.nonce() + ONE)?;
    updated
        .vault_mut()
        .add_asset(FungibleAsset::new(fixture.fee_faucet_id, 25)?.into())?;
    let server = TestServer::start(TestChain::new((block + 1).as_u32())).await;
    serve_account(&server, updated.clone())?;
    let mut rpc = server.node.rpc_client();

    let update = wallet.sync_to(&mut rpc, block).await?;
    wallet.apply(update)?;
    assert!(wallet.deposits().is_empty());
    let update = wallet.sync_to(&mut rpc, block + 1).await?;
    wallet.apply(update)?;
    assert_eq!(wallet.account().as_ref(), &updated);
    assert_ne!(wallet.account().as_ref(), &original);
    assert_eq!(wallet.secret_key().public_key().to_commitment(), signing_key);

    server.chain.lock().unwrap().unavailable = Some("GetAccount");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), wallet.sync_to(&mut rpc, block + 2))
            .await
            .is_err()
    );
    assert_eq!(wallet.account().as_ref(), &updated);
    assert_eq!(wallet.secret_key().public_key().to_commitment(), signing_key);

    server.chain.lock().unwrap().unavailable = Some("SyncNotes");
    let update = wallet.sync_to(&mut rpc, block + 1).await?;
    wallet.apply(update)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), wallet.sync_to(&mut rpc, block + 2))
            .await
            .is_err()
    );
    assert_eq!(wallet.account().as_ref(), &updated);
    server.chain.lock().unwrap().unavailable = None;
    server.chain.lock().unwrap().tip = (block + 2).as_u32();
    let update = wallet.sync_to(&mut rpc, block + 2).await?;
    wallet.apply(update)?;
    Ok(())
}

#[tokio::test]
async fn sync_recovers_unspent_deposits_without_changes_on_cancellation() -> Result<()> {
    let fixture = Fixture::new(1_000_000, TEST_BASE_FEE)?;
    let mut wallet = fixture.wallet;
    let original = wallet.account().as_ref().clone();
    let deposit = |serial: u32| -> Note {
        miden_standards::note::P2idNote::builder()
            .sender(fixture.fee_faucet_id)
            .target(original.id())
            .asset(FungibleAsset::new(fixture.fee_faucet_id, 1_000).unwrap())
            .note_type(miden_protocol::note::NoteType::Public)
            .serial_number(Word::from([serial; 4]))
            .build()
            .unwrap()
            .into()
    };
    let spent = deposit(1);
    let unspent = deposit(2);
    let later = deposit(3);
    let mut chain = TestChain::new(12);
    chain.notes = vec![(3, spent.clone()), (10, unspent.clone())];
    chain.spent = vec![(4, spent.nullifier())];
    chain.unavailable = Some("SyncNullifiers");
    let server = TestServer::start(chain).await;
    let mut updated = original.clone();
    updated.set_nonce(updated.nonce() + ONE)?;
    serve_account(&server, updated.clone())?;
    let mut rpc = server.node.rpc_client();

    assert!(
        tokio::time::timeout(Duration::from_millis(200), wallet.sync_to(&mut rpc, 12.into()))
            .await
            .is_err()
    );
    assert_eq!(wallet.account().as_ref(), &original);
    assert!(wallet.deposits().is_empty());

    server.chain.lock().unwrap().unavailable = None;
    let update = wallet.sync_to(&mut rpc, 12.into()).await?;
    wallet.apply(update)?;
    assert_eq!(wallet.account().as_ref(), &updated);
    assert_eq!(
        &wallet
            .deposits()
            .iter()
            .map(|(key, deposit)| (*key, deposit.note().clone()))
            .collect::<HashMap<_, _>>(),
        &HashMap::from([(unspent.nullifier(), unspent.clone())])
    );
    let update = wallet.sync_to(&mut rpc, 12.into()).await?;
    wallet.apply(update)?;
    assert_eq!(wallet.deposits().len(), 1);
    assert!(wallet.sync_to(&mut rpc, 11.into()).await.is_err());
    assert_eq!(wallet.account().as_ref(), &updated);

    {
        let mut chain = server.chain.lock().unwrap();
        chain.tip = 20;
        chain.notes.push((18, later.clone()));
        chain.spent.push((19, unspent.nullifier()));
        chain.unavailable = Some("GetNotesById");
    }
    let mut latest = updated.clone();
    latest.set_nonce(latest.nonce() + ONE)?;
    serve_account(&server, latest.clone())?;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), wallet.sync_to(&mut rpc, 20.into()))
            .await
            .is_err()
    );
    assert_eq!(wallet.account().as_ref(), &updated);
    assert_eq!(
        &wallet
            .deposits()
            .iter()
            .map(|(key, deposit)| (*key, deposit.note().clone()))
            .collect::<HashMap<_, _>>(),
        &HashMap::from([(unspent.nullifier(), unspent)])
    );

    server.chain.lock().unwrap().unavailable = None;
    let update = wallet.sync_to(&mut rpc, 20.into()).await?;
    wallet.apply(update)?;
    assert_eq!(wallet.account().as_ref(), &latest);
    assert_eq!(
        &wallet
            .deposits()
            .iter()
            .map(|(key, deposit)| (*key, deposit.note().clone()))
            .collect::<HashMap<_, _>>(),
        &HashMap::from([(later.nullifier(), later.clone())])
    );
    wallet.remove_deposit(later.nullifier());
    let update = wallet.sync_to(&mut rpc, 20.into()).await?;
    wallet.apply(update)?;
    assert!(wallet.deposits().is_empty());
    Ok(())
}

#[rstest::rstest]
#[case("GetAccount")]
#[case("SyncNotes")]
#[case("GetNotesById")]
#[case("SyncNullifiers")]
#[tokio::test]
async fn sync_retries_transient_rpc_failures(#[case] method: &'static str) -> Result<()> {
    let fixture = Fixture::new(1_000_000, TEST_BASE_FEE)?;
    let mut wallet = fixture.wallet;
    let note: Note = miden_standards::note::P2idNote::builder()
        .sender(fixture.fee_faucet_id)
        .target(wallet.account_id())
        .asset(FungibleAsset::new(fixture.fee_faucet_id, 1_000)?)
        .note_type(miden_protocol::note::NoteType::Public)
        .serial_number(Word::from([1u32; 4]))
        .build()?
        .into();
    let mut chain = TestChain::new(12);
    chain.notes = vec![(10, note.clone())];
    chain.unavailable_for = Some((method, 1));
    let server = TestServer::start(chain).await;
    serve_account(&server, wallet.account().as_ref().clone())?;
    let update = tokio::time::timeout(
        Duration::from_secs(10),
        wallet.sync_to(&mut server.node.rpc_client(), 12.into()),
    )
    .await??;
    wallet.apply(update)?;
    assert_eq!(
        &wallet
            .deposits()
            .iter()
            .map(|(key, deposit)| (*key, deposit.note().clone()))
            .collect::<HashMap<_, _>>(),
        &HashMap::from([(note.nullifier(), note)])
    );
    Ok(())
}

#[tokio::test]
async fn sync_checks_initial_code_and_loads_later_code_updates() -> Result<()> {
    let fixture = Fixture::new(1_000_000, TEST_BASE_FEE)?;
    let block = fixture.chain.lock().await.latest_block_header().block_num();
    let mut wallet = fixture.wallet;
    let original = wallet.account().as_ref().clone();
    let (id, vault, storage, _, nonce, seed) = original.clone().into_parts();
    let updated = Account::new(
        id,
        vault,
        storage,
        miden_protocol::account::AccountCode::mock(),
        nonce + ONE,
        seed,
    )?;
    let server = TestServer::start(TestChain::new(block.as_u32())).await;
    let mut rpc = server.node.rpc_client();

    serve_account(&server, updated.clone())?;
    assert!(wallet.sync_to(&mut rpc, block).await.is_err());
    assert_eq!(wallet.account().as_ref(), &original);
    serve_account(&server, original.clone())?;
    let update = wallet.sync_to(&mut rpc, block).await?;
    wallet.apply(update)?;
    assert_eq!(wallet.account().as_ref(), &original);
    serve_account(&server, updated.clone())?;
    server.chain.lock().unwrap().tip = (block + 1).as_u32();
    let update = wallet.sync_to(&mut rpc, block + 1).await?;
    wallet.apply(update)?;
    assert_eq!(wallet.account().as_ref(), &updated);
    Ok(())
}
