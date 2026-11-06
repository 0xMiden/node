use miden_protocol::ONE;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{Account, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::{Note, Nullifier};
use miden_standards::account::auth::Approver;
use miden_standards::account::wallets::create_basic_wallet;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::node::tests::{TestChain, TestServer};
use crate::test_utils::{Fixture, TEST_BASE_FEE};

/// Applies `update`, advances the cursor past its scan, and returns the scanned deposits.
fn complete(wallet: &mut FundingWallet, update: WalletUpdate) -> Result<HashMap<Nullifier, Note>> {
    let scan = wallet.apply(update)?;
    wallet.complete_deposit_scan(scan.next_sync);
    Ok(scan_notes(&scan))
}

/// The deposits of a scan keyed by nullifier, for order-independent comparison.
fn scan_notes(scan: &DepositScan) -> HashMap<Nullifier, Note> {
    scan.deposits
        .iter()
        .map(|deposit| (deposit.nullifier(), deposit.note().clone()))
        .collect()
}

fn fee_asset_id() -> AssetId {
    AssetId::new_fungible(FungibleAsset::mock_issuer())
}

/// Builds a wallet with the authentication used by the genesis configuration.
fn genesis_wallet(account_type: AccountType, scheme: AuthScheme) -> (Account, AuthSecretKey) {
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let secret_key = AuthSecretKey::with_scheme_and_rng(scheme, &mut rng).unwrap();
    let auth = Approver::from(&secret_key.public_key());
    let init_seed: [u8; 32] = rng.random();
    let mut account =
        create_basic_wallet(init_seed, auth, account_type).expect("wallet should build");
    account.set_nonce(ONE).expect("nonce should be settable");
    (account, secret_key)
}

#[rstest::rstest]
#[case(AuthScheme::EcdsaK256Keccak)]
#[case(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn loads_public_state_from_the_node_with_only_an_id_and_key(
    #[case] scheme: AuthScheme,
) -> Result<()> {
    let (account, secret_key) = genesis_wallet(AccountType::Public, scheme);
    let server = TestServer::start(TestChain::new(12)).await;
    serve_account(&server, account.clone())?;
    let wallet = FundingWallet::load_at(
        &mut server.node.rpc_client(),
        account.id(),
        secret_key.clone(),
        fee_asset_id(),
        12.into(),
        BlockNumber::GENESIS,
    )
    .await?;

    assert_eq!(wallet.account().as_ref(), &account);
    assert_eq!(wallet.secret_key(), &secret_key);
    assert_eq!(wallet.next_sync(), BlockNumber::GENESIS);
    Ok(())
}

#[rstest::rstest]
#[case(AuthScheme::EcdsaK256Keccak)]
#[case(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn rejects_an_unrelated_signing_key(#[case] scheme: AuthScheme) {
    let (account, _) = genesis_wallet(AccountType::Public, scheme);
    let wrong_key =
        AuthSecretKey::with_scheme_and_rng(scheme, &mut ChaCha20Rng::from_seed([91; 32])).unwrap();
    let server = TestServer::start(TestChain::new(12)).await;
    serve_account(&server, account.clone()).unwrap();
    let error = FundingWallet::load_at(
        &mut server.node.rpc_client(),
        account.id(),
        wrong_key,
        fee_asset_id(),
        12.into(),
        BlockNumber::GENESIS,
    )
    .await
    .err()
    .expect("an unrelated signing key must be rejected");
    assert!(error.to_string().contains("signing key does not match"), "{error:#}");
}

#[tokio::test]
async fn rejects_a_key_with_the_wrong_signature_scheme() {
    let (mut account, key) = genesis_wallet(AccountType::Public, AuthScheme::Falcon512Poseidon2);
    account
        .storage_mut()
        .set_item(
            AuthSingleSig::scheme_id_slot(),
            Word::from([AuthScheme::EcdsaK256Keccak.as_u8(), 0, 0, 0]),
        )
        .unwrap();
    let server = TestServer::start(TestChain::new(12)).await;
    serve_account(&server, account.clone()).unwrap();
    let error = FundingWallet::load_at(
        &mut server.node.rpc_client(),
        account.id(),
        key,
        fee_asset_id(),
        12.into(),
        BlockNumber::GENESIS,
    )
    .await
    .err()
    .expect("a mismatched signature scheme must be rejected");
    assert!(error.to_string().contains("signing key does not match"), "{error:#}");
}

#[tokio::test]
async fn rejects_a_private_account() {
    let (account, secret_key) =
        genesis_wallet(AccountType::Private, AuthScheme::Falcon512Poseidon2);
    let server = TestServer::start(TestChain::new(12)).await;
    let err = FundingWallet::load_at(
        &mut server.node.rpc_client(),
        account.id(),
        secret_key,
        fee_asset_id(),
        12.into(),
        BlockNumber::GENESIS,
    )
    .await
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
    assert_eq!(wallet.next_sync, BlockNumber::GENESIS);

    let shared_account = Arc::clone(wallet.account());
    assert!(wallet.apply(update).is_err());
    assert_eq!(wallet.account().as_ref(), &original);
    assert_eq!(wallet.next_sync, BlockNumber::GENESIS);
    drop(shared_account);

    let update = wallet.sync_to(&mut rpc, 12.into()).await?;
    let scan = wallet.apply(update)?;
    assert_eq!(wallet.account().as_ref(), &updated);
    assert_eq!(scan_notes(&scan), HashMap::from([(note.nullifier(), note)]));
    assert_eq!(scan.next_sync, 13.into());
    // The cursor waits until the caller has stored the scan.
    assert_eq!(wallet.next_sync, BlockNumber::GENESIS);
    wallet.complete_deposit_scan(scan.next_sync);
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
    assert!(complete(&mut wallet, update)?.is_empty());
    let update = wallet.sync_to(&mut rpc, block + 1).await?;
    complete(&mut wallet, update)?;
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
    complete(&mut wallet, update)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), wallet.sync_to(&mut rpc, block + 2))
            .await
            .is_err()
    );
    assert_eq!(wallet.account().as_ref(), &updated);
    server.chain.lock().unwrap().unavailable = None;
    server.chain.lock().unwrap().tip = (block + 2).as_u32();
    let update = wallet.sync_to(&mut rpc, block + 2).await?;
    complete(&mut wallet, update)?;
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
    assert_eq!(wallet.next_sync, BlockNumber::GENESIS);

    // A deposit created and spent within the scanned range is excluded.
    server.chain.lock().unwrap().unavailable = None;
    let update = wallet.sync_to(&mut rpc, 12.into()).await?;
    assert_eq!(
        complete(&mut wallet, update)?,
        HashMap::from([(unspent.nullifier(), unspent.clone())])
    );
    assert_eq!(wallet.account().as_ref(), &updated);
    // Blocks already scanned are not scanned again.
    let update = wallet.sync_to(&mut rpc, 12.into()).await?;
    assert!(complete(&mut wallet, update)?.is_empty());
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
    assert_eq!(wallet.next_sync, 13.into());

    // Only deposits from the new blocks are reported. Deposits found by earlier scans are not
    // checked again: the service removes them itself when it consumes them.
    server.chain.lock().unwrap().unavailable = None;
    let update = wallet.sync_to(&mut rpc, 20.into()).await?;
    assert_eq!(complete(&mut wallet, update)?, HashMap::from([(later.nullifier(), later)]));
    assert_eq!(wallet.account().as_ref(), &latest);
    let update = wallet.sync_to(&mut rpc, 20.into()).await?;
    assert!(complete(&mut wallet, update)?.is_empty());
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
    assert_eq!(complete(&mut wallet, update)?, HashMap::from([(note.nullifier(), note)]));
    Ok(())
}

#[tokio::test]
async fn sync_loads_code_updates() -> Result<()> {
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

    serve_account(&server, original.clone())?;
    let update = wallet.sync_to(&mut rpc, block).await?;
    complete(&mut wallet, update)?;
    assert_eq!(wallet.account().as_ref(), &original);
    serve_account(&server, updated.clone())?;
    server.chain.lock().unwrap().tip = (block + 1).as_u32();
    let update = wallet.sync_to(&mut rpc, block + 1).await?;
    complete(&mut wallet, update)?;
    assert_eq!(wallet.account().as_ref(), &updated);
    Ok(())
}

// DEPOSIT CURSOR
// ================================================================================================

/// Builds a native-asset deposit for `account`.
fn deposit_for(account: &Account, serial: u32) -> UsdcxP2Id {
    let note: Note = miden_standards::note::P2idNote::builder()
        .sender(FungibleAsset::mock_issuer())
        .target(account.id())
        .asset(FungibleAsset::new(FungibleAsset::mock_issuer(), 1_000).unwrap())
        .note_type(miden_protocol::note::NoteType::Public)
        .serial_number(Word::from([serial; 4]))
        .build()
        .unwrap()
        .into();
    UsdcxP2Id::from_note(note, fee_asset_id()).unwrap()
}

/// Loads a public wallet from `server` at `block`, resuming deposit discovery at `next_sync`.
async fn restored_wallet(
    server: &TestServer,
    account: &Account,
    secret_key: AuthSecretKey,
    block: u32,
    next_sync: u32,
) -> Result<FundingWallet> {
    serve_account(server, account.clone())?;
    FundingWallet::load_at(
        &mut server.node.rpc_client(),
        account.id(),
        secret_key,
        fee_asset_id(),
        block.into(),
        next_sync.into(),
    )
    .await
}

#[tokio::test]
async fn a_restored_wallet_resumes_discovery_at_its_cursor() -> Result<()> {
    let (account, secret_key) = genesis_wallet(AccountType::Public, AuthScheme::Falcon512Poseidon2);
    let before_cursor = deposit_for(&account, 1);
    let after_cursor = deposit_for(&account, 2);
    let mut chain = TestChain::new(15);
    chain.notes =
        vec![(3, before_cursor.clone().into_note()), (12, after_cursor.clone().into_note())];
    let server = TestServer::start(chain).await;
    let mut wallet = restored_wallet(&server, &account, secret_key, 15, 11).await?;
    assert_eq!(wallet.next_sync(), BlockNumber::from(11));

    let update = wallet.sync_to(&mut server.node.rpc_client(), 15.into()).await?;
    assert_eq!(
        complete(&mut wallet, update)?,
        HashMap::from([(after_cursor.nullifier(), after_cursor.into_note())])
    );
    assert_eq!(wallet.next_sync(), BlockNumber::from(16));
    Ok(())
}

#[tokio::test]
async fn an_uncompleted_scan_is_repeated_by_the_next_sync() -> Result<()> {
    let (account, secret_key) = genesis_wallet(AccountType::Public, AuthScheme::Falcon512Poseidon2);
    let deposit = deposit_for(&account, 1);
    let mut chain = TestChain::new(15);
    chain.notes = vec![(12, deposit.clone().into_note())];
    let server = TestServer::start(chain).await;
    let mut wallet = restored_wallet(&server, &account, secret_key, 15, 11).await?;
    let expected = HashMap::from([(deposit.nullifier(), deposit.into_note())]);

    // The scan is applied but never stored, so the cursor stays put.
    let update = wallet.sync_to(&mut server.node.rpc_client(), 15.into()).await?;
    assert_eq!(scan_notes(&wallet.apply(update)?), expected);
    assert_eq!(wallet.next_sync(), BlockNumber::from(11));

    let update = wallet.sync_to(&mut server.node.rpc_client(), 15.into()).await?;
    assert_eq!(complete(&mut wallet, update)?, expected);
    Ok(())
}

#[tokio::test]
async fn an_update_that_does_not_continue_the_cursor_is_rejected() -> Result<()> {
    let (account, secret_key) = genesis_wallet(AccountType::Public, AuthScheme::Falcon512Poseidon2);
    let server = TestServer::start(TestChain::new(15)).await;
    let mut wallet = restored_wallet(&server, &account, secret_key, 15, 11).await?;

    let stale = wallet.sync_to(&mut server.node.rpc_client(), 15.into()).await?;
    let update = wallet.sync_to(&mut server.node.rpc_client(), 15.into()).await?;
    complete(&mut wallet, update)?;
    assert!(wallet.apply(stale).is_err());
    assert_eq!(wallet.next_sync(), BlockNumber::from(16));
    Ok(())
}
