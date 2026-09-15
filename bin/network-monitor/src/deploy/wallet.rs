//! Wallet account creation functionality.

use std::sync::LazyLock;

use anyhow::{Context, Result};
use miden_node_tracing::miden_instrument;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentCode,
    AccountComponentMetadata,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_standards::account::auth::{Approver, AuthSingleSig};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::COMPONENT;

/// Storage slot on the wallet account holding the number of increment transactions the wallet has
/// committed.
///
/// This slot is bumped in the *same* transaction that emits the increment note (see
/// [`crate::counter`]), so it is an on-chain, atomically-committed count of *committed* increment
/// requests.
pub static WALLET_COUNTER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::monitor::wallet_contract::counter")
        .expect("storage slot name should be valid")
});

/// Module path under which the wallet's self-counter component is compiled.
///
/// The increment transaction script must reference `increment` under this exact path (via a
/// dynamically-linked copy of [`wallet_counter_component_code`]) so the `call` resolves to the
/// procedure root registered in the account.
pub const WALLET_COUNTER_COMPONENT_PATH: &str = "wallet::program";

/// The wallet self-counter component source (bumps [`WALLET_COUNTER_SLOT_NAME`]).
const WALLET_COUNTER_PROGRAM: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/assets/wallet_counter_program.masm"));

/// Compiles the wallet's self-counter [`AccountComponentCode`].
///
/// This is the single source of truth for the component: [`create_wallet_account`] builds the
/// account from it, and the increment transaction-script builder dynamically links it so
/// `call.::wallet::program::increment` resolves to the same procedure root the account registered.
/// Compilation is deterministic, so both sites obtain identical code and roots.
pub fn wallet_counter_component_code() -> Result<AccountComponentCode> {
    CodeBuilder::default()
        .compile_component_code(WALLET_COUNTER_COMPONENT_PATH, WALLET_COUNTER_PROGRAM)
        .context("failed to compile wallet counter component code")
}

/// Create a wallet account with `RpoFalcon512` authentication and a self-counter component.
///
/// Returns the created account and the secret key for authentication.
#[miden_instrument(
    target = COMPONENT,
    name = "create-wallet-account",
    ret(level = "debug"),
)]
pub fn create_wallet_account() -> Result<(Account, SecretKey)> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut rng);
    let auth_component: AccountComponent = AuthSingleSig::new(Approver::new(
        secret_key.public_key().into(),
        AuthScheme::Falcon512Poseidon2,
    ))
    .into();
    let init_seed: [u8; 32] = rng.random();

    // The wallet's custom component both bumps its counter slot and creates the increment note in
    // one account procedure (see `wallet_counter_program.masm`).
    let component_code = wallet_counter_component_code()?;

    let counter_slot = StorageSlot::with_value(WALLET_COUNTER_SLOT_NAME.clone(), Word::empty());
    let metadata = AccountComponentMetadata::new("wallet::program");
    let counter_component = AccountComponent::new(component_code, vec![counter_slot], metadata)?;

    // `BasicWallet` exposes `receive_asset`, which the P2ID note script calls on the consuming
    // account, so it is what lets the wallet claim the faucet notes that fund its fee payments.
    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_component(auth_component)
        .with_component(BasicWallet)
        .with_component(counter_component)
        .build()
        .context("failed to build wallet account")?;

    Ok((account, secret_key))
}
