//! Wallet account creation functionality.

use std::sync::LazyLock;

use anyhow::{Context, Result};
use miden_node_utils::crypto::get_random_coin;
use miden_node_utils::tracing::miden_instrument;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentMetadata,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_standards::account::auth::{Approver, AuthSingleSig};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use rand::{Rng, SeedableRng};
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

/// Create a wallet account with `RpoFalcon512` authentication and a self-counter component.
///
/// Returns the created account and the secret key for authentication.
#[miden_instrument(
    target = COMPONENT,
    name = "create-wallet-account",
    skip_all,
    ret(level = "debug"),
)]
pub fn create_wallet_account() -> Result<(Account, SecretKey)> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut get_random_coin(&mut rng));
    let auth_component: AccountComponent = AuthSingleSig::new(Approver::new(
        secret_key.public_key().into(),
        AuthScheme::Falcon512Poseidon2,
    ))
    .into();
    let init_seed: [u8; 32] = rng.random();

    // The wallet carries its own counter component so it can increment a storage slot in the same
    // transaction that emits the increment note. See `WALLET_COUNTER_SLOT_NAME`.
    let script = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/assets/wallet_counter_program.masm"
    ));
    let component_code =
        CodeBuilder::default().compile_component_code("wallet::program", script)?;

    let counter_slot = StorageSlot::with_value(WALLET_COUNTER_SLOT_NAME.clone(), Word::empty());
    let metadata = AccountComponentMetadata::new("wallet::program");
    let counter_component = AccountComponent::new(component_code, vec![counter_slot], metadata)?;

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_auth_component(auth_component)
        .with_component(BasicWallet)
        .with_component(counter_component)
        .build()
        .context("failed to build wallet account")?;

    Ok((account, secret_key))
}
