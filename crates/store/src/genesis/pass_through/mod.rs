use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_standards::account::auth::AuthTxFeeCollector;
use miden_standards::account::wallets::BasicWallet;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Builds a public fee collector and its signing key for genesis.
///
/// The account forwards input-note assets to a P2ID note without changing its state.
pub fn build_pass_through_account() -> anyhow::Result<(Account, SecretKey)> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut rng);
    let account = AccountBuilder::new(rng.random())
        .account_type(AccountType::Public)
        .with_component(AuthTxFeeCollector::falcon512_poseidon2(secret_key.public_key()))
        .with_component(BasicWallet)
        .build_existing()?;

    Ok((account, secret_key))
}
