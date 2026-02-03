//! Wallet account creation functionality.

use std::path::Path;

use anyhow::Result;
use miden_node_utils::crypto::get_rpo_random_coin;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountFile, AccountStorageMode, AccountType};
use miden_protocol::crypto::dsa::falcon512_rpo::SecretKey;
use miden_standards::AuthScheme;
use miden_standards::account::wallets::create_basic_wallet;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::instrument;

use crate::COMPONENT;

/// Create a wallet account with `RpoFalcon512` authentication.
///
/// Returns the created account and the secret key for authentication.
#[instrument(target = COMPONENT, name = "create-wallet-account", skip_all, ret(level = "debug"))]
pub fn create_wallet_account() -> Result<(Account, SecretKey)> {
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let secret_key = SecretKey::with_rng(&mut get_rpo_random_coin(&mut rng));
    let auth = AuthScheme::Falcon512Rpo { pub_key: secret_key.public_key().into() };
    let init_seed: [u8; 32] = rng.random();

    let wallet_account = create_basic_wallet(
        init_seed,
        auth,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    )?;

    Ok((wallet_account, secret_key))
}

/// Save wallet account to disk together with its authentication key.
pub fn save_wallet_account(
    account: &Account,
    secret_key: &SecretKey,
    file_path: &Path,
) -> Result<()> {
    let auth_secret_key = AuthSecretKey::Falcon512Rpo(secret_key.clone());
    let account_file = AccountFile::new(account.clone(), vec![auth_secret_key]);
    account_file.write(file_path)?;
    Ok(())
}
