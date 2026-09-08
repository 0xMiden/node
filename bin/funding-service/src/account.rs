//! Loading of the funding account.

use std::path::Path;

use anyhow::{Context, Result};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{AccountFile, AccountId, AccountType};

// FUNDER KEY
// ================================================================================================

/// The identity of the funding account, loaded from its account file.
#[derive(Clone, Debug)]
pub struct FunderKey {
    account_id: AccountId,
}

impl FunderKey {
    /// Reads the funding account and its signing key from an account file.
    pub fn load(path: &Path) -> Result<Self> {
        let account_file = AccountFile::read(path)
            .with_context(|| format!("failed to read the account file at {}", path.display()))?;

        account_file
            .auth_secret_keys
            .iter()
            .find(|key| matches!(key, AuthSecretKey::Falcon512Poseidon2(_)))
            .with_context(|| {
                format!(
                    "the account file at {} holds no Falcon512Poseidon2 secret key",
                    path.display()
                )
            })?;

        let account = account_file.account;
        anyhow::ensure!(
            account.id().account_type() == AccountType::Public,
            "the funding account {} is not public: the service reads its state from the node, \
             which only stores the full state of a public account",
            account.id(),
        );

        Ok(Self { account_id: account.id() })
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::ONE;
    use miden_protocol::account::auth::AuthScheme;
    use miden_protocol::account::{Account, AccountType};
    use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
    use miden_standards::account::auth::Approver;
    use miden_standards::account::wallets::create_basic_wallet;
    use rand::{RngExt, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;

    /// Builds a wallet the way the genesis configuration does, so the test covers the file the
    /// service actually loads.
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
            vec![AuthSecretKey::Falcon512Poseidon2(secret_key)],
        );

        let funder = FunderKey::load(&path).expect("a public wallet with a key should load");

        assert_eq!(funder.account_id(), account.id());
    }

    /// The service reads the funder's vault from the node, which is only possible for a public
    /// account.
    #[test]
    fn rejects_a_private_account() {
        let dir = tempfile::tempdir().unwrap();
        let (account, secret_key) = genesis_wallet(AccountType::Private);
        let path = write_account_file(
            dir.path(),
            &account,
            vec![AuthSecretKey::Falcon512Poseidon2(secret_key)],
        );

        let err = FunderKey::load(&path).expect_err("a private account must be rejected");
        assert!(err.to_string().contains("is not public"), "unexpected error: {err}");
    }
}
