//! The `new-distributor` command run end to end through the binary.

use std::slice::from_ref;

use miden_genesis::output::{DISTRIBUTOR_MAC_FILE, DISTRIBUTOR_SECRET_FILE, read_account_file};
use miden_protocol::ONE;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::utils::serde::Deserializable;
use miden_testing::MockChainBuilder;
use miden_tx::auth::BasicAuthenticator;

/// Account generation provides the same signing key in the account file and the standalone file.
#[rstest::rstest]
#[case("ecdsa-k256-keccak")]
#[case("falcon512-eidos")]
#[tokio::test]
async fn generated_signing_key_is_private_and_matches_the_account(#[case] scheme: &str) {
    let dir = tempfile::tempdir().unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_miden-genesis"))
        .args(["new-distributor", "--auth-scheme", scheme])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let account = read_account_file(&dir.path().join(DISTRIBUTOR_MAC_FILE)).unwrap();
    let key_path = dir.path().join(DISTRIBUTOR_SECRET_FILE);
    let key = AuthSecretKey::read_from_bytes(&fs_err::read(&key_path).unwrap()).unwrap();
    assert_eq!(account.auth_secret_keys(), from_ref(&key));

    let mut wallet = account.account().clone();
    wallet.set_nonce(ONE).unwrap();
    let chain = MockChainBuilder::with_accounts([wallet.clone()]).unwrap().build().unwrap();
    let executed = Box::pin(
        chain
            .build_transaction(wallet.id())
            .authenticator(Some(BasicAuthenticator::new(&[key])))
            .build()
            .unwrap()
            .execute(),
    )
    .await
    .unwrap();
    assert_ne!(executed.tx_inputs().signatures(), []);
    assert_eq!(executed.final_account().id(), wallet.id());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(fs_err::metadata(key_path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
