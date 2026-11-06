//! The `new-distributor` command run end to end through the binary.

use miden_genesis::output::{DISTRIBUTOR_MAC_FILE, DISTRIBUTOR_SECRET_FILE, read_account_file};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::utils::serde::Deserializable;

/// Account generation provides the same signing key in the account file and the standalone file.
#[rstest::rstest]
#[case("ecdsa-k256-keccak")]
#[case("falcon512-poseidon2")]
fn generated_signing_key_is_private_and_matches_the_account(#[case] scheme: &str) {
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
    assert_eq!(account.auth_secret_keys(), &[key]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(fs_err::metadata(key_path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
