use std::process::Command;

use miden_node_store::GenesisState;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::block::ValidatorConfig;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;

#[test]
fn bootstrap_writes_logs_to_stderr() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let validators = ValidatorConfig::new(vec![SigningKey::new().public_key()], 1)?;
    let genesis =
        GenesisState::new(vec![], test_fee_params(), 0, validators, test_protocol_config())
            .into_block()?;
    fs_err::write(directory.path().join("genesis.dat"), miden_node_persistence::encode(&genesis))?;

    let output = Command::new(env!("CARGO_BIN_EXE_miden-validator"))
        .current_dir(directory.path())
        .args(["bootstrap", "--data-directory", "data", "--genesis", "genesis.dat"])
        .env("MIDEN_STDOUT_FILTER", "info")
        .output()?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(output.status.success(), "{stderr}");
    assert!(output.stdout.is_empty(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(!stderr.is_empty(), "expected bootstrap logs on stderr");
    Ok(())
}
