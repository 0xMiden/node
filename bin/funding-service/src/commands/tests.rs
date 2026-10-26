use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::utils::serde::Serializable;

use super::*;

#[test]
fn bootstrap_requires_exactly_one_genesis_source() {
    let account_id = miden_protocol::account::AccountId::try_from(
        miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    )
    .unwrap()
    .to_hex();
    let args = [
        "miden-funding-service",
        "bootstrap",
        "--data-directory",
        "data",
        "--account-id",
        &account_id,
    ];
    assert!(FundingServiceCommand::try_parse_from(args).is_err());
    for source in [["--genesis", "genesis.dat"], ["--network", "testnet"]] {
        assert!(FundingServiceCommand::try_parse_from(args.into_iter().chain(source)).is_ok());
    }
    assert!(
        FundingServiceCommand::try_parse_from(args.into_iter().chain([
            "--genesis",
            "genesis.dat",
            "--network",
            "testnet"
        ]))
        .is_err()
    );
}

#[test]
fn start_requires_a_data_directory_and_migrate_runs_without_node_arguments() {
    let key = hex::encode(SigningKey::new().public_key().to_bytes());
    let args = [
        "miden-funding-service",
        "start",
        "--listen",
        "127.0.0.1:50401",
        "--rpc.url",
        "http://127.0.0.1:57291",
        "--signing-key-file",
        "funding.secret",
        "--validator-signing-public-key",
        &key,
    ];
    assert!(FundingServiceCommand::try_parse_from(args).is_err());
    assert!(
        FundingServiceCommand::try_parse_from(args.into_iter().chain(["--data-directory", "data"]))
            .is_ok()
    );
    assert!(
        FundingServiceCommand::try_parse_from([
            "miden-funding-service",
            "migrate",
            "--data-directory",
            "data",
        ])
        .is_ok()
    );
}
