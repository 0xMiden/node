//! Acceptance and rejection of the command-line flags.

use miden_protocol::address::NetworkId;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, SigningKey};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_usdcx::xreserve::encoding::CircleDomain;

use super::*;
use crate::config::Role;
use crate::test_utils::{
    ATTESTER_KEY_BYTES,
    FAUCET_SEED,
    TOKEN_SUPPLY,
    USED_NONCE_BYTES,
    attester_keys,
    role_id,
    role_id_hex,
    to_hex,
};

/// Asserts a rejection whose message names the actual cause, so the test cannot pass on an
/// unrelated error.
fn assert_error_contains(err: &clap::Error, needle: &str) {
    assert!(
        err.to_string().contains(needle),
        "the error must name the cause `{needle}`, got: {err}",
    );
}

// BUILD
// ================================================================================================

const BASE_BUILD_ARGS: [&str; 14] = [
    "miden-genesis",
    "build",
    "--genesis-block-directory",
    "/tmp/genesis",
    "--accounts-directory",
    "/tmp/accounts",
    "--native-faucet",
    "/tmp/native-faucet.mac",
    "--funding-account",
    "/tmp/funding-account.mac",
    "--verification-base-fee",
    "7",
    "--timestamp",
    "1717344256",
];

fn parse_build(extra: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(BASE_BUILD_ARGS.iter().copied().chain(extra.iter().copied()))
}

#[test]
fn build_validator_keys_parse_from_repeated_flags() {
    let keys = [7u8, 8].map(|seed| {
        SigningKey::read_from_bytes(&[seed; 32]).expect("test signing key should decode")
    });
    let hex_keys = keys.clone().map(|key| hex::encode(key.public_key().to_bytes()));
    let cli = parse_build(&["--validator.key", &hex_keys[0], "--validator.key", &hex_keys[1]])
        .expect("build with explicit validator keys must parse");
    let Command::Build(command) = cli.command else {
        panic!("expected the build command");
    };
    assert_eq!(command.validator_keys, keys.map(|key| key.public_key()).to_vec());
}

#[test]
fn build_requires_an_explicit_validator_set() {
    let Err(error) = parse_build(&[]) else {
        panic!("build without an explicit validator set must be rejected");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);

    let key = SigningKey::read_from_bytes(&[7; 32]).expect("test signing key should decode");
    let key_hex = hex::encode(key.public_key().to_bytes());
    parse_build(&["--accounts-config", "/tmp/accounts.toml", "--validator.key", &key_hex])
        .expect("additional accounts with an explicit validator set must parse");
}

#[test]
fn build_requires_explicit_accounts_fee_and_timestamp() {
    let key = SigningKey::new();
    let key_hex = hex::encode(key.public_key().to_bytes());
    for flag in ["--native-faucet", "--funding-account", "--verification-base-fee", "--timestamp"] {
        let position = BASE_BUILD_ARGS.iter().position(|value| *value == flag).unwrap();
        let args = BASE_BUILD_ARGS
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != position && *index != position + 1)
            .map(|(_, value)| *value)
            .chain(["--validator.key", key_hex.as_str()]);
        let Err(error) = Cli::try_parse_from(args) else {
            panic!("build must require {flag}");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument, "{flag}");
    }
}

#[test]
fn build_rejects_an_invalid_validator_key() {
    let Err(error) = parse_build(&["--validator.key", "not-hex"]) else {
        panic!("an invalid validator key must be rejected");
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
}

// ACCOUNT COMMANDS
// ================================================================================================

#[test]
fn account_commands_parse_with_defaults() {
    for args in [
        vec!["miden-genesis", "new-distributor"],
        vec![
            "miden-genesis",
            "faucet",
            "--owner",
            "0x3cd7940c4946bad179675b1d7d8059",
            "--seed",
            &"07".repeat(32),
            "--token-supply",
            "100000000",
            "--verification-base-fee",
            "7",
        ],
        vec!["miden-genesis", "prefund"],
        vec!["miden-genesis", "record-nonces", "--nonce", &"55".repeat(32)],
    ] {
        Cli::try_parse_from(args).expect("account command must parse with its required flags");
    }
}

// FAUCET
// ================================================================================================

/// The `faucet` flags of the dev fixture: one holder per role, both attesters.
fn dev_faucet_args() -> Vec<String> {
    [
        "miden-genesis",
        "faucet",
        "--owner",
        role_id_hex(Role::Owner),
        "--attest-admin",
        role_id_hex(Role::AttestAdmin),
        "--pauser",
        role_id_hex(Role::Pauser),
        "--unpauser",
        role_id_hex(Role::Unpauser),
        "--blocklist-manager",
        role_id_hex(Role::BlocklistManager),
        "--seed",
        &to_hex(&FAUCET_SEED),
        "--token-supply",
        &TOKEN_SUPPLY.to_string(),
        "--domain",
        "7",
        "--verification-base-fee",
        "500",
        "--attester",
        &to_hex(&ATTESTER_KEY_BYTES[0]),
        "--attester",
        &to_hex(&ATTESTER_KEY_BYTES[1]),
    ]
    .map(str::to_string)
    .to_vec()
}

/// Parses `faucet` flags into the typed inputs.
fn parse_faucet(args: &[String]) -> Result<GenesisToolConfig, clap::Error> {
    let Command::Faucet { config } = Cli::try_parse_from(args)?.command else {
        panic!("expected the faucet command");
    };
    Ok(config)
}

/// Replaces the value following `flag` in `args`.
fn set_flag(args: &mut [String], flag: &str, value: &str) {
    let position = args.iter().position(|arg| arg == flag).expect("the flag is present");
    args[position + 1] = value.to_string();
}

/// Removes `flag` and its value from `args`.
fn remove_flag(args: &mut Vec<String>, flag: &str) {
    let position = args.iter().position(|arg| arg == flag).expect("the flag is present");
    args.drain(position..position + 2);
}

/// The dev flags parse, and the typed inputs reflect them.
#[test]
fn the_dev_flags_round_trip() {
    let config = parse_faucet(&dev_faucet_args()).expect("the dev flags must parse");
    assert_eq!(config.faucet.seed, FAUCET_SEED);
    assert_eq!(config.faucet.token_supply.as_u64(), TOKEN_SUPPLY);
    assert_eq!(config.faucet.domain, CircleDomain::new(7));
    assert_eq!(config.faucet.verification_base_fee, 500);
    assert!(config.faucet.min_burn_amount.is_none());
    assert_eq!(
        config.faucet.attesters.iter().map(PublicKey::to_commitment).collect::<Vec<_>>(),
        attester_keys().iter().map(PublicKey::to_commitment).collect::<Vec<_>>(),
        "the attester keys must decode from their SEC1 bytes",
    );
    for role in Role::ALL {
        assert_eq!(
            config.accounts.get(role),
            [role_id(role)],
            "the {} id must round-trip through the hex form",
            role.as_str(),
        );
    }
}

/// The domain defaults to the Miden domain; the operational roles, the attesters and the min burn
/// amount default to none.
#[test]
fn only_the_owner_seed_supply_and_fee_are_required() {
    let config = parse_faucet(
        &[
            "miden-genesis",
            "faucet",
            "--owner",
            role_id_hex(Role::Owner),
            "--seed",
            &to_hex(&FAUCET_SEED),
            "--token-supply",
            "100000000",
            "--verification-base-fee",
            "7",
        ]
        .map(str::to_string),
    )
    .expect("the minimal flags must parse");
    assert_eq!(config.faucet.domain, CircleDomain::MIDEN);
    assert!(config.faucet.min_burn_amount.is_none());
    assert_eq!(config.faucet.attesters, [] as [PublicKey; 0]);
    for role in Role::ALL.into_iter().filter(|role| *role != Role::Owner) {
        assert!(config.accounts.get(role).is_empty(), "{} defaults to no holder", role.as_str());
    }

    for flag in ["--owner", "--seed", "--token-supply", "--verification-base-fee"] {
        let mut args = dev_faucet_args();
        remove_flag(&mut args, flag);
        let err = parse_faucet(&args).expect_err("the flag must be required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument, "{flag}");
    }
}

/// A list flag takes repeated flags and comma-separated values alike.
#[test]
fn list_flags_take_repeats_and_commas() {
    let extra = "0x2bb51b585b2a98916aebb827cc5899";
    let mut args = dev_faucet_args();
    set_flag(&mut args, "--pauser", &format!("{},{extra}", role_id_hex(Role::Pauser)));
    args.extend(["--unpauser".to_string(), extra.to_string()]);
    let config = parse_faucet(&args).expect("list flags must parse");
    assert_eq!(config.accounts.pausers.len(), 2, "a comma separates two pausers");
    assert_eq!(config.accounts.unpausers.len(), 2, "a repeated flag adds an unpauser");
}

/// A bech32 account id parses to the same id as its hex form.
#[test]
fn a_bech32_account_id_is_accepted() {
    let mut args = dev_faucet_args();
    set_flag(&mut args, "--owner", &role_id(Role::Owner).to_bech32(NetworkId::Testnet));
    assert_eq!(
        parse_faucet(&args).expect("a bech32 owner must parse").accounts.owner,
        role_id(Role::Owner),
        "the bech32 form must decode to the same id as the hex form",
    );
}

/// An account id that parses as neither hex nor bech32 is rejected, with the error naming the
/// failed parse.
#[test]
fn a_malformed_account_id_is_rejected() {
    for (bad_id, cause) in [
        ("0xnothex", "failed to parse hex string into account ID"),
        ("definitely-not-bech32", "failed to decode bech32 string into account ID"),
    ] {
        let mut args = dev_faucet_args();
        set_flag(&mut args, "--owner", bad_id);
        let err = parse_faucet(&args).expect_err("a malformed account id must be rejected");
        assert_error_contains(&err, cause);
    }
}

/// An attester key that is not a valid 33-byte compressed secp256k1 point is rejected, with a wrong
/// length named: a 20-byte value, a truncated key, and a key with an invalid SEC1 tag byte.
#[test]
fn a_malformed_attester_key_is_rejected() {
    for (bad_key, cause) in [
        (to_hex(&[0xfcu8; 20]), "expected 33 bytes, got 20"),
        (to_hex(&[2u8; 32]), "expected 33 bytes, got 32"),
        (to_hex(&[5u8; 33]), "Invalid public key"),
        ("0xzz".to_string(), "Invalid character"),
    ] {
        let mut args = dev_faucet_args();
        set_flag(&mut args, "--attester", &bad_key);
        let err = parse_faucet(&args).expect_err("a malformed attester key must be rejected");
        assert_error_contains(&err, cause);
    }
}

/// A token supply that is not a valid asset amount is rejected at parse time, as it could otherwise
/// exceed the hardcoded supply cap.
#[test]
fn an_out_of_range_token_supply_is_rejected() {
    let mut args = dev_faucet_args();
    set_flag(&mut args, "--token-supply", &u64::MAX.to_string());
    let err = parse_faucet(&args).expect_err("an out-of-range token supply must be rejected");
    assert_error_contains(&err, "exceeds the max allowed amount");
}

/// A faucet seed that is not exactly 32 bytes is rejected.
#[test]
fn a_wrong_length_seed_is_rejected() {
    let mut args = dev_faucet_args();
    set_flag(&mut args, "--seed", &to_hex(&[7u8; 4]));
    let err = parse_faucet(&args).expect_err("a wrong-length seed must be rejected");
    assert_error_contains(&err, "expected 32 bytes, got 4");
}

// RECORD NONCES
// ================================================================================================

/// Parses `record-nonces` flags into the typed nonces.
fn parse_nonces(nonce_flags: &[&str]) -> Result<Vec<DepositNonce>, clap::Error> {
    let args = ["miden-genesis", "record-nonces"]
        .into_iter()
        .chain(nonce_flags.iter().copied());
    let Command::RecordNonces { nonces, .. } = Cli::try_parse_from(args)?.command else {
        panic!("expected the record-nonces command");
    };
    Ok(nonces)
}

/// Repeated and comma-separated nonces decode to their bytes.
#[test]
fn nonces_parse_from_repeats_and_commas() {
    let [first, second] = USED_NONCE_BYTES.map(|bytes| to_hex(&bytes));
    let expected = USED_NONCE_BYTES.map(DepositNonce::new);
    assert_eq!(
        parse_nonces(&["--nonce", &first, "--nonce", &second]).expect("repeated flags parse"),
        expected,
    );
    assert_eq!(
        parse_nonces(&["--nonce", &format!("{first},{second}")]).expect("a comma list parses"),
        expected,
    );
}

/// At least one nonce is required.
#[test]
fn at_least_one_nonce_is_required() {
    let err = parse_nonces(&[]).expect_err("record-nonces without a nonce must be rejected");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

/// A nonce that is not exactly 32 bytes is rejected.
#[test]
fn a_wrong_length_nonce_is_rejected() {
    let err = parse_nonces(&["--nonce", &to_hex(&[0x66u8; 4])])
        .expect_err("a wrong-length nonce must be rejected");
    assert_error_contains(&err, "expected 32 bytes, got 4");
}
