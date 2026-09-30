//! Schema acceptance and rejections of the two input files: the config and the nonces.

mod common;

use assert_matches::assert_matches;
use miden_protocol::account::AccountId;
use miden_protocol::address::NetworkId;
use xusdc_encoding::xreserve::encoding::{CircleDomain, DepositNonce};
use xusdc_genesis::config::{ConfigError, GenesisToolConfig, Role, UsedNoncesFile};

use crate::common::{
    attester_keys, role_id_hex, to_hex, Fixture, NoncesFixture, ATTESTER_KEY_BYTES, TOKEN_SUPPLY,
    USED_NONCE_BYTES,
};

/// The dev fixture parses, and the typed config reflects it.
#[test]
fn the_dev_fixture_round_trips() {
    let fixture = Fixture::new();
    let config = fixture.config();
    assert_eq!(config.faucet.token_supply.as_u64(), TOKEN_SUPPLY);
    assert_eq!(config.faucet.domain, CircleDomain::new(7));
    assert_eq!(config.faucet.verification_base_fee, 500);
    assert!(config.faucet.min_burn_amount.is_none());
    assert_eq!(
        config
            .faucet
            .attesters
            .iter()
            .map(|key| key.to_commitment())
            .collect::<Vec<_>>(),
        attester_keys()
            .iter()
            .map(|key| key.to_commitment())
            .collect::<Vec<_>>(),
        "the attester keys must decode from their configured SEC1 bytes",
    );
    for role in Role::ALL {
        let members = config.accounts.get(role);
        assert_eq!(
            members.len(),
            1,
            "the {} fixture seeds one holder",
            role.as_str()
        );
        assert_eq!(
            members[0].to_hex(),
            role_id_hex(role),
            "the {} id must round-trip through the hex form",
            role.as_str(),
        );
    }
}

/// A bech32 account id parses to the same id as its hex form.
#[test]
fn a_bech32_account_id_is_accepted() {
    let hex = role_id_hex(Role::Owner);
    let id = AccountId::from_hex(hex).expect("the fixture id is valid hex");
    let mut fixture = Fixture::new();
    fixture.json["accounts"]["owner"] = serde_json::Value::from(id.to_bech32(NetworkId::Testnet));
    assert_eq!(
        fixture.config().accounts.owner,
        id,
        "the bech32 form must decode to the same id as the hex form",
    );
}

/// Asserts a parse rejection whose message names the actual cause, so the test cannot pass on
/// an unrelated schema violation.
fn assert_parse_error_contains(err: ConfigError, needle: &str) {
    assert_matches!(err, ConfigError::Parse(source) => {
        assert!(
            source.to_string().contains(needle),
            "the parse error must name the cause `{needle}`, got: {source}",
        );
    });
}

/// An account id that parses as neither hex nor bech32 is rejected, with the error naming the
/// failed parse.
#[test]
fn a_malformed_account_id_is_rejected() {
    for (bad_id, cause) in [
        ("0xnothex", "failed to parse hex string into account ID"),
        (
            "definitely-not-bech32",
            "failed to decode bech32 string into account ID",
        ),
    ] {
        let mut fixture = Fixture::new();
        fixture.json["accounts"]["owner"] = serde_json::Value::from(bad_id);
        let err = fixture
            .parse()
            .expect_err("a malformed account id must be rejected");
        assert_parse_error_contains(err, cause);
    }
}

/// An absent attester list parses as an empty allowlist (seeded later via set_attester).
#[test]
fn an_absent_attester_list_is_an_empty_allowlist() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]
        .as_object_mut()
        .expect("the faucet section is an object")
        .remove("attesters");
    assert!(
        fixture.config().faucet.attesters.is_empty(),
        "an absent attesters field must parse as an empty allowlist",
    );
}

/// An attester key that is not a valid 33-byte compressed secp256k1 point is rejected, with a
/// wrong length named: a 20-byte value, a truncated key, and a key with an invalid SEC1 tag
/// byte.
#[test]
fn a_malformed_attester_key_is_rejected() {
    for (bad_key, cause) in [
        (to_hex(&[0xfcu8; 20]), "expected 33 bytes, got 20"),
        (to_hex(&[2u8; 32]), "expected 33 bytes, got 32"),
        (to_hex(&[5u8; 33]), "Invalid public key"),
        ("0xzz".to_string(), "Invalid character"),
    ] {
        let mut fixture = Fixture::new();
        fixture.json["faucet"]["attesters"][0] = serde_json::Value::from(bad_key);
        let err = fixture
            .parse()
            .expect_err("a malformed attester key must be rejected");
        assert_parse_error_contains(err, cause);
    }
}

/// A token supply that is not a valid asset amount is rejected at parse time — it could
/// otherwise exceed the hardcoded supply cap.
#[test]
fn an_out_of_range_token_supply_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]["token_supply"] = serde_json::Value::from(u64::MAX);
    let err = fixture
        .parse()
        .expect_err("an out-of-range token supply must be rejected");
    assert_parse_error_contains(err, "exceeds the max allowed amount");
}

/// A faucet seed that is not exactly 32 bytes is a schema violation.
#[test]
fn a_wrong_length_seed_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]["seed"] = serde_json::Value::from(to_hex(&[7u8; 4]));
    let err = fixture
        .parse()
        .expect_err("a wrong-length seed must be rejected");
    assert_parse_error_contains(err, "expected 32 bytes, got 4");
}

/// An unknown field anywhere in the document is a schema violation (`deny_unknown_fields`);
/// so is `used_nonces`, which lives in the nonces file, not the config.
#[test]
fn an_unknown_field_is_rejected() {
    for field in ["surprise", "used_nonces"] {
        let mut fixture = Fixture::new();
        fixture.json["faucet"][field] = serde_json::Value::from(1u64);
        let err = fixture
            .parse()
            .expect_err("an unknown field must be rejected");
        assert_parse_error_contains(err, "unknown field");
    }
}

// TEMPLATE
// ================================================================================================

/// Fails on any string value that is still a `<...>` placeholder.
fn assert_no_placeholders(value: &serde_json::Value, path: &str) {
    match value {
        serde_json::Value::String(text) => {
            assert!(
                !text.starts_with('<'),
                "the placeholder at {path} must be filled by the test, got: {text}",
            );
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_no_placeholders(item, &format!("{path}[{index}]"));
            }
        }
        serde_json::Value::Object(fields) => {
            for (name, field) in fields {
                assert_no_placeholders(field, &format!("{path}.{name}"));
            }
        }
        _ => {}
    }
}

/// The checked-in template does not parse as it is (its placeholders force the operator to
/// fill it), and parses once every placeholder is filled — so its placeholders sit exactly at
/// the fields the schema has, with the pre-filled values intact.
#[test]
fn the_template_parses_once_its_placeholders_are_filled() {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.template.json"))
            .expect("the template is readable");
    assert!(
        GenesisToolConfig::from_json(&text).is_err(),
        "the unfilled template must not parse",
    );

    let mut json: serde_json::Value =
        serde_json::from_str(&text).expect("the template is valid JSON");
    json["accounts"]["owner"] = serde_json::Value::from(role_id_hex(Role::Owner));
    json["faucet"]["attesters"] = serde_json::json!([to_hex(&ATTESTER_KEY_BYTES[0])]);
    assert_no_placeholders(&json, "config");

    let config =
        GenesisToolConfig::from_json(&json.to_string()).expect("the filled template parses");
    assert_eq!(
        config.faucet.token_supply.as_u64(),
        100_000_000,
        "the template pre-fills the launch supply, 100 USDC in base units"
    );
    let mut seed = [0u8; 32];
    seed[..12].copy_from_slice(b"USDCX-FAUCET");
    assert_eq!(
        config.faucet.seed, seed,
        "the template pre-fills the faucet seed with the padded ASCII marker"
    );
    assert_eq!(
        config.faucet.verification_base_fee, 7,
        "the template pre-fills the launch verification base fee"
    );
    assert_eq!(
        config.faucet.domain,
        CircleDomain::new(10007),
        "the template pre-fills the Miden domain"
    );
    assert_eq!(config.faucet.min_burn_amount, Some(1));
    for role in Role::ALL.into_iter().filter(|role| *role != Role::Owner) {
        assert!(
            config.accounts.get(role).is_empty(),
            "the template leaves the operational roles for the bootstrap admin to assign",
        );
    }
}

// NONCES FILE
// ================================================================================================

/// The nonces fixture parses to its typed nonces.
#[test]
fn the_nonces_fixture_parses() {
    let nonces = NoncesFixture::new()
        .parse()
        .expect("the nonces fixture must parse");
    assert_eq!(
        nonces.used_nonces,
        USED_NONCE_BYTES.map(DepositNonce::new),
        "the nonces must decode from their configured bytes",
    );
}

/// The checked-in nonces template does not parse as it is, and parses once its placeholder is
/// filled.
#[test]
fn the_nonces_template_parses_once_its_placeholder_is_filled() {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/nonces.template.json"))
            .expect("the template is readable");
    assert!(
        UsedNoncesFile::from_json(&text).is_err(),
        "the unfilled template must not parse",
    );

    let mut json: serde_json::Value =
        serde_json::from_str(&text).expect("the template is valid JSON");
    json["used_nonces"] = serde_json::json!([to_hex(&USED_NONCE_BYTES[0])]);
    assert_no_placeholders(&json, "nonces");

    let nonces = UsedNoncesFile::from_json(&json.to_string()).expect("the filled template parses");
    assert_eq!(nonces.used_nonces, [DepositNonce::new(USED_NONCE_BYTES[0])]);
}

/// A nonce that is not exactly 32 bytes is a schema violation.
#[test]
fn a_wrong_length_nonce_is_rejected() {
    let mut fixture = NoncesFixture::new();
    fixture.json["used_nonces"][1] = serde_json::Value::from(to_hex(&[0x66u8; 4]));
    let err = fixture
        .parse()
        .expect_err("a wrong-length nonce must be rejected");
    assert_parse_error_contains(err, "expected 32 bytes, got 4");
}

/// The nonce list is required: a file without it is not a nonces file.
#[test]
fn a_missing_nonce_list_is_rejected() {
    let mut fixture = NoncesFixture::new();
    fixture.json = serde_json::json!({});
    let err = fixture
        .parse()
        .expect_err("a missing nonce list must be rejected");
    assert_parse_error_contains(err, "missing field `used_nonces`");
}

/// An unknown field in the nonces file is a schema violation.
#[test]
fn an_unknown_nonces_field_is_rejected() {
    let mut fixture = NoncesFixture::new();
    fixture.json["surprise"] = serde_json::Value::from(1u64);
    let err = fixture
        .parse()
        .expect_err("an unknown field must be rejected");
    assert_parse_error_contains(err, "unknown field");
}
