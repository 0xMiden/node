//! Shared test fixtures: the dev config JSON (mutable, so tests can inject malformed values),
//! the nonces JSON, and the accounts the commands take as inputs.

// Each test binary compiles its own copy of this module and exercises a different subset of it.
#![allow(dead_code)]

use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::Account;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use xusdc_genesis::accounts::{build_faucet, new_distributor_with};
use xusdc_genesis::config::{ConfigError, GenesisToolConfig, Role, UsedNoncesFile};

/// The dev faucet seed (`0x07` repeated).
pub const FAUCET_SEED: [u8; 32] = [7; 32];

/// The dev distributor seed (`0x0d` repeated).
pub const DISTRIBUTOR_SEED: [u8; 32] = [0x0d; 32];

/// The dev token supply, in base units.
pub const TOKEN_SUPPLY: u64 = 250_000_000;

/// Two known-valid attester keys in the 33-byte compressed SEC1 form: the secp256k1 generator
/// point and its double.
pub const ATTESTER_KEY_BYTES: [[u8; 33]; 2] = [
    [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ],
    [
        0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D, 0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0,
        0x7C, 0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C, 0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C,
        0x70, 0x9E, 0xE5,
    ],
];

/// Two fixture deposit nonces, the `record-nonces` input.
pub const USED_NONCE_BYTES: [[u8; 32]; 2] = [[0x55; 32], [0x66; 32]];

/// The `0x`-prefixed hex string of `bytes` — the config's byte encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{hex}")
}

/// The fixture attester keys, decoded.
pub fn attester_keys() -> Vec<PublicKey> {
    ATTESTER_KEY_BYTES
        .iter()
        .map(|bytes| PublicKey::read_from_bytes(bytes).expect("the fixture keys are valid"))
        .collect()
}

/// The fixed dev role ids, as hex strings.
pub fn role_id_hex(role: Role) -> &'static str {
    match role {
        Role::Owner => "0x3cd7940c4946bad179675b1d7d8059",
        Role::AttestAdmin => "0x2bb51b585b2a98916aebb827cc5804",
        Role::Pauser => "0x88dc763b163d53513c4ea2c4f5f1f7",
        Role::Unpauser => "0x83b89e07263e3b51799cb3af134d6d",
        Role::BlocklistManager => "0x5cf939821efad05159595966886192",
    }
}

/// A materialized dev fixture: the config JSON, mutable so tests can inject malformed values.
pub struct Fixture {
    pub json: serde_json::Value,
}

impl Fixture {
    /// Assembles the dev config.
    pub fn new() -> Self {
        let mut accounts = serde_json::Map::new();
        for role in Role::ALL {
            let value = if role == Role::Owner {
                serde_json::Value::from(role_id_hex(role))
            } else {
                serde_json::Value::from(vec![role_id_hex(role)])
            };
            accounts.insert(role.as_str().to_string(), value);
        }
        let json = serde_json::json!({
            "accounts": accounts,
            "faucet": {
                "seed": to_hex(&FAUCET_SEED),
                "token_supply": TOKEN_SUPPLY,
                "domain": 7,
                "verification_base_fee": 500,
                "attesters": [to_hex(&ATTESTER_KEY_BYTES[0]), to_hex(&ATTESTER_KEY_BYTES[1])],
            },
        });
        Self { json }
    }

    /// Parses the (possibly mutated) config JSON.
    pub fn parse(&self) -> Result<GenesisToolConfig, ConfigError> {
        GenesisToolConfig::from_json(&self.json.to_string())
    }

    /// Parses the config JSON, expecting it to be valid.
    pub fn config(&self) -> GenesisToolConfig {
        self.parse().expect("the fixture config must parse")
    }
}

/// The nonces JSON listing both fixture nonces, mutable so tests can inject malformed values.
pub struct NoncesFixture {
    pub json: serde_json::Value,
}

impl NoncesFixture {
    pub fn new() -> Self {
        let json = serde_json::json!({
            "used_nonces": [to_hex(&USED_NONCE_BYTES[0]), to_hex(&USED_NONCE_BYTES[1])],
        });
        Self { json }
    }

    /// Parses the (possibly mutated) nonces JSON.
    pub fn parse(&self) -> Result<UsedNoncesFile, ConfigError> {
        UsedNoncesFile::from_json(&self.json.to_string())
    }
}

/// The genesis faucet built from the dev config.
pub fn genesis_faucet() -> Account {
    build_faucet(&Fixture::new().config()).expect("the dev fixture must build")
}

/// A fresh (undeployed) distributor with an ECDSA key, deterministic in its seed.
pub fn fresh_distributor() -> AccountFile {
    new_distributor_with(DISTRIBUTOR_SEED, AuthSecretKey::new_ecdsa_k256_keccak())
        .expect("the distributor must compose")
}
