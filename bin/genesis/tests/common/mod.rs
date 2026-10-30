//! Shared test fixtures: the dev faucet inputs (mutable, so tests can vary them), the fixture
//! nonces, and the accounts the commands take as inputs.

// Each test binary compiles its own copy of this module and exercises a different subset of it.
#![allow(dead_code)]

use miden_genesis::accounts::{build_faucet, new_distributor_with};
use miden_genesis::config::{FaucetConfig, GenesisToolConfig, Role, RoleAccounts};
use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use miden_usdcx::xreserve::encoding::{CircleDomain, DepositNonce};

/// The dev faucet seed (`0x07` repeated).
pub const FAUCET_SEED: [u8; 32] = [7; 32];

/// The dev distributor seed (`0x0d` repeated).
pub const DISTRIBUTOR_SEED: [u8; 32] = [0x0d; 32];

/// The dev token supply, in base units.
pub const TOKEN_SUPPLY: u64 = 250_000_000;

/// Two known-valid attester keys in the 33-byte compressed SEC1 form: the secp256k1 generator point
/// and its double.
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

/// The `0x`-prefixed hex string of `bytes`, the flags' byte encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
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

/// The fixed dev role id of `role`, decoded.
pub fn role_id(role: Role) -> AccountId {
    AccountId::from_hex(role_id_hex(role)).expect("the fixture ids are valid hex")
}

/// The dev faucet inputs: one holder per role, both attesters, no min burn amount.
pub fn dev_config() -> GenesisToolConfig {
    GenesisToolConfig {
        accounts: RoleAccounts {
            owner: role_id(Role::Owner),
            attest_admins: vec![role_id(Role::AttestAdmin)],
            pausers: vec![role_id(Role::Pauser)],
            unpausers: vec![role_id(Role::Unpauser)],
            blocklist_managers: vec![role_id(Role::BlocklistManager)],
        },
        faucet: FaucetConfig {
            seed: FAUCET_SEED,
            token_supply: AssetAmount::new(TOKEN_SUPPLY).expect("the dev supply is in range"),
            domain: CircleDomain::new(7),
            min_burn_amount: None,
            verification_base_fee: 500,
            attesters: attester_keys(),
        },
    }
}

/// Both fixture nonces, decoded.
pub fn used_nonces() -> Vec<DepositNonce> {
    USED_NONCE_BYTES.map(DepositNonce::new).to_vec()
}

/// The genesis faucet built from the dev inputs.
pub fn genesis_faucet() -> Account {
    build_faucet(&dev_config()).expect("the dev fixture must build")
}

/// A fresh (undeployed) distributor with an ECDSA key, deterministic in its seed.
pub fn fresh_distributor() -> AccountFile {
    new_distributor_with(DISTRIBUTOR_SEED, AuthSecretKey::new_ecdsa_k256_keccak())
        .expect("the distributor must compose")
}
