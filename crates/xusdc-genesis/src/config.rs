//! The tool's input-file schemas: the faucet config ([`GenesisToolConfig`]) and the consumed
//! deposit nonces ([`UsedNoncesFile`]).

use std::path::{Path, PathBuf};

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use serde::de::{DeserializeOwned, Deserializer, Error as _};
use serde::Deserialize;
use xusdc_encoding::xreserve::encoding::{CircleDomain, DepositNonce};

// ROLES
// ================================================================================================

/// The five faucet roles the `XReserveStablecoinBuilder` seeds (`ADMIN`, `ATTEST_ADMIN`,
/// `DOM_PAUSER`, `DOM_UNPAUSER`, `BLK_MANAGER`). `ADMIN` has exactly one holder; the four
/// operational roles take zero or more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    AttestAdmin,
    Pauser,
    Unpauser,
    BlocklistManager,
}

impl Role {
    /// Every role, in the stable order the outputs are emitted in.
    pub const ALL: [Role; 5] = [
        Role::Owner,
        Role::AttestAdmin,
        Role::Pauser,
        Role::Unpauser,
        Role::BlocklistManager,
    ];

    /// The role's config-field name, doubling as its name in the stdout listing.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::AttestAdmin => "attest_admins",
            Role::Pauser => "pausers",
            Role::Unpauser => "unpausers",
            Role::BlocklistManager => "blocklist_managers",
        }
    }
}

// CONFIG
// ================================================================================================

/// The tool config: the role holders' account ids and the [`FaucetConfig`]. Unknown fields are
/// rejected. The crate's `config.template.json` is its placeholder form.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisToolConfig {
    pub accounts: RoleAccounts,
    pub faucet: FaucetConfig,
}

/// The role holders' account ids, each id given as `0x`-prefixed hex or as bech32. `owner` is
/// the single `ADMIN` holder; the four operational roles take a list of zero or more holders
/// (absent means empty — the role is populated later through the standard role-action note).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAccounts {
    #[serde(deserialize_with = "account_id")]
    pub owner: AccountId,
    #[serde(default, deserialize_with = "account_ids")]
    pub attest_admins: Vec<AccountId>,
    #[serde(default, deserialize_with = "account_ids")]
    pub pausers: Vec<AccountId>,
    #[serde(default, deserialize_with = "account_ids")]
    pub unpausers: Vec<AccountId>,
    #[serde(default, deserialize_with = "account_ids")]
    pub blocklist_managers: Vec<AccountId>,
}

impl RoleAccounts {
    /// Returns the account ids configured for `role`.
    pub fn get(&self, role: Role) -> &[AccountId] {
        match role {
            Role::Owner => std::slice::from_ref(&self.owner),
            Role::AttestAdmin => &self.attest_admins,
            Role::Pauser => &self.pausers,
            Role::Unpauser => &self.unpausers,
            Role::BlocklistManager => &self.blocklist_managers,
        }
    }
}

/// The faucet's account seed and the `XReserveStablecoinBuilder` inputs that are not role
/// account ids; amounts are base units.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaucetConfig {
    /// The faucet's 32-byte account seed, as a hex string.
    #[serde(deserialize_with = "seed")]
    pub seed: [u8; 32],
    /// The initial supply, validated as an [`AssetAmount`] at parse time so it cannot exceed
    /// the hardcoded supply cap.
    #[serde(deserialize_with = "asset_amount")]
    pub token_supply: AssetAmount,
    /// The Circle domain id.
    pub domain: CircleDomain,
    pub min_burn_amount: Option<u64>,
    pub verification_base_fee: u32,
    /// The deposit attesters allowlisted at build time, each as the hex string of the key's 33
    /// compressed SEC1 bytes; empty means the allowlist is seeded later through `set_attester`
    /// notes.
    #[serde(default, deserialize_with = "attesters")]
    pub attesters: Vec<PublicKey>,
}

impl GenesisToolConfig {
    /// Reads and parses the config file at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        load_json(path)
    }

    /// Parses a config from its JSON text.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(ConfigError::Parse)
    }
}

// USED NONCES
// ================================================================================================

/// The `record-nonces` input: the Circle deposit nonces the genesis state already honours (the
/// balances seeded at genesis are backed by their deposits), each as the hex string of its 32
/// bytes. Unknown fields are rejected.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsedNoncesFile {
    #[serde(deserialize_with = "used_nonces")]
    pub used_nonces: Vec<DepositNonce>,
}

impl UsedNoncesFile {
    /// Reads and parses the nonces file at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        load_json(path)
    }

    /// Parses the nonces from their JSON text.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(ConfigError::Parse)
    }
}

/// Reads and parses the JSON file at `path`.
fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(ConfigError::Parse)
}

/// Deserializes an asset amount from its base-unit u64, rejecting out-of-range values.
fn asset_amount<'de, D: Deserializer<'de>>(deserializer: D) -> Result<AssetAmount, D::Error> {
    AssetAmount::new(u64::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// Deserializes an account id from its hex or bech32 string.
fn account_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<AccountId, D::Error> {
    let text = String::deserialize(deserializer)?;
    AccountId::parse(&text)
        .map(|(id, _network)| id)
        .map_err(D::Error::custom)
}

/// Deserializes a list of account ids from their hex or bech32 strings.
fn account_ids<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<AccountId>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|text| {
            AccountId::parse(text)
                .map(|(id, _network)| id)
                .map_err(D::Error::custom)
        })
        .collect()
}

/// Decodes a hex string (an optional `0x` prefix) into bytes.
fn hex_bytes<E: serde::de::Error>(text: &str) -> Result<Vec<u8>, E> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).map_err(E::custom)
}

/// Decodes a hex string into exactly `N` bytes.
fn hex_array<E: serde::de::Error, const N: usize>(text: &str) -> Result<[u8; N], E> {
    <[u8; N]>::try_from(hex_bytes::<E>(text)?)
        .map_err(|bytes| E::custom(format!("expected {N} bytes, got {}", bytes.len())))
}

/// Deserializes the faucet seed from its 32-byte hex string.
fn seed<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    hex_array::<D::Error, 32>(&String::deserialize(deserializer)?)
}

/// Deserializes attester keys from the hex strings of their 33-byte compressed SEC1 form.
fn attesters<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<PublicKey>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|text| {
            PublicKey::read_from_bytes(&hex_array::<D::Error, 33>(text)?).map_err(D::Error::custom)
        })
        .collect()
}

/// Deserializes deposit nonces from the hex strings of their 32 bytes.
fn used_nonces<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<DepositNonce>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|text| hex_array::<D::Error, 32>(text).map(DepositNonce::new))
        .collect()
}

// ERRORS
// ================================================================================================

/// Errors the input-file loaders return.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("reading the input file {}", .path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The JSON does not match the schema: a malformed value (an account id, an attester key,
    /// the seed, a nonce) or an unknown field.
    #[error("the JSON does not match the schema")]
    Parse(#[source] serde_json::Error),
}
