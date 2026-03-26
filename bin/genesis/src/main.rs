use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::Parser;
use miden_agglayer::create_bridge_account;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::delta::{AccountStorageDelta, AccountVaultDelta};
use miden_protocol::account::{
    Account,
    AccountDelta,
    AccountFile,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::crypto::dsa::falcon512_poseidon2::{self, SecretKey as FalconSecretKey};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::{Felt, ONE, Word};
use miden_standards::AuthMethod;
use miden_standards::account::wallets::create_basic_wallet;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

/// Generate canonical Miden genesis accounts (bridge, bridge admin, GER manager)
/// and a genesis.toml configuration file.
#[derive(Parser)]
#[command(name = "miden-genesis")]
struct Cli {
    /// Output directory for generated files.
    #[arg(long, default_value = "./genesis")]
    output_dir: PathBuf,

    /// Hex-encoded Falcon512 public key for the bridge admin account.
    /// If omitted, a new keypair is generated and the secret key is included in the .mac file.
    #[arg(long, value_name = "HEX", requires = "ger_manager_public_key")]
    bridge_admin_public_key: Option<String>,

    /// Hex-encoded Falcon512 public key for the GER manager account.
    /// If omitted, a new keypair is generated and the secret key is included in the .mac file.
    #[arg(long, value_name = "HEX", requires = "bridge_admin_public_key")]
    ger_manager_public_key: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(
        &cli.output_dir,
        cli.bridge_admin_public_key.as_deref(),
        cli.ger_manager_public_key.as_deref(),
    )
}

fn run(
    output_dir: &Path,
    bridge_admin_public_key: Option<&str>,
    ger_manager_public_key: Option<&str>,
) -> anyhow::Result<()> {
    fs_err::create_dir_all(output_dir).context("failed to create output directory")?;

    // Generate or parse bridge admin key.
    let (bridge_admin_pub, bridge_admin_secret) =
        resolve_pubkey(bridge_admin_public_key, "bridge admin")?;

    // Generate or parse GER manager key.
    let (ger_manager_pub, ger_manager_secret) =
        resolve_pubkey(ger_manager_public_key, "GER manager")?;

    // Create bridge admin wallet (nonce=0, local account to be deployed later).
    let bridge_admin = create_basic_wallet(
        rand::random(),
        AuthMethod::SingleSig {
            approver: (bridge_admin_pub.into(), AuthScheme::Falcon512Poseidon2),
        },
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    )
    .context("failed to create bridge admin account")?;
    let bridge_admin_id = bridge_admin.id();

    // Create GER manager wallet (nonce=0, local account to be deployed later).
    let ger_manager = create_basic_wallet(
        rand::random(),
        AuthMethod::SingleSig {
            approver: (ger_manager_pub.into(), AuthScheme::Falcon512Poseidon2),
        },
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    )
    .context("failed to create GER manager account")?;
    let ger_manager_id = ger_manager.id();

    // Create bridge account (NoAuth, nonce=0), then bump nonce to 1 for genesis.
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let bridge_seed: [u64; 4] = rng.random();
    let bridge_seed = Word::from(bridge_seed.map(Felt::new));
    let bridge = create_bridge_account(bridge_seed, bridge_admin_id, ger_manager_id);

    // Bump bridge nonce to 1 (required for genesis accounts).
    // File-loaded accounts via [[account]] in genesis.toml are included as-is,
    // so we must set nonce=1 before writing the .mac file.
    let bridge = bump_nonce_to_one(bridge).context("failed to bump bridge account nonce")?;

    // Write .mac files.
    let bridge_admin_secrets = bridge_admin_secret
        .map(|sk| vec![AuthSecretKey::Falcon512Poseidon2(sk)])
        .unwrap_or_default();
    AccountFile::new(bridge_admin, bridge_admin_secrets)
        .write(output_dir.join("bridge_admin.mac"))
        .context("failed to write bridge_admin.mac")?;

    let ger_manager_secrets = ger_manager_secret
        .map(|sk| vec![AuthSecretKey::Falcon512Poseidon2(sk)])
        .unwrap_or_default();
    AccountFile::new(ger_manager, ger_manager_secrets)
        .write(output_dir.join("ger_manager.mac"))
        .context("failed to write ger_manager.mac")?;

    let bridge_id = bridge.id();
    AccountFile::new(bridge, vec![])
        .write(output_dir.join("bridge.mac"))
        .context("failed to write bridge.mac")?;

    // Write genesis.toml.
    let timestamp = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs(),
    )
    .expect("timestamp should fit in a u32 before the year 2106");

    let genesis_toml = format!(
        r#"version = 1
timestamp = {timestamp}

[fee_parameters]
verification_base_fee = 0

[[account]]
path = "bridge.mac"
"#,
    );

    fs_err::write(output_dir.join("genesis.toml"), genesis_toml)
        .context("failed to write genesis.toml")?;

    println!("Genesis files written to {}", output_dir.display());
    println!("  bridge_admin.mac  (id: {})", bridge_admin_id.to_hex());
    println!("  ger_manager.mac   (id: {})", ger_manager_id.to_hex());
    println!("  bridge.mac        (id: {})", bridge_id.to_hex());
    println!("  genesis.toml");

    Ok(())
}

/// Generates a new Falcon512 keypair using a random seed.
fn generate_falcon_keypair() -> (falcon512_poseidon2::PublicKey, FalconSecretKey) {
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let auth_seed: [u64; 4] = rng.random();
    let mut coin = RandomCoin::new(Word::from(auth_seed.map(Felt::new)));
    let secret_key = FalconSecretKey::with_rng(&mut coin);
    let public_key = secret_key.public_key();
    (public_key, secret_key)
}

/// Resolves a Falcon512 key pair: either parses the provided hex public key or generates a new
/// keypair.
fn resolve_pubkey(
    hex_pubkey: Option<&str>,
    label: &str,
) -> anyhow::Result<(falcon512_poseidon2::PublicKey, Option<FalconSecretKey>)> {
    if let Some(hex_str) = hex_pubkey {
        let bytes =
            hex::decode(hex_str).with_context(|| format!("invalid hex for {label} public key"))?;
        let pubkey = falcon512_poseidon2::PublicKey::read_from_bytes(&bytes)
            .with_context(|| format!("failed to deserialize {label} public key"))?;
        Ok((pubkey, None))
    } else {
        let (public_key, secret_key) = generate_falcon_keypair();
        Ok((public_key, Some(secret_key)))
    }
}

/// Bumps an account's nonce from 0 to 1 using an `AccountDelta`.
fn bump_nonce_to_one(mut account: Account) -> anyhow::Result<Account> {
    let delta = AccountDelta::new(
        account.id(),
        AccountStorageDelta::default(),
        AccountVaultDelta::default(),
        ONE,
    )?;
    account.apply_delta(&delta)?;
    Ok(account)
}

#[cfg(test)]
mod tests {
    use miden_node_store::genesis::config::GenesisConfig;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
    use miden_protocol::utils::serde::Serializable;

    use super::*;

    /// Parses the generated genesis.toml, builds a genesis block, and asserts the bridge account
    /// is included with nonce=1.
    async fn assert_valid_genesis_block(dir: &Path) {
        let bridge_id = AccountFile::read(dir.join("bridge.mac")).unwrap().account.id();

        let config = GenesisConfig::read_toml_file(&dir.join("genesis.toml")).unwrap();
        let signer = SecretKey::read_from_bytes(&[0x01; 32]).unwrap();
        let (state, _) = config.into_state(signer).unwrap();

        let bridge = state.accounts.iter().find(|a| a.id() == bridge_id).unwrap();
        assert_eq!(bridge.nonce(), ONE);

        state.into_block().await.expect("genesis block should build");
    }

    #[tokio::test]
    async fn default_mode_includes_secret_keys() {
        let dir = tempfile::tempdir().unwrap();
        run(dir.path(), None, None).unwrap();

        let admin = AccountFile::read(dir.path().join("bridge_admin.mac")).unwrap();
        assert_eq!(admin.auth_secret_keys.len(), 1);

        let ger = AccountFile::read(dir.path().join("ger_manager.mac")).unwrap();
        assert_eq!(ger.auth_secret_keys.len(), 1);

        assert_valid_genesis_block(dir.path()).await;
    }

    #[tokio::test]
    async fn custom_public_keys_excludes_secret_keys() {
        let dir = tempfile::tempdir().unwrap();

        let (admin_pub, _) = generate_falcon_keypair();
        let (ger_pub, _) = generate_falcon_keypair();
        let admin_hex = hex::encode((&admin_pub).to_bytes());
        let ger_hex = hex::encode((&ger_pub).to_bytes());

        run(dir.path(), Some(&admin_hex), Some(&ger_hex)).unwrap();

        let admin = AccountFile::read(dir.path().join("bridge_admin.mac")).unwrap();
        assert!(admin.auth_secret_keys.is_empty());

        let ger = AccountFile::read(dir.path().join("ger_manager.mac")).unwrap();
        assert!(ger.auth_secret_keys.is_empty());

        assert_valid_genesis_block(dir.path()).await;
    }
}
