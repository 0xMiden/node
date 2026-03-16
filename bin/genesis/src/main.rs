use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::Parser;
use miden_agglayer::create_bridge_account;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::delta::{AccountStorageDelta, AccountVaultDelta};
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountDelta,
    AccountFile,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::crypto::dsa::falcon512_rpo::{self, SecretKey as RpoSecretKey};
use miden_protocol::crypto::rand::RpoRandomCoin;
use miden_protocol::utils::Deserializable;
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
    #[arg(long, value_name = "HEX")]
    bridge_admin_public_key: Option<String>,

    /// Hex-encoded Falcon512 public key for the GER manager account.
    /// If omitted, a new keypair is generated and the secret key is included in the .mac file.
    #[arg(long, value_name = "HEX")]
    ger_manager_public_key: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    fs_err::create_dir_all(&cli.output_dir).context("failed to create output directory")?;

    // Generate or parse bridge admin key.
    let (bridge_admin_pub, bridge_admin_secret) =
        resolve_falcon_key(cli.bridge_admin_public_key.as_deref(), "bridge admin")?;

    // Generate or parse GER manager key.
    let (ger_manager_pub, ger_manager_secret) =
        resolve_falcon_key(cli.ger_manager_public_key.as_deref(), "GER manager")?;

    // Create bridge admin wallet (nonce=0, local account to be deployed later).
    let bridge_admin = create_basic_wallet(
        rand::random(),
        AuthMethod::SingleSig {
            approver: (bridge_admin_pub.into(), AuthScheme::Falcon512Rpo),
        },
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    )
    .context("failed to create bridge admin account")?;
    let bridge_admin = strip_code_decorators(bridge_admin);
    let bridge_admin_id = bridge_admin.id();

    // Create GER manager wallet (nonce=0, local account to be deployed later).
    let ger_manager = create_basic_wallet(
        rand::random(),
        AuthMethod::SingleSig {
            approver: (ger_manager_pub.into(), AuthScheme::Falcon512Rpo),
        },
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    )
    .context("failed to create GER manager account")?;
    let ger_manager = strip_code_decorators(ger_manager);
    let ger_manager_id = ger_manager.id();

    // Create bridge account (NoAuth, nonce=0), then bump nonce to 1 for genesis.
    let mut rng = ChaCha20Rng::from_seed(rand::random());
    let bridge_seed: [u64; 4] = rng.random();
    let bridge_seed = Word::from(bridge_seed.map(Felt::new));
    let bridge = create_bridge_account(bridge_seed, bridge_admin_id, ger_manager_id);
    let bridge = strip_code_decorators(bridge);

    // Bump bridge nonce to 1 (required for genesis accounts).
    // File-loaded accounts via [[account]] in genesis.toml are included as-is,
    // so we must set nonce=1 before writing the .mac file.
    let bridge = bump_nonce_to_one(bridge).context("failed to bump bridge account nonce")?;

    // Write .mac files.
    let bridge_admin_secrets = bridge_admin_secret
        .map(|sk| vec![AuthSecretKey::Falcon512Rpo(sk)])
        .unwrap_or_default();
    AccountFile::new(bridge_admin, bridge_admin_secrets)
        .write(cli.output_dir.join("bridge_admin.mac"))
        .context("failed to write bridge_admin.mac")?;

    let ger_manager_secrets = ger_manager_secret
        .map(|sk| vec![AuthSecretKey::Falcon512Rpo(sk)])
        .unwrap_or_default();
    AccountFile::new(ger_manager, ger_manager_secrets)
        .write(cli.output_dir.join("ger_manager.mac"))
        .context("failed to write ger_manager.mac")?;

    let bridge_id = bridge.id();
    AccountFile::new(bridge, vec![])
        .write(cli.output_dir.join("bridge.mac"))
        .context("failed to write bridge.mac")?;

    // Write genesis.toml.
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs();

    let genesis_toml = format!(
        r#"version = 1
timestamp = {timestamp}

[fee_parameters]
verification_base_fee = 0

[[account]]
path = "bridge.mac"
"#,
    );

    fs_err::write(cli.output_dir.join("genesis.toml"), genesis_toml)
        .context("failed to write genesis.toml")?;

    println!("Genesis files written to {}", cli.output_dir.display());
    println!("  bridge_admin.mac  (id: {})", bridge_admin_id.to_hex());
    println!("  ger_manager.mac   (id: {})", ger_manager_id.to_hex());
    println!("  bridge.mac        (id: {})", bridge_id.to_hex());
    println!("  genesis.toml");

    Ok(())
}

/// Resolves a Falcon512 key pair: either parses the provided hex public key or generates a new
/// keypair.
fn resolve_falcon_key(
    hex_pubkey: Option<&str>,
    label: &str,
) -> anyhow::Result<(falcon512_rpo::PublicKey, Option<RpoSecretKey>)> {
    if let Some(hex_str) = hex_pubkey {
        let bytes =
            hex::decode(hex_str).with_context(|| format!("invalid hex for {label} public key"))?;
        let pubkey = falcon512_rpo::PublicKey::read_from_bytes(&bytes)
            .with_context(|| format!("failed to deserialize {label} public key"))?;
        Ok((pubkey, None))
    } else {
        let mut rng = ChaCha20Rng::from_seed(rand::random());
        let auth_seed: [u64; 4] = rng.random();
        let mut coin = RpoRandomCoin::new(Word::from(auth_seed.map(Felt::new)));
        let secret_key = RpoSecretKey::with_rng(&mut coin);
        let public_key = secret_key.public_key();
        Ok((public_key, Some(secret_key)))
    }
}

/// Bumps an account's nonce from 0 to 1 using an `AccountDelta`.
///
/// Genesis accounts loaded via `[[account]]` in genesis.toml are included as-is (no automatic
/// nonce bump). By convention, nonce=0 means "not yet deployed" and genesis accounts must have
/// nonce>=1.
fn bump_nonce_to_one(mut account: Account) -> anyhow::Result<Account> {
    let delta = AccountDelta::new(
        account.id(),
        AccountStorageDelta::default(),
        AccountVaultDelta::default(),
        ONE,
    )?;
    account.apply_delta(&delta)?;
    debug_assert_eq!(account.nonce(), ONE);
    Ok(account)
}

/// Strips source location decorators from an account's code MAST forest.
///
/// This ensures serialized .mac files are deterministic regardless of build path.
fn strip_code_decorators(account: Account) -> Account {
    let (id, vault, storage, code, nonce, seed) = account.into_parts();

    let mut mast = code.mast();
    Arc::make_mut(&mut mast).strip_decorators();
    let code = AccountCode::from_parts(mast, code.procedures().to_vec());

    Account::new_unchecked(id, vault, storage, code, nonce, seed)
}
