// This build.rs is required to trigger the `diesel_migrations::embed_migrations!` proc-macro in
// `store/src/db/migrations.rs` to include the latest version of the migrations into the binary, see <https://docs.rs/diesel_migrations/latest/diesel_migrations/macro.embed_migrations.html#automatic-rebuilds>.

use std::path::PathBuf;
use std::sync::Arc;

use miden_agglayer::{
    EthAddressFormat,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountCode, AccountFile, AccountStorageMode, AccountType};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::rand::RpoRandomCoin;
use miden_protocol::{Felt, Word};
use miden_standards::AuthMethod;
use miden_standards::account::wallets::create_basic_wallet;

fn main() {
    build_rs::output::rerun_if_changed("src/db/migrations");
    // If we do one re-write, the default rules are disabled,
    // hence we need to trigger explicitly on `Cargo.toml`.
    // <https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-changed>
    build_rs::output::rerun_if_changed("Cargo.toml");

    // Generate sample agglayer account files for genesis config samples.
    generate_agglayer_sample_accounts();
}

/// Generates sample agglayer account files for the `02-with-account-files` genesis config sample.
///
/// Creates:
/// - `02-with-account-files/bridge.mac` - agglayer bridge account
/// - `02-with-account-files/agglayer_faucet_eth.mac` - agglayer faucet for wrapped ETH
/// - `02-with-account-files/agglayer_faucet_usdc.mac` - agglayer faucet for wrapped USDC
fn generate_agglayer_sample_accounts() {
    // Use CARGO_MANIFEST_DIR to get the absolute path to the crate root
    let manifest_dir = build_rs::input::cargo_manifest_dir();
    let samples_dir: PathBuf =
        manifest_dir.join("src/genesis/config/samples/02-with-account-files");

    // Create the directory if it doesn't exist
    fs_err::create_dir_all(&samples_dir).expect("Failed to create samples directory");

    // Use deterministic seeds for reproducible builds.
    // WARNING: DO NOT USE THESE IN PRODUCTION
    let bridge_seed: Word = Word::new([Felt::new(1u64); 4]);
    let eth_faucet_seed: Word = Word::new([Felt::new(2u64); 4]);
    let usdc_faucet_seed: Word = Word::new([Felt::new(3u64); 4]);

    // Create bridge admin and GER manager as proper wallet accounts.
    // WARNING: DO NOT USE THESE IN PRODUCTION
    let bridge_admin_key =
        SecretKey::with_rng(&mut RpoRandomCoin::new(Word::new([Felt::new(4u64); 4])));
    let ger_manager_key =
        SecretKey::with_rng(&mut RpoRandomCoin::new(Word::new([Felt::new(5u64); 4])));

    let bridge_admin = create_basic_wallet(
        [4u8; 32],
        AuthMethod::SingleSig {
            approver: (bridge_admin_key.public_key().into(), AuthScheme::Falcon512Poseidon2),
        },
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    )
    .expect("bridge admin account should be valid");

    let ger_manager = create_basic_wallet(
        [5u8; 32],
        AuthMethod::SingleSig {
            approver: (ger_manager_key.public_key().into(), AuthScheme::Falcon512Poseidon2),
        },
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
    )
    .expect("GER manager account should be valid");

    let bridge_admin_id = bridge_admin.id();
    let ger_manager_id = ger_manager.id();

    // Create the bridge account first (faucets need to reference it)
    // Use "existing" variant so accounts have nonce > 0 (required for genesis)
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin_id, ger_manager_id);
    let bridge_account_id = bridge_account.id();

    // Placeholder Ethereum addresses for sample faucets.
    // WARNING: DO NOT USE THESE ADDRESSES IN PRODUCTION
    let eth_origin_address = EthAddressFormat::new([1u8; 20]);
    let usdc_origin_address = EthAddressFormat::new([2u8; 20]);

    // Create AggLayer faucets using "existing" variant
    // ETH: 8 decimals (protocol max is 12), max supply of 1 billion tokens
    let eth_faucet = create_existing_agglayer_faucet(
        eth_faucet_seed,
        "ETH",
        8,
        Felt::new(1_000_000_000),
        Felt::new(0),
        bridge_account_id,
        &eth_origin_address,
        0u32,
        10u8,
    );

    // USDC: 6 decimals, max supply of 10 billion tokens
    let usdc_faucet = create_existing_agglayer_faucet(
        usdc_faucet_seed,
        "USDC",
        6,
        Felt::new(10_000_000_000),
        Felt::new(0),
        bridge_account_id,
        &usdc_origin_address,
        0u32,
        10u8,
    );

    // Strip source location decorators from account code to ensure deterministic output.
    let bridge_account = strip_code_decorators(bridge_account);
    let eth_faucet = strip_code_decorators(eth_faucet);
    let usdc_faucet = strip_code_decorators(usdc_faucet);

    // Save account files (without secret keys since these use NoAuth)
    let bridge_file = AccountFile::new(bridge_account, vec![]);
    let eth_faucet_file = AccountFile::new(eth_faucet, vec![]);
    let usdc_faucet_file = AccountFile::new(usdc_faucet, vec![]);

    // Write files
    bridge_file
        .write(samples_dir.join("bridge.mac"))
        .expect("Failed to write bridge.mac");
    eth_faucet_file
        .write(samples_dir.join("agglayer_faucet_eth.mac"))
        .expect("Failed to write agglayer_faucet_eth.mac");
    usdc_faucet_file
        .write(samples_dir.join("agglayer_faucet_usdc.mac"))
        .expect("Failed to write agglayer_faucet_usdc.mac");
}

/// Clears debug info from an account's code MAST forest.
///
/// This is necessary because the MAST forest embeds absolute file paths from the Cargo build
/// directory, which include a hash that differs between `cargo check` and `cargo build`. Clearing
/// debug info ensures the serialized `.mac` files are identical regardless of which cargo command
/// is used (CI or local builds or tests).
fn strip_code_decorators(account: Account) -> Account {
    let (id, vault, storage, code, nonce, seed) = account.into_parts();

    let mut mast = code.mast();
    Arc::make_mut(&mut mast).clear_debug_info();
    let code = AccountCode::from_parts(mast, code.procedures().to_vec());

    Account::new_unchecked(id, vault, storage, code, nonce, seed)
}
