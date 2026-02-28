// This build.rs is required to trigger the `diesel_migrations::embed_migrations!` proc-macro in
// `store/src/db/migrations.rs` to include the latest version of the migrations into the binary, see <https://docs.rs/diesel_migrations/latest/diesel_migrations/macro.embed_migrations.html#automatic-rebuilds>.

use std::path::PathBuf;
use std::sync::Arc;

use miden_agglayer::{create_existing_agglayer_faucet, create_existing_bridge_account};
use miden_protocol::account::{Account, AccountCode, AccountFile};
use miden_protocol::{Felt, Word};

fn main() {
    build_rs::output::rerun_if_changed("src/db/migrations");
    // If we do one re-write, the default rules are disabled,
    // hence we need to trigger explicitly on `Cargo.toml`.
    // <https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-changed>
    build_rs::output::rerun_if_changed("Cargo.toml");

    // Generate sample agglayer account files for genesis config samples.
    generate_agglayer_sample_accounts();
    miden_node_rocksdb_cxx_linkage_fix::configure();
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

    // Use deterministic seeds for reproducible builds
    // WARNING: DO NOT USE THIS IN PRODUCTION
    let bridge_seed: Word = Word::new([Felt::new(1u64); 4]);
    let eth_faucet_seed: Word = Word::new([Felt::new(2u64); 4]);
    let usdc_faucet_seed: Word = Word::new([Felt::new(3u64); 4]);

    // Create the bridge account first (faucets need to reference it)
    // Use "existing" variant so accounts have nonce > 0 (required for genesis)
    let bridge_account = create_existing_bridge_account(bridge_seed);
    let bridge_account_id = bridge_account.id();

    // Create AggLayer faucets using "existing" variant
    // ETH: 18 decimals, max supply of 1 billion tokens
    let eth_faucet = create_existing_agglayer_faucet(
        eth_faucet_seed,
        "ETH",
        18,
        Felt::new(1_000_000_000),
        bridge_account_id,
    );

    // USDC: 6 decimals, max supply of 10 billion tokens
    let usdc_faucet = create_existing_agglayer_faucet(
        usdc_faucet_seed,
        "USDC",
        6,
        Felt::new(10_000_000_000),
        bridge_account_id,
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

/// Strips source location decorators from an account's code MAST forest.
///
/// This is necessary because the MAST forest embeds absolute file paths from the Cargo build
/// directory, which include a hash that differs between `cargo check` and `cargo build`. Stripping
/// decorators ensures the serialized `.mac` files are identical regardless of which cargo command
/// is used (CI or local builds or tests).
fn strip_code_decorators(account: Account) -> Account {
    let (id, vault, storage, code, nonce, seed) = account.into_parts();

    let mut mast = code.mast();
    Arc::make_mut(&mut mast).strip_decorators();
    let code = AccountCode::from_parts(mast, code.procedures().to_vec());

    Account::new_unchecked(id, vault, storage, code, nonce, seed)
}
