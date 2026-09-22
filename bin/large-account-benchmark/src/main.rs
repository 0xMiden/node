//! Seeds an oversized network account and checks the ntx-builder can work with it.
//!
//! - `seed` writes the counter account, its owner wallet, and the faucet fees are denominated in as
//!   `.mac` [`AccountFile`]s. A genesis configuration references the first two via `[[account]]`
//!   entries, so the store and the ntx-builder both load the account from `genesis.dat` on disk with
//!   no wire transfer involved, and the faucet via `native_faucet`, which makes the asset the counter
//!   prices its notes in the asset the chain settles in.
//! - `verify` submits one increment and asserts the counter advances within a block budget. The
//!   increment emits a network note, which makes the ntx-builder load the full account — so a passing
//!   run is the evidence that an account this large can be worked with at all.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use miden_objects::account_file::AccountFile;
use miden_protocol::ONE;
use miden_protocol::account::Account;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use url::Url;

mod accounts;
mod increment;
mod rpc;

use self::accounts::{create_counter_account, create_fee_faucet_account, create_wallet_account};

/// File name of the seeded owner wallet (carries its signing key).
const WALLET_FILE: &str = "wallet.mac";
/// File name of the seeded fee faucet (carries its signing key). Referenced by the genesis
/// configuration's `native_faucet`, not by an `[[account]]` entry.
const FAUCET_FILE: &str = "faucet.mac";
/// File name of the seeded network counter account (no secret key; the ntx-builder authors its
/// transactions).
const COUNTER_FILE: &str = "counter.mac";

#[derive(Parser)]
#[command(name = "miden-large-account-benchmark", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write the wallet + counter pair as `.mac` files for a genesis configuration to reference.
    Seed(SeedArgs),
    /// Submit one increment and assert the counter advances, then exit.
    ///
    /// This is the end-to-end check that the whole setup works: that the seeded accounts are on
    /// chain, that a transaction against the wallet is accepted, and — the part that matters — that
    /// the ntx-builder can load an account this large and consume the resulting network note. Exits
    /// non-zero if the counter has not advanced within the block budget.
    Verify(VerifyArgs),
}

#[derive(clap::Args)]
struct SeedArgs {
    /// Directory into which `wallet.mac` and `counter.mac` are written.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,

    /// Number of entries to pre-populate into the counter account's storage map.
    #[arg(long, default_value_t = 0, value_name = "N")]
    counter_map_entries: u32,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Directory holding the `wallet.mac` and `counter.mac` written by `seed`.
    #[arg(long, value_name = "DIR")]
    accounts_dir: PathBuf,

    /// URL of the node's RPC endpoint.
    #[arg(long, env = "MIDEN_LARGE_ACCOUNT_BENCH_RPC_URL", value_name = "URL")]
    rpc_url: Url,

    /// Hex-encoded public keys of the validators trusted to attest the node's transaction
    /// encryption key.
    #[arg(
        long = "validator-signing-public-key",
        env = "MIDEN_LARGE_ACCOUNT_BENCH_VALIDATOR_SIGNING_PUBLIC_KEYS",
        value_delimiter = ',',
        required = true,
        value_name = "HEX"
    )]
    validator_signing_public_keys: Vec<String>,

    /// How many blocks to allow for the counter to advance before failing.
    #[arg(long, default_value_t = 20, value_name = "N")]
    wait_blocks: u32,

    /// How often to poll the counter and the chain tip while waiting.
    #[arg(long, default_value = "2s", value_parser = humantime_duration, value_name = "DURATION")]
    poll_interval: Duration,

    /// Per-request RPC timeout.
    #[arg(long, default_value = "30s", value_parser = humantime_duration, value_name = "DURATION")]
    request_timeout: Duration,
}

fn humantime_duration(raw: &str) -> Result<Duration, String> {
    raw.parse::<humantime::Duration>()
        .map(Into::into)
        .map_err(|err| err.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Seed(args) => seed(&args),
        Command::Verify(args) => verify(&args).await,
    }
}

// SEED
// ================================================================================================

fn seed(args: &SeedArgs) -> Result<()> {
    fs_err::create_dir_all(&args.output_dir)
        .with_context(|| format!("failed to create output dir {}", args.output_dir.display()))?;

    let Seeded {
        faucet,
        faucet_secret_key,
        wallet,
        wallet_secret_key,
        counter,
    } = build_seeded_accounts(args.counter_map_entries)?;

    let faucet_id = faucet.id();
    let wallet_id = wallet.id();
    let counter_id = counter.id();

    write_wallet(&args.output_dir, &wallet, &wallet_secret_key)?;
    AccountFile::new(faucet, vec![AuthSecretKey::Falcon512Poseidon2(faucet_secret_key)])
        .write(args.output_dir.join(FAUCET_FILE))
        .context("failed to write faucet.mac")?;
    AccountFile::new(counter, vec![])
        .write(args.output_dir.join(COUNTER_FILE))
        .context("failed to write counter.mac")?;

    println!("fee_faucet_id={}", faucet_id.to_hex());
    println!("wallet_id={}", wallet_id.to_hex());
    println!("counter_id={}", counter_id.to_hex());
    println!("counter_map_entries={}", args.counter_map_entries);
    println!("output_dir={}", args.output_dir.display());

    Ok(())
}

/// The accounts a seed run writes.
struct Seeded {
    /// The faucet fees are denominated in, at nonce zero for genesis to adopt as its native faucet.
    faucet: Account,
    faucet_secret_key: SecretKey,
    /// The owner wallet, in committed form.
    wallet: Account,
    wallet_secret_key: SecretKey,
    /// The oversized network counter, in committed form.
    counter: Account,
}

/// Builds the faucet + wallet + counter set.
///
/// The wallet and the counter are committed here by bumping their nonce, since genesis takes them
/// as `[[account]]` entries and writes them into the block as-is. The faucet is left at nonce zero
/// because genesis commits that one itself.
fn build_seeded_accounts(counter_map_entries: u32) -> Result<Seeded> {
    let (faucet, faucet_secret_key) =
        create_fee_faucet_account().context("failed to create the fee faucet")?;

    let (mut wallet, wallet_secret_key) =
        create_wallet_account().context("failed to create wallet")?;
    wallet.set_nonce(ONE).context("failed to bump wallet nonce")?;

    let mut counter = create_counter_account(wallet.id(), faucet.id(), counter_map_entries)
        .context("failed to create counter account")?;
    counter.set_nonce(ONE).context("failed to bump counter nonce")?;

    Ok(Seeded {
        faucet,
        faucet_secret_key,
        wallet,
        wallet_secret_key,
        counter,
    })
}

// VERIFY
// ================================================================================================

async fn verify(args: &VerifyArgs) -> Result<()> {
    let (wallet, secret_key, counter) = load_pair(&args.accounts_dir)?;

    println!("wallet_id={}", wallet.id().to_hex());
    println!("counter_id={}", counter.id().to_hex());
    println!("connecting to {}", args.rpc_url);

    // Connecting is itself part of the check: it performs the genesis handshake and verifies the
    // node's encryption key against the trusted validator, so a broken node fails here.
    let client = rpc::SubmissionClient::connect(
        &args.rpc_url,
        args.request_timeout,
        &args.validator_signing_public_keys,
    )
    .await?;

    let mut driver = increment::Driver::new(
        wallet,
        counter,
        secret_key.clone(),
        &client,
        ChaCha20Rng::from_rng(&mut rand::rng()),
    )
    .await?;

    // Read both baselines before submitting, so the assertion is against a known starting point.
    let baseline = driver
        .observed_counter(&client)
        .await
        .context("failed to read the counter before submitting")?;
    let start_tip = client.chain_tip().await?;

    println!(
        "baseline: counter={} chain_tip={start_tip}",
        baseline.map_or_else(|| "not on chain".to_string(), |v| v.to_string()),
    );

    let result = driver
        .submit_one(&client)
        .await
        .context("the increment transaction was rejected")?;
    println!(
        "submitted increment at block {} · proved in {:.2}s · tx {}",
        result.block_num,
        result.proving_time.as_secs_f64(),
        result.tx_id,
    );

    write_wallet(&args.accounts_dir, driver.wallet(), &secret_key)?;

    println!(
        "waiting up to {} blocks for the ntx-builder to consume the note...",
        args.wait_blocks,
    );

    let baseline_value = baseline.unwrap_or(0);
    loop {
        tokio::time::sleep(args.poll_interval).await;

        let observed = driver
            .observed_counter(&client)
            .await
            .context("failed to read the counter while waiting")?;
        let tip = client.chain_tip().await?;
        let blocks_elapsed = tip.saturating_sub(start_tip);

        match poll_progress(baseline_value, observed, blocks_elapsed, args.wait_blocks) {
            Progress::Increased => {
                println!(
                    "counter advanced to {} after {blocks_elapsed} blocks",
                    observed.expect("an increased counter is on chain"),
                );
                println!("PASS: the ntx-builder loaded the account and consumed the network note");
                return Ok(());
            },
            Progress::TimedOut => {
                anyhow::bail!(
                    "counter did not advance past {baseline_value} within {blocks_elapsed} blocks \
                     (still {}). The wallet transaction landed, so the note was emitted — the \
                     ntx-builder did not consume it. Check its logs; for an account this large, \
                     failing or timing out while loading it is the expected cause",
                    observed.map_or_else(|| "not on chain".to_string(), |v| v.to_string()),
                );
            },
            Progress::Waiting => println!(
                "  counter={} blocks_elapsed={blocks_elapsed}/{}",
                observed.map_or_else(|| "not on chain".to_string(), |v| v.to_string()),
                args.wait_blocks,
            ),
        }
    }
}

/// What a single poll of the verification loop concluded.
#[derive(Debug, PartialEq, Eq)]
enum Progress {
    /// The counter advanced past the baseline: the ntx-builder consumed the note.
    Increased,
    /// The block budget elapsed without the counter moving.
    TimedOut,
    /// Neither yet — keep polling.
    Waiting,
}

/// Decides whether verification has succeeded, failed, or should keep waiting.
///
/// Progress is judged on the counter strictly exceeding the value read before the increment was
/// submitted, and the deadline is measured in blocks rather than seconds so the check does not depend
/// on how fast the network happens to be producing them.
///
/// The block budget is checked *after* the counter, so a counter that advances on the very block the
/// budget expires still passes rather than racing the deadline.
fn poll_progress(
    baseline: u64,
    observed: Option<u64>,
    blocks_elapsed: u32,
    budget: u32,
) -> Progress {
    if observed.is_some_and(|value| value > baseline) {
        return Progress::Increased;
    }
    if blocks_elapsed >= budget {
        return Progress::TimedOut;
    }
    Progress::Waiting
}

// ACCOUNT FILES
// ================================================================================================

/// Reads the wallet (with its signing key) and the counter account from a seeded directory.
fn load_pair(dir: &Path) -> Result<(Account, SecretKey, Account)> {
    let wallet_file =
        AccountFile::read(dir.join(WALLET_FILE)).context("failed to read wallet.mac")?;
    let counter_file =
        AccountFile::read(dir.join(COUNTER_FILE)).context("failed to read counter.mac")?;

    let secret_key = wallet_file
        .auth_secret_keys()
        .iter()
        .find_map(|key| match key {
            AuthSecretKey::Falcon512Poseidon2(sk) => Some(sk.clone()),
            _ => None,
        })
        .context("wallet.mac does not contain a Falcon512Poseidon2 secret key")?;

    Ok((wallet_file.into_parts().0, secret_key, counter_file.into_parts().0))
}

/// Writes the wallet and its signing key to `wallet.mac`, replacing any existing file.
fn write_wallet(dir: &Path, wallet: &Account, secret_key: &SecretKey) -> Result<()> {
    let final_path = dir.join(WALLET_FILE);
    let temp_path = dir.join(format!("{WALLET_FILE}.tmp"));

    AccountFile::new(wallet.clone(), vec![AuthSecretKey::Falcon512Poseidon2(secret_key.clone())])
        .write(&temp_path)
        .context("failed to write the wallet account file")?;

    fs_err::rename(&temp_path, &final_path).context("failed to replace wallet.mac")?;

    Ok(())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{Progress, poll_progress};

    /// The verification loop must not declare success on a counter that has not moved, must not
    /// give up while the block budget remains, and must not fail a counter that advances on the
    /// very block the budget runs out.
    #[test]
    fn poll_progress_decides_on_counter_movement_then_block_budget() {
        // Advanced past the baseline: success, regardless of how many blocks it took.
        assert_eq!(poll_progress(5, Some(6), 1, 20), Progress::Increased);
        assert_eq!(poll_progress(0, Some(1), 19, 20), Progress::Increased);

        // Unmoved, budget remaining: keep waiting.
        assert_eq!(poll_progress(5, Some(5), 0, 20), Progress::Waiting);
        assert_eq!(poll_progress(5, Some(5), 19, 20), Progress::Waiting);
        assert_eq!(poll_progress(0, None, 3, 20), Progress::Waiting);

        // Budget exhausted with no movement: fail.
        assert_eq!(poll_progress(5, Some(5), 20, 20), Progress::TimedOut);
        assert_eq!(poll_progress(0, None, 25, 20), Progress::TimedOut);

        // Counter movement wins on the boundary block, so a late consume is not a spurious failure.
        assert_eq!(poll_progress(5, Some(6), 20, 20), Progress::Increased);

        // A counter *below* the baseline is not progress (it should not happen, but must not pass).
        assert_eq!(poll_progress(5, Some(4), 1, 20), Progress::Waiting);

        // A zero budget fails immediately rather than looping forever.
        assert_eq!(poll_progress(5, Some(5), 0, 0), Progress::TimedOut);
    }
}
