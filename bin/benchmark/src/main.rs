//! Runs benchmarks

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountStorageMode,
    AccountType,
    PartialAccount,
    StorageMapKey,
};
use miden_protocol::asset::{Asset, AssetVaultKey, AssetWitness, FungibleAsset, TokenSymbol};
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::merkle::mmr::{MmrPeaks, PartialMmr};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::transaction::{
    AccountInputs,
    InputNote,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
    TransactionId,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Felt, MastForest, Word};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::faucets::BasicFungibleFaucet;
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::account::metadata::{FungibleTokenMetadata, TokenName};
use miden_standards::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyAuthority,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::P2idNote;
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{
    DataStore,
    DataStoreError,
    LocalTransactionProver,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};
use rand::Rng;
use rayon::prelude::*;
use tokio::sync::Semaphore;
use url::Url;

const PROOFS_DIR: &str = "./benchmark-proofs";

// COMMANDS
// ================================================================================================

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    CreateProofs {
        /// RPC endpoint of the target miden node — used to discover the
        /// genesis commitment that the generated proofs are bound to. Must
        /// match the node you intend to submit the proofs against.
        #[arg(long, default_value = "http://127.0.0.1:57291")]
        rpc_url: Url,
        /// Number of mint + consume transaction pairs to generate. Each
        /// pair takes seconds of real STARK proving, so start small.
        #[arg(long, default_value_t = 10)]
        num_transactions: u64,
    },
    RunBenchmark {
        /// RPC endpoint of the target miden node.
        #[arg(long, default_value = "http://127.0.0.1:57291")]
        rpc_url: Url,
        /// Number of concurrent submission tasks.
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
        /// Number of blocks to wait after the last submission RPC returns
        /// before checking which of our txs have been included on-chain.
        /// Larger values give the mempool more time to drain a backlog.
        #[arg(long, default_value_t = 3)]
        wait_blocks: u32,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    cli.run().await;
}

impl Cli {
    async fn run(self) {
        match self.command {
            Command::CreateProofs { rpc_url, num_transactions } => {
                create_proofs(rpc_url, num_transactions).await;
            },
            Command::RunBenchmark { rpc_url, concurrency, wait_blocks } => {
                run_benchmark(rpc_url, concurrency, wait_blocks).await;
            },
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single linear orchestration of genesis fetch + mint phase + consume phase; \
              splitting would just shuffle locals (faucet, data_store, authenticator) around"
)]
async fn create_proofs(rpc_url: Url, num_transactions: u64) {
    let mut rpc_client = create_genesis_aware_rpc_client(&rpc_url, Duration::from_secs(10))
        .await
        .unwrap();

    println!("Fetching genesis block header from {rpc_url}...");
    let genesis_header_proto = rpc_client
        .get_block_header_by_number(get_genesis_header_request())
        .await
        .unwrap()
        .into_inner()
        .block_header
        .expect("RPC returned no block header");
    let genesis_header: BlockHeader = genesis_header_proto.try_into().unwrap();

    println!("Creating faucet...");
    let (mut faucet, faucet_secret_key) = create_faucet();

    let coin_seed: [u64; 4] = rand::rng().random();
    let mut seed_rng = RandomCoin::new(coin_seed.map(Felt::new).into());
    let wallet_secret_key = SecretKey::with_rng(&mut seed_rng);
    let wallet_public_key = wallet_secret_key.public_key();

    println!("Creating {num_transactions} wallets in parallel...");
    let wallets: Vec<Account> = (0..num_transactions)
        .into_par_iter()
        .map(|index| create_wallet(&wallet_public_key, index))
        .collect();

    let genesis_chain_mmr =
        PartialBlockchain::new(PartialMmr::from_peaks(MmrPeaks::default()), Vec::new())
            .expect("failed to create empty chain MMR");

    let mut data_store = BenchmarkDataStore::new(genesis_header.clone(), genesis_chain_mmr);
    data_store.add_account(faucet.clone());
    for wallet in &wallets {
        data_store.add_account(wallet.clone());
    }

    let authenticator = BasicAuthenticator::new(&[
        AuthSecretKey::Falcon512Poseidon2(faucet_secret_key),
        AuthSecretKey::Falcon512Poseidon2(wallet_secret_key),
    ]);

    let prover = LocalTransactionProver::default();
    let faucet_id = faucet.id();

    // Mint phase — sequential because each mint mutates the faucet.
    println!("Proving {num_transactions} mint transactions (sequential)...");
    let mut mint_txs: Vec<ProvenTransaction> = Vec::with_capacity(num_transactions as usize);
    let mut mint_tx_inputs: Vec<Vec<u8>> = Vec::with_capacity(num_transactions as usize);
    let mut mint_notes: Vec<Note> = Vec::with_capacity(num_transactions as usize);
    let mint_phase_start = Instant::now();
    let mut mint_exec_total = Duration::ZERO;
    let mut mint_prove_total = Duration::ZERO;

    for index in 0..num_transactions {
        let wallet_id = wallets[index as usize].id();
        let note = {
            let asset = Asset::Fungible(FungibleAsset::new(faucet_id, 10).unwrap());
            P2idNote::create(
                faucet_id,
                wallet_id,
                vec![asset],
                miden_protocol::note::NoteType::Public,
                miden_protocol::note::NoteAttachment::default(),
                &mut seed_rng,
            )
            .expect("note creation failed")
        };

        let account_interface = AccountInterface::from_account(&faucet);
        let script = account_interface
            .build_send_notes_script(&[note.clone().into()], None)
            .expect("failed to build mint send-notes script");

        let mut tx_args = TransactionArgs::default().with_tx_script(script);
        tx_args.add_output_note_recipient(Box::new(note.recipient().clone()));

        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let exec_t0 = Instant::now();
        let executed_tx = Box::pin(executor.execute_transaction(
            faucet_id,
            genesis_header.block_num(),
            InputNotes::default(),
            tx_args,
        ))
        .await
        .expect("failed to execute mint transaction");
        mint_exec_total += exec_t0.elapsed();

        let tx_inputs_bytes = executed_tx.tx_inputs().to_bytes();
        let delta = executed_tx.account_delta().clone();

        let prove_t0 = Instant::now();
        let proven_tx = prover.prove(executed_tx).await.expect("failed to prove mint transaction");
        mint_prove_total += prove_t0.elapsed();

        // Evolve the faucet state for the next iteration. The first mint of a
        // never-before-seen account produces a full-state delta (because the
        // delta carries the freshly deployed code); subsequent mints produce
        // partial-state deltas that can be applied incrementally.
        if delta.is_full_state() {
            faucet = Account::try_from(&delta)
                .expect("failed to materialize faucet from full-state delta");
        } else {
            faucet.apply_delta(&delta).expect("failed to apply faucet delta");
        }
        data_store.add_account(faucet.clone());

        mint_txs.push(proven_tx);
        mint_tx_inputs.push(tx_inputs_bytes);
        mint_notes.push(note);

        if (index + 1) % 10 == 0 || index + 1 == num_transactions {
            println!("  proved {} / {num_transactions} mint txs", index + 1);
        }
    }
    let mint_phase_elapsed = mint_phase_start.elapsed();
    print_proving_summary(
        "Mint",
        num_transactions,
        mint_phase_elapsed,
        mint_exec_total,
        mint_prove_total,
    );

    // Consume phase — also sequential for now (each tx is one wallet, independent
    // wallets, so this could be parallelized later with bounded concurrency).
    println!("Proving {num_transactions} consume transactions (sequential)...");
    let mut consume_txs: Vec<ProvenTransaction> = Vec::with_capacity(num_transactions as usize);
    let mut consume_tx_inputs: Vec<Vec<u8>> = Vec::with_capacity(num_transactions as usize);
    let consume_phase_start = Instant::now();
    let mut consume_exec_total = Duration::ZERO;
    let mut consume_prove_total = Duration::ZERO;

    for index in 0..num_transactions {
        let wallet_id = wallets[index as usize].id();
        let note = mint_notes[index as usize].clone();
        let input_note = InputNote::Unauthenticated { note };
        let input_notes =
            InputNotes::new(vec![input_note]).expect("failed to construct input notes for consume");

        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        let exec_t0 = Instant::now();
        let executed_tx = Box::pin(executor.execute_transaction(
            wallet_id,
            genesis_header.block_num(),
            input_notes,
            TransactionArgs::default(),
        ))
        .await
        .expect("failed to execute consume transaction");
        consume_exec_total += exec_t0.elapsed();

        let tx_inputs_bytes = executed_tx.tx_inputs().to_bytes();

        let prove_t0 = Instant::now();
        let proven_tx =
            prover.prove(executed_tx).await.expect("failed to prove consume transaction");
        consume_prove_total += prove_t0.elapsed();

        consume_txs.push(proven_tx);
        consume_tx_inputs.push(tx_inputs_bytes);

        if (index + 1) % 10 == 0 || index + 1 == num_transactions {
            println!("  proved {} / {num_transactions} consume txs", index + 1);
        }
    }
    let consume_phase_elapsed = consume_phase_start.elapsed();
    print_proving_summary(
        "Consume",
        num_transactions,
        consume_phase_elapsed,
        consume_exec_total,
        consume_prove_total,
    );

    let out_dir = PathBuf::from(PROOFS_DIR);
    println!("Writing proofs to {}/", out_dir.display());
    fs_err::create_dir_all(&out_dir).unwrap();
    write_to_file(&out_dir.join("mint_txs.bin"), &mint_txs);
    write_to_file(&out_dir.join("mint_tx_inputs.bin"), &mint_tx_inputs);
    write_to_file(&out_dir.join("consume_txs.bin"), &consume_txs);
    write_to_file(&out_dir.join("consume_tx_inputs.bin"), &consume_tx_inputs);
    println!("Done.");
}

/// Prints a per-phase summary of how long proof generation took, broken down
/// into the executor (VM execution) and prover (STARK proving) costs, plus the
/// mean per tx for each so that runs of different sizes can be compared.
fn print_proving_summary(
    label: &str,
    num_transactions: u64,
    wall: Duration,
    exec_total: Duration,
    prove_total: Duration,
) {
    let n_u32 = u32::try_from(num_transactions).unwrap_or(u32::MAX);
    let exec_mean = if num_transactions > 0 {
        exec_total / n_u32
    } else {
        Duration::ZERO
    };
    let prove_mean = if num_transactions > 0 {
        prove_total / n_u32
    } else {
        Duration::ZERO
    };
    let per_tx_mean = if num_transactions > 0 {
        (exec_total + prove_total) / n_u32
    } else {
        Duration::ZERO
    };
    println!("{label} proving summary (n={num_transactions}):");
    println!("  wall time:           {}", format_duration_secs(wall));
    println!(
        "  execute_transaction: total={}  mean={}/tx",
        format_duration_secs(exec_total),
        format_duration_secs(exec_mean),
    );
    println!(
        "  prover.prove:        total={}  mean={}/tx",
        format_duration_secs(prove_total),
        format_duration_secs(prove_mean),
    );
    println!("  exec+prove per tx:   mean={}/tx", format_duration_secs(per_tx_mean));
}

async fn run_benchmark(rpc_url: Url, concurrency: usize, wait_blocks: u32) {
    let in_dir = PathBuf::from(PROOFS_DIR);

    println!("Loading mint txs from {}", in_dir.join("mint_txs.bin").display());
    let mint_txs: Vec<ProvenTransaction> = read_from_file(&in_dir.join("mint_txs.bin"));
    let mint_tx_inputs: Vec<Vec<u8>> = read_from_file(&in_dir.join("mint_tx_inputs.bin"));
    assert_eq!(mint_txs.len(), mint_tx_inputs.len(), "mint tx/inputs length mismatch");

    println!("Loading consume txs from {}", in_dir.join("consume_txs.bin").display());
    let consume_txs: Vec<ProvenTransaction> = read_from_file(&in_dir.join("consume_txs.bin"));
    let consume_tx_inputs: Vec<Vec<u8>> = read_from_file(&in_dir.join("consume_tx_inputs.bin"));
    assert_eq!(consume_txs.len(), consume_tx_inputs.len(), "consume tx/inputs length mismatch");

    // Compute the tx-id master lists up front so we can match them against
    // on-chain block contents later, without having to interrogate the node.
    let mint_ids: Vec<TransactionId> = mint_txs.iter().map(ProvenTransaction::id).collect();
    let consume_ids: Vec<TransactionId> = consume_txs.iter().map(ProvenTransaction::id).collect();

    println!("Connecting to {rpc_url}...");
    let rpc_client = create_genesis_aware_rpc_client(&rpc_url, Duration::from_secs(30))
        .await
        .expect("failed to create RPC client");

    let h_start = current_block_height(rpc_client.clone()).await;
    println!("Chain height at start: {h_start}");

    println!(
        "Submitting {} mint txs sequentially (each one mutates the shared faucet, so the \
         submits must be serialized for the mempool to chain them)...",
        mint_txs.len()
    );
    let mint_stats = submit_sequential(rpc_client.clone(), mint_txs, mint_tx_inputs).await;
    print_phase_progress("mint", &mint_stats);

    println!("Submitting {} consume txs with concurrency={concurrency}...", consume_txs.len());
    let consume_stats =
        submit_all(rpc_client.clone(), consume_txs, consume_tx_inputs, concurrency).await;
    print_phase_progress("consume", &consume_stats);

    println!("Waiting {wait_blocks} blocks for the last submissions to land...");
    let h_final = wait_for_n_blocks(rpc_client.clone(), wait_blocks).await;

    println!("Checking which submitted txs landed in blocks {}..={}", h_start + 1, h_final);
    let ack_by_id = build_ack_map(&mint_ids, &mint_stats, &consume_ids, &consume_stats);
    let inclusion = compute_inclusion(rpc_client.clone(), h_start + 1, h_final, ack_by_id).await;

    print_summary(h_start, h_final, &mint_stats, &consume_stats, concurrency, &inclusion);
}

fn print_phase_progress(label: &str, stats: &PhaseStats) {
    let elapsed = stats.elapsed.as_secs_f64();
    let rate = rate_per_second(stats.ok_count(), stats.elapsed);
    println!(
        "  {label}: ok={ok} err={err} in {elapsed:.1}s ({rate:.1} tx/s ack rate)",
        ok = stats.ok_count(),
        err = stats.err_count(),
    );
}

/// Computes `count / elapsed`, treating a zero-or-negative elapsed window as
/// zero. Wrapping the cast in a helper keeps the precision-loss expect tightly
/// scoped — the loss is harmless for display purposes.
#[expect(
    clippy::cast_precision_loss,
    reason = "presentational rate; precision loss past 2^52 events is irrelevant"
)]
fn rate_per_second(count: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs > 0.0 { (count as f64) / secs } else { 0.0 }
}

/// Computes `100 * num / den` as a percentage, returning 0 when `den == 0`.
#[expect(
    clippy::cast_precision_loss,
    reason = "presentational percentage; precision loss past 2^52 is irrelevant"
)]
fn ratio_pct(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        (num as f64) * 100.0 / (den as f64)
    }
}

/// Build a lookup from the on-chain `TransactionId` of every successfully
/// submitted tx to the `SystemTime` at which the node `ACKed` its submission.
/// Used by [`compute_inclusion`] to compute per-tx inclusion latency.
fn build_ack_map(
    mint_ids: &[TransactionId],
    mint_stats: &PhaseStats,
    consume_ids: &[TransactionId],
    consume_stats: &PhaseStats,
) -> HashMap<TransactionId, SystemTime> {
    let mut map = HashMap::new();
    for outcome in &mint_stats.outcomes {
        if let Some(ack_at) = outcome.ack_at {
            map.insert(mint_ids[outcome.index], ack_at);
        }
    }
    for outcome in &consume_stats.outcomes {
        if let Some(ack_at) = outcome.ack_at {
            map.insert(consume_ids[outcome.index], ack_at);
        }
    }
    map
}

fn print_summary(
    h_start: u32,
    h_final: u32,
    mint: &PhaseStats,
    consume: &PhaseStats,
    concurrency: usize,
    inclusion: &InclusionResult,
) {
    println!();
    println!("=== Summary ===");
    println!(
        "Chain height: {h_start} -> {h_final} ({} blocks, of which {} contained at least one of our txs)",
        h_final - h_start,
        inclusion.blocks_with_our_txs
    );
    println!();
    print_phase_summary("Mint phase (sequential)", mint);
    println!();
    print_phase_summary(&format!("Consume phase (concurrent, c={concurrency})"), consume);
    println!();
    print_inclusion_summary(inclusion);
}

fn print_phase_summary(title: &str, stats: &PhaseStats) {
    let ok = stats.ok_count();
    let err = stats.err_count();
    let elapsed = stats.elapsed.as_secs_f64();
    let total = stats.outcomes.len() as u64;

    println!("{title}:");
    println!(
        "  ok = {ok} / {total}   err = {err}   ({})",
        format_err_breakdown(stats.err_by_code()),
    );

    let mut latencies = stats.submit_latencies();
    if let Some(p) = percentiles(&mut latencies) {
        println!(
            "  submit RPC latency: mean={mean}  p50={p50}  p95={p95}  p99={p99}  max={max}",
            mean = format_duration_ms(p.mean),
            p50 = format_duration_ms(p.p50),
            p95 = format_duration_ms(p.p95),
            p99 = format_duration_ms(p.p99),
            max = format_duration_ms(p.max),
        );
    } else {
        println!("  submit RPC latency: (no successful submissions)");
    }

    let rate = rate_per_second(stats.ok_count(), stats.elapsed);
    println!("  elapsed = {elapsed:.1}s,   RPC ack rate = {rate:.1} tx/s");
}

fn print_inclusion_summary(inclusion: &InclusionResult) {
    let submitted = inclusion.submitted_count;
    let included = inclusion.included_count;
    let drop = submitted.saturating_sub(included);
    let drop_pct = ratio_pct(drop, submitted);

    println!("Inclusion (per-tx ID match against block contents):");
    println!(
        "  included = {included} / {submitted} submitted   ({drop} missing, {drop_pct:.1}% drop)",
    );

    if inclusion.blocks_with_our_txs == 0 {
        println!("  no blocks observed containing any of our txs");
        return;
    }

    let txs_per_block: Vec<u32> = inclusion.txs_per_block_when_present.clone();
    let sum_txs: u32 = txs_per_block.iter().copied().sum();
    let mean_tpb =
        f64::from(sum_txs) / f64::from(u32::try_from(txs_per_block.len()).unwrap_or(u32::MAX));
    let max_tpb = txs_per_block.iter().copied().max().unwrap_or(0);
    println!(
        "  blocks with our txs = {} (mean txs/block when present = {:.1}, max = {})",
        inclusion.blocks_with_our_txs, mean_tpb, max_tpb
    );

    let span = u64::from(inclusion.last_inclusion_ts)
        .saturating_sub(u64::from(inclusion.first_inclusion_ts));
    if span == 0 {
        println!(
            "  inclusion TPS: all {included} txs landed in a single block at timestamp {} \
             (no usable timespan to divide over)",
            inclusion.first_inclusion_ts
        );
    } else {
        let tps = rate_per_second(included, Duration::from_secs(span));
        println!(
            "  inclusion TPS = {included} included / {span}s spanning blocks {}..={}  =>  {tps:.1} tx/s",
            inclusion.first_inclusion_block, inclusion.last_inclusion_block
        );
    }

    let mut lats = inclusion.inclusion_latencies.clone();
    if let Some(p) = percentiles(&mut lats) {
        println!(
            "  inclusion latency (submit_ack -> block timestamp): mean={mean}  p50={p50}  p95={p95}  p99={p99}  max={max}",
            mean = format_duration_secs(p.mean),
            p50 = format_duration_secs(p.p50),
            p95 = format_duration_secs(p.p95),
            p99 = format_duration_secs(p.p99),
            max = format_duration_secs(p.max),
        );
    }
}

fn read_from_file<T: Deserializable>(path: &std::path::Path) -> T {
    let bytes = fs_err::read(path).unwrap_or_else(|_| {
        panic!("failed to read {} — run `create-proofs` first", path.display())
    });
    T::read_from_bytes(&bytes)
        .unwrap_or_else(|_| panic!("failed to deserialize {}", path.display()))
}

fn write_to_file<T: Serializable>(path: &std::path::Path, value: &T) {
    fs_err::write(path, value.to_bytes())
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}

// SUBMISSION STATS
// ================================================================================================

/// Outcome of a single `submit_proven_transaction` RPC.
#[derive(Debug)]
struct SubmitOutcome {
    /// Position of this tx in the original input vec — used to recover the
    /// corresponding `TransactionId` from the caller-owned id list.
    index: usize,
    /// `Ok(rpc_round_trip_duration)` on success, `Err(grpc_code)` on failure.
    result: Result<Duration, tonic::Code>,
    /// Wall-clock timestamp at which the RPC returned `Ok`. `None` on error.
    /// Stored as `SystemTime` so it is directly comparable to block headers'
    /// unix-second timestamps when computing inclusion latency.
    ack_at: Option<SystemTime>,
}

/// Aggregated stats for one submission phase (mint or consume).
#[derive(Debug)]
struct PhaseStats {
    /// Wall-clock duration of the entire phase.
    elapsed: Duration,
    /// One entry per input tx, aligned by `index`.
    outcomes: Vec<SubmitOutcome>,
}

impl PhaseStats {
    fn ok_count(&self) -> u64 {
        self.outcomes.iter().filter(|o| o.result.is_ok()).count() as u64
    }

    fn err_count(&self) -> u64 {
        self.outcomes.iter().filter(|o| o.result.is_err()).count() as u64
    }

    fn submit_latencies(&self) -> Vec<Duration> {
        self.outcomes.iter().filter_map(|o| o.result.as_ref().ok().copied()).collect()
    }

    fn err_by_code(&self) -> HashMap<tonic::Code, u64> {
        let mut map: HashMap<tonic::Code, u64> = HashMap::new();
        for o in &self.outcomes {
            if let Err(code) = o.result {
                *map.entry(code).or_insert(0) += 1;
            }
        }
        map
    }
}

fn format_err_breakdown(by_code: HashMap<tonic::Code, u64>) -> String {
    if by_code.is_empty() {
        return "no errors".to_string();
    }
    let mut entries: Vec<(tonic::Code, u64)> = by_code.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    let parts: Vec<String> = entries.iter().map(|(c, n)| format!("{c:?}={n}")).collect();
    parts.join(", ")
}

fn format_duration_ms(d: Duration) -> String {
    format!("{:.1}ms", d.as_secs_f64() * 1000.0)
}

fn format_duration_secs(d: Duration) -> String {
    format!("{:.2}s", d.as_secs_f64())
}

#[derive(Debug, Clone, Copy)]
struct Percentiles {
    mean: Duration,
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
}

/// Returns `None` if there are no samples.
fn percentiles(samples: &mut [Duration]) -> Option<Percentiles> {
    if samples.is_empty() {
        return None;
    }
    samples.sort();
    let n = samples.len();
    // Integer index for percentile `num/den`. Picked over an `f64` cast to
    // avoid the cast_sign_loss / cast_precision_loss footguns.
    let pick = |num: usize, den: usize| -> Duration {
        let idx = (n * num / den).min(n - 1);
        samples[idx]
    };
    let sum: Duration = samples.iter().copied().sum();
    let mean = sum / u32::try_from(n).unwrap_or(u32::MAX);
    Some(Percentiles {
        mean,
        p50: pick(50, 100),
        p95: pick(95, 100),
        p99: pick(99, 100),
        max: *samples.last().unwrap(),
    })
}

async fn submit_all(
    client: RpcClient,
    txs: Vec<ProvenTransaction>,
    tx_inputs: Vec<Vec<u8>>,
    concurrency: usize,
) -> PhaseStats {
    /// How many distinct error messages to surface to the console as they
    /// happen. The full failure breakdown still appears in the summary.
    const MAX_ERRORS_TO_PRINT: u64 = 5;

    let start = Instant::now();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    // Incrementing-only counter used purely to budget the live error prints.
    // It is never read on the hot path, so it does not introduce any
    // submit-side synchronization beyond what was already there.
    let printed = Arc::new(AtomicU64::new(0));

    let total = txs.len();
    let mut set = tokio::task::JoinSet::new();
    for (i, (tx, inputs)) in txs.into_iter().zip(tx_inputs.into_iter()).enumerate() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let mut client = client.clone();
        let printed = printed.clone();
        set.spawn(async move {
            let request = proto::transaction::ProvenTransaction {
                transaction: tx.to_bytes(),
                transaction_inputs: Some(inputs),
            };
            let t0 = Instant::now();
            let outcome = match client.submit_proven_transaction(request).await {
                Ok(_) => SubmitOutcome {
                    index: i,
                    result: Ok(t0.elapsed()),
                    ack_at: Some(SystemTime::now()),
                },
                Err(status) => {
                    if printed.fetch_add(1, Ordering::Relaxed) < MAX_ERRORS_TO_PRINT {
                        eprintln!(
                            "  tx idx {i} failed: code={:?} message={}",
                            status.code(),
                            status.message()
                        );
                    }
                    SubmitOutcome {
                        index: i,
                        result: Err(status.code()),
                        ack_at: None,
                    }
                },
            };
            drop(permit);
            outcome
        });
    }

    // Outcomes carry their original `index`, so completion order is fine —
    // downstream summarizers don't depend on the vec being in spawn order.
    let mut outcomes = Vec::with_capacity(total);
    while let Some(res) = set.join_next().await {
        outcomes.push(res.expect("submission task panicked"));
    }

    PhaseStats { elapsed: start.elapsed(), outcomes }
}

/// Submit txs one at a time, awaiting each RPC response before sending the
/// next. Used for the mint phase, where every tx mutates the shared faucet
/// and therefore must arrive at the mempool in order — the block-producer's
/// mempool will reject out-of-order submissions but happily chains in-order
/// ones against its own pending state, so we only need to serialize the
/// `submit_proven_transaction` calls themselves, not wait for block
/// inclusion in between.
async fn submit_sequential(
    mut client: RpcClient,
    txs: Vec<ProvenTransaction>,
    tx_inputs: Vec<Vec<u8>>,
) -> PhaseStats {
    let start = Instant::now();
    let total = txs.len();
    let mut outcomes = Vec::with_capacity(total);

    for (i, (tx, inputs)) in txs.into_iter().zip(tx_inputs.into_iter()).enumerate() {
        let request = proto::transaction::ProvenTransaction {
            transaction: tx.to_bytes(),
            transaction_inputs: Some(inputs),
        };

        let t0 = Instant::now();
        let outcome = match client.submit_proven_transaction(request).await {
            Ok(_) => SubmitOutcome {
                index: i,
                result: Ok(t0.elapsed()),
                ack_at: Some(SystemTime::now()),
            },
            Err(status) => {
                eprintln!("  tx {} / {total} failed: {status}", i + 1);
                SubmitOutcome {
                    index: i,
                    result: Err(status.code()),
                    ack_at: None,
                }
            },
        };
        outcomes.push(outcome);
    }

    PhaseStats { elapsed: start.elapsed(), outcomes }
}

// INCLUSION CHECK
// ================================================================================================

#[derive(Debug)]
struct InclusionResult {
    submitted_count: u64,
    included_count: u64,
    /// Block number of the earliest block containing any of our txs.
    first_inclusion_block: u32,
    /// Block number of the latest block containing any of our txs.
    last_inclusion_block: u32,
    /// Header timestamps (unix seconds) of those two blocks. Used to compute
    /// inclusion TPS as `included_count / (last_ts - first_ts)`.
    first_inclusion_ts: u32,
    last_inclusion_ts: u32,
    /// Number of blocks in the scanned range that contained at least one of
    /// our txs (excludes empty blocks and blocks unrelated to this run).
    blocks_with_our_txs: u32,
    /// Per-block count of our txs, recorded only for blocks where the count
    /// is non-zero. Used for mean/max txs-per-block in the summary.
    txs_per_block_when_present: Vec<u32>,
    /// For each successfully submitted tx that landed in a block: the
    /// elapsed time from RPC ack to that block's header timestamp.
    inclusion_latencies: Vec<Duration>,
}

/// Walk every block from `from_block` to `to_block` inclusive, deserialize
/// it as a [`SignedBlock`], and check which of the submitted tx-ids appear
/// in each block's transaction headers. Sequential because the volumes are
/// small and the call is cheap.
async fn compute_inclusion(
    mut client: RpcClient,
    from_block: u32,
    to_block: u32,
    mut ack_by_id: HashMap<TransactionId, SystemTime>,
) -> InclusionResult {
    let submitted_count = ack_by_id.len() as u64;
    let mut included_count: u64 = 0;
    let mut first_inclusion_block: u32 = 0;
    let mut last_inclusion_block: u32 = 0;
    let mut first_inclusion_ts: u32 = 0;
    let mut last_inclusion_ts: u32 = 0;
    let mut blocks_with_our_txs: u32 = 0;
    let mut txs_per_block_when_present: Vec<u32> = Vec::new();
    let mut inclusion_latencies: Vec<Duration> = Vec::new();

    if from_block > to_block {
        return InclusionResult {
            submitted_count,
            included_count,
            first_inclusion_block,
            last_inclusion_block,
            first_inclusion_ts,
            last_inclusion_ts,
            blocks_with_our_txs,
            txs_per_block_when_present,
            inclusion_latencies,
        };
    }

    for block_num in from_block..=to_block {
        let request = proto::blockchain::BlockRequest { block_num, include_proof: None };
        let response = match client.get_block_by_number(request).await {
            Ok(r) => r.into_inner(),
            Err(status) => {
                eprintln!(
                    "  warning: get_block_by_number({block_num}) failed: {status} \
                     — skipping this block in the inclusion scan"
                );
                continue;
            },
        };
        let Some(bytes) = response.block else {
            continue;
        };
        let signed_block = match SignedBlock::read_from_bytes(&bytes) {
            Ok(sb) => sb,
            Err(err) => {
                eprintln!(
                    "  warning: failed to deserialize SignedBlock for block {block_num}: {err}"
                );
                continue;
            },
        };

        let block_ts = signed_block.header().timestamp();
        let block_ts_system = UNIX_EPOCH + Duration::from_secs(u64::from(block_ts));
        let mut hits_in_this_block: u32 = 0;

        for header in signed_block.body().transactions().as_slice() {
            if let Some(ack_at) = ack_by_id.remove(&header.id()) {
                hits_in_this_block += 1;
                included_count += 1;
                // Block timestamps have 1-second resolution and may round
                // down past the ack instant; clamp negative deltas to zero.
                let latency = block_ts_system.duration_since(ack_at).unwrap_or_default();
                inclusion_latencies.push(latency);
            }
        }

        if hits_in_this_block > 0 {
            if blocks_with_our_txs == 0 {
                first_inclusion_block = block_num;
                first_inclusion_ts = block_ts;
            }
            last_inclusion_block = block_num;
            last_inclusion_ts = block_ts;
            blocks_with_our_txs += 1;
            txs_per_block_when_present.push(hits_in_this_block);
        }
    }

    InclusionResult {
        submitted_count,
        included_count,
        first_inclusion_block,
        last_inclusion_block,
        first_inclusion_ts,
        last_inclusion_ts,
        blocks_with_our_txs,
        txs_per_block_when_present,
        inclusion_latencies,
    }
}

async fn current_block_height(mut client: RpcClient) -> u32 {
    let response = client
        .get_block_header_by_number(BlockHeaderByNumberRequest {
            block_num: None,
            include_mmr_proof: None,
        })
        .await
        .expect("failed to fetch latest block header")
        .into_inner();
    let header: BlockHeader = response
        .block_header
        .expect("no block header in response")
        .try_into()
        .expect("failed to decode block header");
    header.block_num().as_u32()
}

/// Wait until the chain has advanced by `n` blocks past whatever the current
/// height is, then return. Used to give the block-producer time to include
/// in-flight submissions without falsely waiting forever (the node produces
/// empty blocks at a steady interval, so "no height change" never fires).
async fn wait_for_n_blocks(client: RpcClient, n: u32) -> u32 {
    let start_height = current_block_height(client.clone()).await;
    let target = start_height + n;
    let mut last = start_height;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let h = current_block_height(client.clone()).await;
        if h != last {
            println!("  block height: {h}");
            last = h;
        }
        if h >= target {
            return h;
        }
    }
}

/// Create an RPC client configured with the correct genesis metadata in the
/// `Accept` header so that write RPCs such as `SubmitProvenTransaction` are
/// accepted by the node.
pub async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<RpcClient> {
    let use_tls = rpc_url.scheme() == "https";

    let tls_stage = Builder::new(rpc_url.clone());
    let timeout_stage = if use_tls {
        tls_stage.with_tls().context("Failed to configure TLS for RPC client")?
    } else {
        tls_stage.without_tls()
    };
    let mut rpc: RpcClient = timeout_stage
        .with_timeout(timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to create RPC client for genesis discovery")?;

    let response = rpc
        .get_block_header_by_number(get_genesis_header_request())
        .await
        .context("Failed to get genesis block header from RPC")?
        .into_inner();

    let genesis_block_header = response
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    let genesis_header: BlockHeader =
        genesis_block_header.try_into().context("Failed to convert block header")?;

    let genesis_commitment = genesis_header.commitment();
    let genesis = genesis_commitment.to_hex();

    let tls_stage = Builder::new(rpc_url.clone());
    let timeout_stage = if use_tls {
        tls_stage.with_tls().context("Failed to configure TLS for RPC client")?
    } else {
        tls_stage.without_tls()
    };
    let rpc_client = timeout_stage
        .with_timeout(timeout)
        .without_metadata_version()
        .with_metadata_genesis(genesis)
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to connect to RPC server with genesis metadata")?;

    Ok(rpc_client)
}

fn get_genesis_header_request() -> BlockHeaderByNumberRequest {
    BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    }
}

/// Creates a new faucet account and returns it alongside its secret key.
fn create_faucet() -> (Account, SecretKey) {
    let coin_seed: [u64; 4] = rand::rng().random();
    let mut rng = RandomCoin::new(coin_seed.map(Felt::new).into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let init_seed = [0_u8; 32];

    let token_symbol = TokenSymbol::new("TEST").unwrap();
    let token_metadata = FungibleTokenMetadata::builder(
        TokenName::new("TEST").unwrap(),
        token_symbol,
        2,
        FungibleAsset::MAX_AMOUNT,
    )
    .build()
    .unwrap();
    let faucet = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Private)
        .with_component(token_metadata)
        .with_component(BasicFungibleFaucet)
        .with_components(TokenPolicyManager::new(
            PolicyAuthority::AuthControlled,
            MintPolicyConfig::AllowAll,
            BurnPolicyConfig::AllowAll,
        ))
        .with_auth_component(AuthSingleSig::new(
            key_pair.public_key().into(),
            AuthScheme::Falcon512Poseidon2,
        ))
        .build()
        .unwrap();
    (faucet, key_pair)
}

/// Creates a new wallet account with the given public key, using `index` to vary
/// the init seed so each wallet ends up with a distinct account ID.
fn create_wallet(
    public_key: &miden_protocol::crypto::dsa::falcon512_poseidon2::PublicKey,
    index: u64,
) -> Account {
    let init_seed: Vec<_> = index.to_be_bytes().into_iter().chain([0u8; 24]).collect();
    AccountBuilder::new(init_seed.try_into().unwrap())
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Private)
        .with_auth_component(AuthSingleSig::new(
            public_key.clone().into(),
            AuthScheme::Falcon512Poseidon2,
        ))
        .with_component(BasicWallet)
        .build()
        .unwrap()
}

// BENCHMARK DATA STORE
// ================================================================================================

/// In-memory `DataStore` impl used to feed the [`TransactionExecutor`] when
/// generating real proofs locally. Modelled on the network-monitor's
/// `MonitorDataStore`.
pub struct BenchmarkDataStore {
    accounts: HashMap<AccountId, Account>,
    block_header: BlockHeader,
    partial_block_chain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl BenchmarkDataStore {
    pub fn new(block_header: BlockHeader, partial_block_chain: PartialBlockchain) -> Self {
        Self {
            accounts: HashMap::new(),
            block_header,
            partial_block_chain,
            mast_store: TransactionMastStore::new(),
        }
    }

    pub fn add_account(&mut self, account: Account) {
        self.mast_store.load_account_code(account.code());
        self.accounts.insert(account.id(), account);
    }

    fn get_account(&self, account_id: AccountId) -> Result<&Account, DataStoreError> {
        self.accounts.get(&account_id).ok_or_else(|| DataStoreError::Other {
            error_msg: "unknown account".into(),
            source: None,
        })
    }
}

impl DataStore for BenchmarkDataStore {
    async fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        _block_refs: BTreeSet<BlockNumber>,
    ) -> Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError> {
        let account = self.get_account(account_id)?;
        let partial_account = PartialAccount::from(account);
        Ok((partial_account, self.block_header.clone(), self.partial_block_chain.clone()))
    }

    async fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> Result<miden_protocol::account::StorageMapWitness, DataStoreError> {
        let account = self.get_account(account_id)?;
        for slot in account.storage().slots() {
            if let miden_protocol::account::StorageSlotContent::Map(map) = slot.content() {
                if map.root() == map_root {
                    return Ok(map.open(&map_key));
                }
            }
        }
        Err(DataStoreError::Other {
            error_msg: format!("no storage map with the requested root in account {account_id}")
                .into(),
            source: None,
        })
    }

    async fn get_foreign_account_inputs(
        &self,
        _foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> Result<AccountInputs, DataStoreError> {
        unimplemented!("foreign account inputs are not needed for the benchmark")
    }

    async fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> Result<Vec<AssetWitness>, DataStoreError> {
        let account = self.get_account(account_id)?;

        if account.vault().root() != vault_root {
            return Err(DataStoreError::Other {
                error_msg: "vault root mismatch".into(),
                source: None,
            });
        }

        Result::<Vec<_>, _>::from_iter(vault_keys.into_iter().map(|vault_key| {
            AssetWitness::new(account.vault().open(vault_key).into()).map_err(|err| {
                DataStoreError::Other {
                    error_msg: "failed to open vault asset tree".into(),
                    source: Some(Box::new(err)),
                }
            })
        }))
    }

    async fn get_note_script(
        &self,
        _script_root: NoteScriptRoot,
    ) -> Result<Option<NoteScript>, DataStoreError> {
        Ok(None)
    }
}

impl MastForestStore for BenchmarkDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<Arc<MastForest>> {
        self.mast_store.get(procedure_hash)
    }
}
