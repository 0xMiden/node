//! The `run-benchmark` orchestrator and the submission RPC primitives.
//!
//! `run` is the top-level entry point invoked from `main::Cli::run` for the
//! `RunBenchmark` subcommand. It owns the dance of loading the proven-tx
//! bundle, submitting mints sequentially and consumes concurrently, waiting
//! for the chain to advance, and handing off to [`crate::inclusion`] +
//! [`crate::summary`] for the inclusion scan and the human-readable summary.
//!
//! The submission primitives ([`submit_all`], [`submit_sequential`]) and the
//! aggregate types ([`SubmitOutcome`], [`PhaseStats`]) live here too because
//! they're not used anywhere else — only `summary` reads `PhaseStats` and only
//! by `&` reference.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated as proto;
use miden_protocol::transaction::{ProvenTransaction, TransactionId};
use miden_protocol::utils::serde::Serializable;
use tokio::sync::Semaphore;
use url::Url;

use crate::inclusion::{current_block_height, scan_with_drain};
use crate::summary::{print_phase_progress, print_summary};
use crate::{PROOFS_DIR, create_genesis_aware_rpc_client_pool, read_from_file};

// ORCHESTRATOR
// ================================================================================================

pub(crate) async fn run(rpc_url: Url, concurrency: usize, connections: usize, wait_blocks: u32) {
    let in_dir = PathBuf::from(PROOFS_DIR);

    println!("Loading mint txs from {}", in_dir.join("mint_txs.bin").display());
    let mint_txs: Vec<ProvenTransaction> = read_from_file(&in_dir.join("mint_txs.bin"));
    let mint_tx_inputs: Vec<Vec<u8>> = read_from_file(&in_dir.join("mint_tx_inputs.bin"));
    assert_eq!(mint_txs.len(), mint_tx_inputs.len(), "mint tx/inputs length mismatch");

    println!("Loading consume txs from {}", in_dir.join("consume_txs.bin").display());
    let consume_txs: Vec<ProvenTransaction> = read_from_file(&in_dir.join("consume_txs.bin"));
    let consume_tx_inputs: Vec<Vec<u8>> = read_from_file(&in_dir.join("consume_tx_inputs.bin"));
    assert_eq!(consume_txs.len(), consume_tx_inputs.len(), "consume tx/inputs length mismatch");

    // Compute the consume tx-id master list up front so we can match it against on-chain block
    // contents later, without having to interrogate the node. (Mints are not tracked on-chain.)
    let consume_ids: Vec<TransactionId> = consume_txs.iter().map(ProvenTransaction::id).collect();

    println!("Connecting to {rpc_url} ({connections} connection(s))...");
    let pool = create_genesis_aware_rpc_client_pool(&rpc_url, Duration::from_secs(30), connections)
        .await
        .expect("failed to create RPC client pool");
    let pool = Arc::new(pool);

    let h_start = current_block_height(pool[0].clone()).await;
    println!("Chain height at start: {h_start}");

    println!(
        "Submitting {} mint txs sequentially (each one mutates the shared faucet, so the \
         submits must be serialized for the mempool to chain them)...",
        mint_txs.len()
    );
    let mint_stats = submit_sequential(pool[0].clone(), mint_txs, mint_tx_inputs).await;
    print_phase_progress("mint", &mint_stats);

    println!(
        "Submitting {} consume txs with concurrency={concurrency} across {} connection(s)...",
        consume_txs.len(),
        pool.len(),
    );
    let consume_stats = submit_all(pool.clone(), consume_txs, consume_tx_inputs, concurrency).await;
    print_phase_progress("consume", &consume_stats);

    let ack_by_id = build_ack_map(&consume_ids, &consume_stats);
    println!(
        "Watching for inclusion of {} acked consume tx(s) (max {wait_blocks} blocks past height {h_start})...",
        ack_by_id.len(),
    );
    let (h_final, inclusion) =
        scan_with_drain(pool[0].clone(), h_start, wait_blocks, ack_by_id).await;

    print_summary(h_start, h_final, &mint_stats, &consume_stats, concurrency, &inclusion);
}

// SUBMISSION STATS
// ================================================================================================

/// Outcome of a single `submit_proven_tx` RPC.
#[derive(Debug)]
pub(crate) struct SubmitOutcome {
    /// Position of this tx in the original input vec — used to recover the corresponding
    /// `TransactionId` from the caller-owned id list.
    pub(crate) index: usize,
    /// `Ok(rpc_round_trip_duration)` on success, `Err(grpc_code)` on failure.
    pub(crate) result: Result<Duration, tonic::Code>,
    /// Wall-clock timestamp at which the RPC returned `Ok`. `None` on error. Stored as `SystemTime`
    /// so it is directly comparable to block headers' unix-second timestamps when computing
    /// inclusion latency.
    pub(crate) ack_at: Option<SystemTime>,
}

/// Aggregated stats for one submission phase (mint or consume).
#[derive(Debug)]
pub(crate) struct PhaseStats {
    /// Wall-clock duration of the entire phase.
    pub(crate) elapsed: Duration,
    /// One entry per input tx, aligned by `index`.
    pub(crate) outcomes: Vec<SubmitOutcome>,
}

impl PhaseStats {
    pub(crate) fn ok_count(&self) -> u64 {
        self.outcomes.iter().filter(|o| o.result.is_ok()).count() as u64
    }

    pub(crate) fn err_count(&self) -> u64 {
        self.outcomes.iter().filter(|o| o.result.is_err()).count() as u64
    }

    pub(crate) fn submit_latencies(&self) -> Vec<Duration> {
        self.outcomes.iter().filter_map(|o| o.result.as_ref().ok().copied()).collect()
    }

    pub(crate) fn err_by_code(&self) -> HashMap<tonic::Code, u64> {
        let mut map: HashMap<tonic::Code, u64> = HashMap::new();
        for o in &self.outcomes {
            if let Err(code) = o.result {
                *map.entry(code).or_insert(0) += 1;
            }
        }
        map
    }
}

// SUBMISSION PRIMITIVES
// ================================================================================================

async fn submit_all(
    pool: Arc<Vec<RpcClient>>,
    txs: Vec<ProvenTransaction>,
    tx_inputs: Vec<Vec<u8>>,
    concurrency: usize,
) -> PhaseStats {
    /// How many distinct error messages to surface to the console as they happen. The full failure
    /// breakdown still appears in the summary.
    const MAX_ERRORS_TO_PRINT: u64 = 5;

    let start = Instant::now();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    // Incrementing-only counter used purely to budget the live error prints. It is never read on
    // the hot path, so it does not introduce any submit-side synchronization beyond what was
    // already there.
    let printed = Arc::new(AtomicU64::new(0));

    let total = txs.len();
    let mut set = tokio::task::JoinSet::new();
    for (i, (tx, inputs)) in txs.into_iter().zip(tx_inputs.into_iter()).enumerate() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        // Round-robin across the connection pool so concurrent submissions ride separate HTTP/2
        // sockets instead of multiplexing over one channel.
        let mut client = pool[i % pool.len()].clone();
        let printed = printed.clone();
        set.spawn(async move {
            let request = proto::transaction::ProvenTransaction {
                transaction: tx.to_bytes(),
                transaction_inputs: Some(inputs),
            };
            let t0 = Instant::now();
            let outcome = match client.submit_proven_tx(request).await {
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

    // Outcomes carry their original `index`, so completion order is fine — downstream summarizers
    // don't depend on the vec being in spawn order.
    let mut outcomes = Vec::with_capacity(total);
    while let Some(res) = set.join_next().await {
        outcomes.push(res.expect("submission task panicked"));
    }

    PhaseStats { elapsed: start.elapsed(), outcomes }
}

/// Submit txs one at a time, awaiting each RPC response before sending the next. Used for the mint
/// phase, where every tx mutates the shared faucet and therefore must arrive at the mempool in
/// order — the block-producer's mempool will reject out-of-order submissions but happily chains
/// in-order ones against its own pending state, so we only need to serialize the `submit_proven_tx`
/// calls themselves, not wait for block inclusion in between.
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
        let outcome = match client.submit_proven_tx(request).await {
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

/// Build a lookup from the on-chain `TransactionId` of every successfully submitted consume tx to
/// the `SystemTime` at which the node ack'd its submission. Used by the inclusion scan to compute
/// per-tx inclusion latency. Mint txs are intentionally excluded (see the call site).
fn build_ack_map(
    consume_ids: &[TransactionId],
    consume_stats: &PhaseStats,
) -> HashMap<TransactionId, SystemTime> {
    let mut map = HashMap::new();
    for outcome in &consume_stats.outcomes {
        if let Some(ack_at) = outcome.ack_at {
            map.insert(consume_ids[outcome.index], ack_at);
        }
    }
    map
}
