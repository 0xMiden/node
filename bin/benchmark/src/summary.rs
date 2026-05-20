//! Every line the bench prints to stdout, plus the formatting and metric helpers that only matter
//! for output (percentiles, rate/percentage casts, duration formatters). Other modules pass
//! `PhaseStats` and `InclusionResult` references in; this module never mutates or owns them.

use std::collections::HashMap;
use std::time::Duration;

use crate::inclusion::{BlockHit, InclusionResult};
use crate::submit::PhaseStats;

// PROOF-GENERATION SUMMARY
// ================================================================================================

/// Prints a per-phase summary of how long proof generation took, broken down into the executor (VM
/// execution) and prover (STARK proving) costs, plus the mean per tx for each so that runs of
/// different sizes can be compared.
pub(crate) fn print_proving_summary(
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

// SUBMISSION SUMMARIES
// ================================================================================================

pub(crate) fn print_phase_progress(label: &str, stats: &PhaseStats) {
    let elapsed = stats.elapsed.as_secs_f64();
    let rate = rate_per_second(stats.ok_count(), stats.elapsed);
    println!(
        "  {label}: ok={ok} err={err} in {elapsed:.1}s ({rate:.1} tx/s ack rate)",
        ok = stats.ok_count(),
        err = stats.err_count(),
    );
}

pub(crate) fn print_summary(
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
        inclusion.per_block_hits.len(),
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

    let hits = &inclusion.per_block_hits;
    if hits.is_empty() {
        println!("  no blocks observed containing any of our txs");
        return;
    }

    // Per-block aggregates.
    let counts: Vec<u32> = hits.iter().map(|h| h.hit_count).collect();
    let sum_counts: u32 = counts.iter().copied().sum();
    let max_count = counts.iter().copied().max().unwrap_or(0);
    let n_blocks = u32::try_from(counts.len()).unwrap_or(u32::MAX);
    let mean_count = f64::from(sum_counts) / f64::from(n_blocks);

    let peak_block = hits.iter().max_by_key(|h| h.hit_count).expect("non-empty hits");
    let first_block = hits.first().expect("non-empty hits");
    let last_block = hits.last().expect("non-empty hits");

    println!(
        "  blocks with our txs = {n_blocks} \
         (block range {}..={}, mean txs/block when present = {mean_count:.1}, max = {max_count})",
        first_block.block_num, last_block.block_num,
    );

    // Derive the block interval from consecutive scanned timestamps.
    let Some(block_interval) = inclusion.derived_block_interval() else {
        println!(
            "  block interval: could not derive from {} scanned block(s) \
             (need >=2 blocks spanning at least one second boundary)",
            inclusion.scanned_block_count,
        );
        println!("  throughput metrics skipped; per-block series follows.");
        print_per_block_series(hits, None);
        return;
    };

    println!(
        "  derived block interval = {} (from {} scanned blocks, span = {}s)",
        format_duration_secs(block_interval),
        inclusion.scanned_block_count,
        inclusion.scanned_last_ts - inclusion.scanned_first_ts,
    );

    // Throughput. Each block-with-our-txs is treated as `block_interval` seconds of node work.
    let interval_secs = block_interval.as_secs_f64();
    let peak_rate = rate_per_second(u64::from(peak_block.hit_count), block_interval);
    let mean_rate = if interval_secs > 0.0 {
        mean_count / interval_secs
    } else {
        0.0
    };
    let window_rate = rate_per_second(included, block_interval.saturating_mul(n_blocks));

    println!(
        "  peak per-block rate  = {} txs in block {}  =>  {peak_rate:.1} tx/s",
        peak_block.hit_count, peak_block.block_num,
    );
    println!("  mean per-block rate  = {mean_count:.1} txs/block  =>  {mean_rate:.1} tx/s");
    println!(
        "  window-average TPS   = {included} included / ({n_blocks} blocks * {}) \
         =>  {window_rate:.1} tx/s",
        format_duration_secs(block_interval),
    );

    print_per_block_series(hits, Some(block_interval));

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

/// Print a compact per-block series so the operator can eyeball the time-series shape (ramp,
/// plateau, dip). Empty blocks in the scan range are intentionally omitted. If `block_interval` is
/// `Some`, each line also shows the equivalent rate; if `None`, only the raw count.
fn print_per_block_series(hits: &[BlockHit], block_interval: Option<Duration>) {
    println!("  per-block series:");
    for hit in hits {
        match block_interval {
            Some(interval) => {
                let rate = rate_per_second(u64::from(hit.hit_count), interval);
                println!(
                    "    block {} (ts={}): {} txs   ({rate:.1} tx/s @ block_interval)",
                    hit.block_num, hit.block_ts, hit.hit_count,
                );
            },
            None => {
                println!(
                    "    block {} (ts={}): {} txs",
                    hit.block_num, hit.block_ts, hit.hit_count,
                );
            },
        }
    }
}

// METRIC HELPERS
// ================================================================================================

/// Computes `count / elapsed`, treating a zero-or-negative elapsed window as zero. Wrapping the
/// cast in a helper keeps the precision-loss expect tightly scoped — the loss is harmless for
/// display purposes.
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
    // Integer index for percentile `num/den`. Picked over an `f64` cast to avoid the cast_sign_loss
    // / cast_precision_loss footguns.
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
