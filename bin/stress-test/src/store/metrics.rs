use std::time::Duration;

/// Prints a summary of the benchmark results, including the average and various percentile
/// request latencies to help diagnose performance outliers.
pub fn print_summary(timers_accumulator: &[Duration]) {
    let avg_time = timers_accumulator.iter().sum::<Duration>() / timers_accumulator.len() as u32;
    println!("Average request latency: {avg_time:?}");

    let p50_time = compute_percentile(timers_accumulator, 50.0);
    let p95_time = compute_percentile(timers_accumulator, 95.0);
    let p99_time = compute_percentile(timers_accumulator, 99.0);
    let p99_9_time = compute_percentile(timers_accumulator, 99.9);

    println!("P50 request latency: {p50_time:?}");
    println!("P95 request latency: {p95_time:?}");
    println!("P99 request latency: {p99_time:?}");
    println!("P99.9 request latency: {p99_9_time:?}");
}

/// Computes a percentile from a list of durations.
#[expect(clippy::cast_sign_loss, clippy::cast_precision_loss)]
fn compute_percentile(times: &[Duration], percentile: f64) -> Duration {
    if times.is_empty() {
        return Duration::ZERO;
    }

    let mut sorted_times = times.to_vec();
    sorted_times.sort_unstable();

    // Calculate the index for the given percentile
    // For P99.9 with 10000 samples: index = (99.9 / 100.0) * 10000 = 9990
    let index = (percentile / 100.0 * sorted_times.len() as f64).round() as usize;

    // Ensure index is within bounds
    let index = index.min(sorted_times.len() - 1);

    sorted_times[index]
}
