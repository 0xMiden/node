//! Pluggable prover for the `create-proofs` orchestrator.
//!
//! - [`BenchmarkProver::Local`] keeps the current `LocalTransactionProver` path (the default when
//!   `--remote-prover-url` is not set).
//! - [`BenchmarkProver::Remote`] talks to a deployed remote prover. To avoid slamming an
//!   autoscaling fleet at t=0, requests are paced by a [`RampingRateLimiter`] that starts at
//!   [`START_RATE`] rps and bumps by 1 rps every [`STEP_DURATION`] until it hits [`MAX_RATE`].
//!   Retryable gRPC errors (resource-exhausted, unavailable, deadline-exceeded, or any
//!   transport-level failure) freeze the ramp at the current step for the rest of the run.

use std::error::Error as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction, TransactionInputs};
use miden_remote_prover_client::RemoteTransactionProver;
use miden_tx::{LocalTransactionProver, TransactionProverError};
use tokio::sync::{Mutex, Semaphore};

// SCHEDULE CONSTANTS
// ================================================================================================

const START_RATE: u32 = 1;
const MAX_RATE: u32 = 10;
const STEP_DURATION: Duration = Duration::from_secs(180);

/// Per-request gRPC deadline. STARK transaction proofs routinely exceed the default 10s, so we
/// override it. Anything past this is treated as a retryable error.
const PROVE_TIMEOUT: Duration = Duration::from_secs(120);

/// Cap on the number of proving requests in flight at once, independent of the rate. At
/// [`MAX_RATE`] with ~30s proof latency we'd otherwise stack hundreds of in-flight requests.
const MAX_IN_FLIGHT: usize = 64;

// RETRY CONSTANTS
// ================================================================================================

const RETRY_BASE: Duration = Duration::from_millis(500);
const RETRY_MAX_BACKOFF: Duration = Duration::from_secs(30);
const RETRY_MAX_ATTEMPTS: u32 = 10;
const RETRY_BACKOFF_SHIFT_CAP: u32 = 6;

// BENCHMARK PROVER
// ================================================================================================

pub(crate) enum BenchmarkProver {
    Local(LocalTransactionProver),
    Remote {
        prover: RemoteTransactionProver,
        limiter: Arc<RampingRateLimiter>,
        permits: Arc<Semaphore>,
    },
}

impl BenchmarkProver {
    pub(crate) fn local() -> Self {
        Self::Local(LocalTransactionProver::default())
    }

    pub(crate) fn remote(endpoint: String) -> Self {
        let prover = RemoteTransactionProver::new(endpoint).with_timeout(PROVE_TIMEOUT);
        Self::Remote {
            prover,
            limiter: Arc::new(RampingRateLimiter::new()),
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
        }
    }

    /// Prove the given executed transaction. The remote path paces dispatch through the rate
    /// limiter and retries retryable errors with exponential backoff; the local path runs the
    /// in-process prover directly.
    pub(crate) async fn prove(
        &self,
        executed_tx: ExecutedTransaction,
    ) -> Result<ProvenTransaction> {
        match self {
            Self::Local(prover) => prover
                .prove(executed_tx)
                .await
                .map_err(|err| anyhow::anyhow!("local proving failed: {err}")),
            Self::Remote { prover, limiter, permits } => {
                let tx_inputs: TransactionInputs = executed_tx.into();
                prove_remote_with_retry(prover, limiter, permits, &tx_inputs).await
            },
        }
    }
}

async fn prove_remote_with_retry(
    prover: &RemoteTransactionProver,
    limiter: &Arc<RampingRateLimiter>,
    permits: &Arc<Semaphore>,
    tx_inputs: &TransactionInputs,
) -> Result<ProvenTransaction> {
    // Hold one in-flight permit across every retry so the concurrency cap accounts for
    // slow-but-still-progressing requests.
    let _permit = permits
        .clone()
        .acquire_owned()
        .await
        .expect("in-flight semaphore is never closed");

    let mut attempt: u32 = 0;
    loop {
        limiter.acquire().await;
        match prover.prove(tx_inputs).await {
            Ok(tx) => return Ok(tx),
            Err(err) => {
                if !is_retryable(&err) {
                    return Err(anyhow::anyhow!("remote proving failed: {err}"));
                }
                limiter.freeze();
                attempt += 1;
                if attempt > RETRY_MAX_ATTEMPTS {
                    return Err(anyhow::anyhow!(
                        "remote proving failed after {RETRY_MAX_ATTEMPTS} retries: {err}"
                    ));
                }
                let shift = attempt.min(RETRY_BACKOFF_SHIFT_CAP);
                let backoff = (RETRY_BASE.saturating_mul(1 << shift)).min(RETRY_MAX_BACKOFF);
                eprintln!(
                    "remote prover returned retryable error (attempt {attempt}/{RETRY_MAX_ATTEMPTS}, backoff {backoff:?}): {err}"
                );
                tokio::time::sleep(backoff).await;
            },
        }
    }
}

/// Walk the error source chain looking for a tonic status or transport error. We classify
/// resource-exhausted, unavailable, deadline-exceeded, and any transport-level failure (e.g. broken
/// pipe, connect refused) as retryable.
fn is_retryable(err: &TransactionProverError) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = err.source();
    while let Some(e) = src {
        if let Some(status) = e.downcast_ref::<tonic::Status>() {
            return matches!(
                status.code(),
                tonic::Code::ResourceExhausted
                    | tonic::Code::Unavailable
                    | tonic::Code::DeadlineExceeded
            );
        }
        if e.downcast_ref::<tonic::transport::Error>().is_some() {
            return true;
        }
        src = e.source();
    }
    false
}

// RAMPING RATE LIMITER
// ================================================================================================

/// A wall-clock-anchored rate limiter that ramps from [`START_RATE`] to
/// [`MAX_RATE`] requests/sec, bumping by 1 rps every [`STEP_DURATION`].
///
/// [`freeze`](Self::freeze) caps the rate at its current value for the rest of
/// the run; once frozen, the ramp never resumes.
pub(crate) struct RampingRateLimiter {
    start: Instant,
    inner: Mutex<Inner>,
    /// Last rate we logged a step transition for. Used purely for logging.
    reported_rate: AtomicU32,
}

struct Inner {
    /// Earliest instant at which the next `acquire()` may return.
    next_release: Instant,
    /// If `Some(rate)`, the rate is capped at `rate` for the rest of the run.
    frozen_at: Option<u32>,
}

impl RampingRateLimiter {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            inner: Mutex::new(Inner { next_release: now, frozen_at: None }),
            reported_rate: AtomicU32::new(0),
        }
    }

    /// Block until this caller is allowed to dispatch one request under the current rate schedule.
    async fn acquire(&self) {
        let sleep_until = {
            let mut inner = self.inner.lock().await;
            let rate = compute_rate(self.start, inner.frozen_at);
            let now = Instant::now();
            let earliest = inner.next_release.max(now);
            let slot = earliest + slot_interval(rate);
            inner.next_release = slot;

            let prev = self.reported_rate.swap(rate, Ordering::Relaxed);
            if prev != rate {
                println!("  rate limiter: now dispatching at {rate} req/s");
            }
            earliest
        };
        tokio::time::sleep_until(sleep_until.into()).await;
    }

    /// Freeze the rate at the current value. Idempotent — first freeze wins.
    fn freeze(&self) {
        // Best-effort lock; if contended, the other caller will set it.
        if let Ok(mut inner) = self.inner.try_lock() {
            if inner.frozen_at.is_none() {
                let rate = compute_rate(self.start, None);
                inner.frozen_at = Some(rate);
                println!(
                    "  rate limiter: freezing ramp at {rate} req/s after retryable prover error"
                );
            }
        }
    }
}

fn compute_rate(start: Instant, frozen_at: Option<u32>) -> u32 {
    let elapsed = start.elapsed();
    let step = u32::try_from(elapsed.as_secs() / STEP_DURATION.as_secs()).unwrap_or(u32::MAX);
    let target = START_RATE.saturating_add(step).min(MAX_RATE);
    frozen_at.map_or(target, |cap| target.min(cap))
}

fn slot_interval(rate: u32) -> Duration {
    Duration::from_micros(1_000_000 / u64::from(rate.max(1)))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_starts_at_start_rate() {
        let now = Instant::now();
        assert_eq!(compute_rate(now, None), START_RATE);
    }

    #[test]
    fn rate_is_capped_by_freeze() {
        let now = Instant::now();
        // `frozen_at` is a cap, not a target — at t=0 the natural rate is `START_RATE`, which is
        // already below caps of 3 or higher.
        assert_eq!(compute_rate(now, Some(3)), START_RATE);
        assert_eq!(compute_rate(now, Some(MAX_RATE)), START_RATE);
        // A cap below the natural rate clamps the result down.
        assert_eq!(compute_rate(now, Some(0)), 0);
    }

    #[test]
    fn natural_rate_is_capped_at_max() {
        // Simulate "elapsed > MAX_RATE * STEP_DURATION" by constructing a start instant far in the
        // past.
        let long_ago = Instant::now()
            .checked_sub(STEP_DURATION * (MAX_RATE + 5))
            .expect("test environment supports backdated Instants");
        assert_eq!(compute_rate(long_ago, None), MAX_RATE);
        assert_eq!(compute_rate(long_ago, Some(4)), 4);
    }

    #[test]
    fn slot_interval_matches_rate() {
        assert_eq!(slot_interval(1), Duration::from_secs(1));
        assert_eq!(slot_interval(10), Duration::from_millis(100));
    }
}
