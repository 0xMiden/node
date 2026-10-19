use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::time::Duration;

use anyhow::Context;
use miden_node_tracing::{error, info};
pub use tokio_util::sync::CancellationToken;

/// Time allowed for services to finish after a shutdown signal before the process exits.
pub const GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Operating-system signal which requested service shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownSignal {
    Interrupt,
    Terminate,
}

impl Display for ShutdownSignal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupt => f.write_str("SIGINT"),
            Self::Terminate => f.write_str("SIGTERM"),
        }
    }
}

/// Runs a service future until it completes or a shutdown signal is received.
///
/// On `SIGTERM` or Ctrl-C, the provided root cancellation token is cancelled and the service future
/// is given [`GRACE_PERIOD`] to complete. If it does not, the process exits immediately so
/// blocking work cannot hold the Tokio runtime alive indefinitely.
pub async fn run_with_shutdown<F, Fut>(service_name: &'static str, run: F) -> anyhow::Result<()>
where
    F: FnOnce(CancellationToken) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    run_with_shutdown_signal(service_name, run, shutdown_signal()).await
}

async fn run_with_shutdown_signal<F, Fut, Signal>(
    service_name: &'static str,
    run: F,
    signal: Signal,
) -> anyhow::Result<()>
where
    F: FnOnce(CancellationToken) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
    Signal: Future<Output = anyhow::Result<ShutdownSignal>>,
{
    let token = CancellationToken::new();
    let service = run(token.clone());
    tokio::pin!(service);
    tokio::pin!(signal);

    tokio::select! {
        result = &mut service => result,
        result = &mut signal => {
            let signal = result?;
            info!(
                "Shutdown requested",
                service.name = service_name,
                shutdown.signal = signal.to_string()
            );
            token.cancel();

            let Ok(result) = tokio::time::timeout(GRACE_PERIOD, &mut service).await else {
                error!(
                    anyhow::anyhow!("graceful shutdown timed out"),
                    "Graceful shutdown timed out; exiting process",
                    service.name = service_name,
                    shutdown.grace_period_ms = GRACE_PERIOD
                );
                std::process::exit(1);
            };

            result?;
            info!("Shutdown complete", service.name = service_name);
            Ok(())
        },
    }
}

/// Waits for SIGTERM or Ctrl-C.
pub async fn shutdown_signal() -> anyhow::Result<ShutdownSignal> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("failed to install SIGTERM handler")?;

        tokio::select! {
            _ = terminate.recv() => Ok(ShutdownSignal::Terminate),
            result = tokio::signal::ctrl_c() => {
                result
                    .context("failed to install Ctrl-C handler")
                    .map(|()| ShutdownSignal::Interrupt)
            },
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to install Ctrl-C handler")
            .map(|()| ShutdownSignal::Interrupt)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test]
    async fn signal_cancels_and_waits_for_service() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let service_cancelled = Arc::clone(&cancelled);

        run_with_shutdown_signal(
            "test-service",
            move |shutdown| async move {
                shutdown.cancelled().await;
                service_cancelled.store(true, Ordering::Relaxed);
                Ok(())
            },
            std::future::ready(Ok(ShutdownSignal::Interrupt)),
        )
        .await
        .expect("clean shutdown should succeed");

        assert!(cancelled.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn signal_handler_error_is_propagated() {
        let err = run_with_shutdown_signal(
            "test-service",
            |shutdown| async move {
                shutdown.cancelled().await;
                Ok(())
            },
            std::future::ready(Err(anyhow::anyhow!("signal handler failed"))),
        )
        .await
        .expect_err("signal error should be returned");

        assert_eq!(err.to_string(), "signal handler failed");
    }
}
