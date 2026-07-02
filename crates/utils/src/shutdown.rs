use std::future::Future;
use std::time::Duration;

use anyhow::Context;
pub use tokio_util::sync::CancellationToken;

/// Time allowed for services to finish after a shutdown signal before the process exits.
pub const GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Runs a service future until it completes or a shutdown signal is received.
///
/// On `SIGTERM` or Ctrl-C, the provided root cancellation token is cancelled and the service future
/// is given [`GRACE_PERIOD`] to complete. If it does not, the process exits immediately so
/// blocking work cannot hold the Tokio runtime alive indefinitely.
pub async fn run_with_shutdown<F, Fut>(run: F) -> anyhow::Result<()>
where
    F: FnOnce(CancellationToken) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let token = CancellationToken::new();
    let service = run(token.clone());
    tokio::pin!(service);

    tokio::select! {
        result = &mut service => result,
        result = shutdown_signal() => {
            result?;
            tracing::info!("Shutdown signal received; cancelling service tasks");
            token.cancel();

            let Ok(result) = tokio::time::timeout(GRACE_PERIOD, &mut service).await else {
                tracing::error!(
                    grace_period = ?GRACE_PERIOD,
                    "Graceful shutdown timed out; exiting process",
                );
                std::process::exit(0);
            };

            result
        },
    }
}

/// Waits for SIGTERM or Ctrl-C.
pub async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("failed to install SIGTERM handler")?;

        tokio::select! {
            _ = terminate.recv() => Ok(()),
            result = tokio::signal::ctrl_c() => {
                result.context("failed to install Ctrl-C handler")
            },
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("failed to install Ctrl-C handler")
    }
}
