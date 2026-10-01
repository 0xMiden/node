use std::future::Future;

use clap::Parser;
mod commands;

// MAIN
// ================================================================================================

fn main() -> anyhow::Result<()> {
    let command = commands::ValidatorCommand::parse();
    run_with_runtime(async move {
        let _otel_guard = miden_node_tracing::setup_tracing(command.open_telemetry())?;
        miden_node_utils::shutdown::run_with_shutdown("miden-validator", |shutdown| {
            command.handle(shutdown)
        })
        .await
    })
}

fn run_with_runtime(task: impl Future<Output = anyhow::Result<()>>) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(task);
    runtime.shutdown_background();
    result
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use miden_node_tracing::spawn::spawn_blocking_in_current_span;

    use super::*;

    #[test]
    fn runtime_exit_does_not_wait_for_blocking_work() -> anyhow::Result<()> {
        const CHILD: &str = "MIDEN_VALIDATOR_TEST_BLOCKING_EXIT";
        if std::env::var_os(CHILD).is_some() {
            return run_with_runtime(async {
                let (started, ready) = tokio::sync::oneshot::channel();
                spawn_blocking_in_current_span(move || {
                    let _ = started.send(());
                    std::thread::sleep(Duration::from_secs(20));
                });
                ready.await?;
                tokio::time::sleep(Duration::from_millis(500)).await;
                Ok(())
            });
        }

        let started = Instant::now();
        let output = Command::new(std::env::current_exe()?)
            .args(["--exact", "tests::runtime_exit_does_not_wait_for_blocking_work"])
            .env(CHILD, "1")
            .output()?;
        anyhow::ensure!(output.status.success(), "child process failed: {output:?}");
        anyhow::ensure!(started.elapsed() < Duration::from_secs(5), "child process did not exit");
        Ok(())
    }
}
