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

#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use miden_node_tracing::spawn::spawn_blocking_in_current_span;

    use super::*;

    #[test]
    fn shutdown_signal_exits_with_blocking_work() -> anyhow::Result<()> {
        const READY_PATH: &str = "MIDEN_VALIDATOR_TEST_READY_PATH";
        if let Some(ready_path) = std::env::var_os(READY_PATH) {
            return run_with_runtime(async {
                miden_node_utils::shutdown::run_with_shutdown(
                    "test validator",
                    |shutdown| async move {
                        let (started, ready) = tokio::sync::oneshot::channel();
                        spawn_blocking_in_current_span(move || {
                            let _ = started.send(());
                            std::thread::sleep(Duration::from_secs(20));
                        });
                        ready.await?;
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        fs_err::write(ready_path, b"ready")?;
                        shutdown.cancelled().await;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        Ok(())
                    },
                )
                .await
            });
        }

        let root = tempfile::tempdir()?;
        let ready_path = root.path().join("ready");
        let started = Instant::now();
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", "tests::shutdown_signal_exits_with_blocking_work"])
            .env(READY_PATH, &ready_path)
            .spawn()?;
        while !ready_path.exists() {
            if started.elapsed() >= Duration::from_secs(5) {
                child.kill()?;
                child.wait()?;
                anyhow::bail!("child process did not start the service");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        anyhow::ensure!(
            Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status()?
                .success(),
            "failed to signal child process"
        );
        loop {
            if let Some(status) = child.try_wait()? {
                anyhow::ensure!(status.success(), "child process failed: {status}");
                break;
            }
            if started.elapsed() >= Duration::from_secs(5) {
                child.kill()?;
                child.wait()?;
                anyhow::bail!("child process did not exit within one shutdown window");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}
