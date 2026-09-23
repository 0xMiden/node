use std::collections::HashMap;
use std::future::Future;

use anyhow::Context;
use miden_node_tracing::warn;
use tokio::task::{Id, JoinError, JoinSet};

use crate::shutdown::CancellationToken;

/// A named task set for supervising concurrently-running Tokio tasks.
///
/// Dropping a task set aborts all tasks that are still running.
pub struct Tasks {
    handles: JoinSet<anyhow::Result<()>>,
    names: HashMap<Id, String>,
}

impl Default for Tasks {
    fn default() -> Self {
        Self {
            handles: JoinSet::new(),
            names: HashMap::new(),
        }
    }
}

impl Tasks {
    /// Creates an empty task set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns a named task into the set.
    pub fn spawn(
        &mut self,
        name: impl Into<String>,
        task: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> Id {
        let id = self.handles.spawn(task).id();
        self.names.insert(id, name.into());
        id
    }

    /// Spawns a named task that does not return an error.
    pub fn spawn_infallible(
        &mut self,
        name: impl Into<String>,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Id {
        self.spawn(name, async move {
            task.await;
            Ok(())
        })
    }

    /// Waits for the next task to complete.
    pub async fn join_next(&mut self) -> Option<(String, Result<anyhow::Result<()>, JoinError>)> {
        let result = self.handles.join_next_with_id().await?;
        let id = match &result {
            Ok((id, _)) => *id,
            Err(err) => err.id(),
        };
        let name = self.names.remove(&id).unwrap_or_else(|| "unknown".to_string());
        let result = result.map(|(_, output)| output);

        Some((name, result))
    }

    /// Returns `true` if no tasks are currently in the set.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Returns the number of tasks currently in the set.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Waits for the next task to complete, treating that completion as an error.
    ///
    /// This is intended for supervised task sets where every task is expected to run indefinitely.
    pub async fn join_next_as_error(&mut self) -> anyhow::Result<()> {
        let Some((task, result)) = self.join_next().await else {
            anyhow::bail!("task set is empty");
        };

        Self::unexpected_completion(&task, result)
    }

    /// Waits for either an unexpected task completion or a shutdown request.
    ///
    /// Before shutdown, any task completion is treated as fatal because this type supervises
    /// long-running tasks. Such a completion triggers the shutdown itself: the token is cancelled
    /// and the remaining tasks are drained before the error is returned. Returning without
    /// draining would drop the set and abort the surviving tasks mid-work — e.g. the store's
    /// block writer between its database commit and tree update, tearing persistent state.
    ///
    /// Once `token` is cancelled (whether externally or by a failure here), clean task exits are
    /// accepted and this method waits for all tracked tasks to finish. The first failure observed
    /// is returned as the root cause; subsequent failures are logged, since they are often
    /// knock-on effects of the first.
    pub async fn join_next_or_cancelled(&mut self, token: CancellationToken) -> anyhow::Result<()> {
        let mut outcome = Ok(());
        while !token.is_cancelled() {
            tokio::select! {
                biased;
                () = token.cancelled() => break,
                result = self.join_next() => {
                    let Some((task, result)) = result else {
                        anyhow::bail!("task set is empty");
                    };
                    outcome = Self::unexpected_completion(&task, result);
                    // Shut the remaining tasks down and fall through to the drain below.
                    token.cancel();
                },
            }
        }

        while let Some((task, result)) = self.join_next().await {
            match (&outcome, Self::shutdown_completion(&task, result)) {
                // No failure so far: this task's result (clean or failed) becomes the outcome.
                (Ok(()), result) => outcome = result,
                // A failure is already recorded as the root cause; later failures are often
                // knock-on effects of it, so log them rather than mask it.
                (Err(_), Err(err)) => {
                    warn!(&err, "task failed during shutdown", task.name = task);
                },
                // A failure is already recorded and this task exited cleanly: nothing to add.
                (Err(_), Ok(())) => {},
            }
        }

        outcome
    }

    /// Interprets a task completion observed *before* shutdown was requested.
    ///
    /// Supervised tasks are expected to run until shutdown, so every completion — even a clean
    /// exit — is an error here; the variants only differ in how much context the error carries
    /// (task failure, or a panicked/aborted task surfacing as a [`JoinError`]).
    fn unexpected_completion(
        task: &str,
        result: Result<anyhow::Result<()>, JoinError>,
    ) -> anyhow::Result<()> {
        match result {
            Ok(Ok(())) => anyhow::bail!("task {task} completed unexpectedly"),
            Ok(Err(err)) => Err(err).with_context(|| format!("task {task} failed")),
            Err(err) => Err(err).with_context(|| format!("task {task} failed to join")),
        }
    }

    /// Interprets a task completion observed *after* shutdown was requested.
    ///
    /// During shutdown a clean exit is the expected outcome, and a cancelled task is also fine —
    /// abort is how a dropped set winds tasks down. A task error or a panic (a non-cancellation
    /// [`JoinError`]) is still a failure worth reporting.
    fn shutdown_completion(
        task: &str,
        result: Result<anyhow::Result<()>, JoinError>,
    ) -> anyhow::Result<()> {
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err).with_context(|| format!("task {task} failed during shutdown")),
            Err(err) if err.is_cancelled() => Ok(()),
            Err(err) => Err(err).with_context(|| format!("task {task} failed to join")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn join_next_or_cancelled_accepts_clean_task_completion_after_cancellation() {
        let token = crate::shutdown::CancellationToken::new();
        let mut tasks = Tasks::new();
        tasks.spawn("worker", {
            let token = token.clone();
            async move {
                token.cancelled().await;
                Ok(())
            }
        });

        token.cancel();

        tasks
            .join_next_or_cancelled(token)
            .await
            .expect("clean shutdown should not be treated as an error");
    }

    #[tokio::test]
    async fn join_next_or_cancelled_treats_task_completion_before_cancellation_as_error() {
        let token = crate::shutdown::CancellationToken::new();
        let mut tasks = Tasks::new();
        tasks.spawn("worker", async { Ok(()) });

        let err = tasks
            .join_next_or_cancelled(token)
            .await
            .expect_err("unexpected task completion should fail before shutdown");

        assert_eq!(err.to_string(), "task worker completed unexpectedly");
    }

    #[tokio::test]
    async fn join_next_or_cancelled_drains_remaining_tasks_after_a_failure() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let token = crate::shutdown::CancellationToken::new();
        let mut tasks = Tasks::new();
        let survivor_finished = Arc::new(AtomicBool::new(false));

        tasks.spawn("failing", async { anyhow::bail!("boom") });
        tasks.spawn("survivor", {
            let token = token.clone();
            let finished = Arc::clone(&survivor_finished);
            async move {
                token.cancelled().await;
                // Work past the cancellation point: an aborted task would never get here.
                tokio::time::sleep(Duration::from_millis(10)).await;
                finished.store(true, Ordering::Relaxed);
                Ok(())
            }
        });

        let err = tasks
            .join_next_or_cancelled(token.clone())
            .await
            .expect_err("the failing task's error should be returned");

        assert_eq!(err.to_string(), "task failing failed");
        assert!(token.is_cancelled(), "a task failure should trigger shutdown");
        assert!(tasks.is_empty(), "all tasks should be drained before returning");
        assert!(
            survivor_finished.load(Ordering::Relaxed),
            "surviving tasks should shut down gracefully, not be aborted",
        );
    }

    #[tokio::test]
    async fn join_next_or_cancelled_drains_past_failures_during_shutdown() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let token = crate::shutdown::CancellationToken::new();
        let mut tasks = Tasks::new();
        let survivor_finished = Arc::new(AtomicBool::new(false));

        tasks.spawn("failing", {
            let token = token.clone();
            async move {
                token.cancelled().await;
                anyhow::bail!("boom")
            }
        });
        tasks.spawn("survivor", {
            let token = token.clone();
            let finished = Arc::clone(&survivor_finished);
            async move {
                token.cancelled().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
                finished.store(true, Ordering::Relaxed);
                Ok(())
            }
        });

        token.cancel();

        let err = tasks
            .join_next_or_cancelled(token)
            .await
            .expect_err("a failure during shutdown should be reported");

        assert_eq!(err.to_string(), "task failing failed during shutdown");
        assert!(tasks.is_empty(), "draining should continue past the failed task");
        assert!(
            survivor_finished.load(Ordering::Relaxed),
            "surviving tasks should shut down gracefully, not be aborted",
        );
    }

    #[tokio::test]
    async fn join_next_or_cancelled_waits_for_all_tasks_to_complete_after_cancellation() {
        let token = crate::shutdown::CancellationToken::new();
        let mut tasks = Tasks::new();
        tasks.spawn("worker-a", {
            let token = token.clone();
            async move {
                token.cancelled().await;
                Ok(())
            }
        });
        tasks.spawn("worker-b", {
            let token = token.clone();
            async move {
                token.cancelled().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            }
        });

        token.cancel();

        tasks
            .join_next_or_cancelled(token)
            .await
            .expect("shutdown should wait for all clean task exits");
        assert!(tasks.is_empty());
    }
}
