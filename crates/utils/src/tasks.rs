use std::collections::HashMap;
use std::future::Future;

use anyhow::Context;
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
    /// long-running tasks. Once `token` is cancelled, clean task exits are accepted and this method
    /// waits for all tracked tasks to finish.
    pub async fn join_next_or_cancelled(&mut self, token: CancellationToken) -> anyhow::Result<()> {
        while !token.is_cancelled() {
            tokio::select! {
                biased;
                () = token.cancelled() => break,
                result = self.join_next() => {
                    let Some((task, result)) = result else {
                        anyhow::bail!("task set is empty");
                    };
                    Self::unexpected_completion(&task, result)?;
                },
            }
        }

        while let Some((task, result)) = self.join_next().await {
            Self::shutdown_completion(&task, result)?;
        }

        Ok(())
    }

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
