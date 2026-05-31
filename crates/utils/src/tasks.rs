use std::collections::HashMap;
use std::future::Future;

use anyhow::Context;
use tokio::task::{Id, JoinError, JoinSet};

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

        match result {
            Ok(Ok(())) => anyhow::bail!("task {task} completed unexpectedly"),
            Ok(Err(err)) => Err(err).with_context(|| format!("task {task} failed")),
            Err(err) => Err(err).with_context(|| format!("task {task} failed to join")),
        }
    }
}
