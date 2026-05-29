use std::collections::HashMap;
use std::future::Future;

use anyhow::Context;
use tokio::task::{Id, JoinError, JoinSet};

/// A named task set for supervising concurrently-running Tokio tasks.
///
/// Dropping a task set aborts all tasks that are still running. Use [`Self::abort_all`] when the
/// tasks should be cancelled before the task set itself is dropped.
pub struct Tasks<T> {
    handles: JoinSet<T>,
    names: HashMap<Id, String>,
}

impl<T> Default for Tasks<T> {
    fn default() -> Self {
        Self {
            handles: JoinSet::new(),
            names: HashMap::new(),
        }
    }
}

impl<T: Send + 'static> Tasks<T> {
    /// Creates an empty task set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns a named task into the set.
    pub fn spawn(
        &mut self,
        name: impl Into<String>,
        task: impl Future<Output = T> + Send + 'static,
    ) -> Id {
        let id = self.handles.spawn(task).id();
        self.names.insert(id, name.into());
        id
    }

    /// Waits for the next task to complete.
    pub async fn join_next(&mut self) -> Option<(String, Result<T, JoinError>)> {
        let result = self.handles.join_next_with_id().await?;
        let id = match &result {
            Ok((id, _)) => *id,
            Err(err) => err.id(),
        };
        let name = self.names.remove(&id).unwrap_or_else(|| "unknown".to_string());
        let result = result.map(|(_, output)| output);

        Some((name, result))
    }

    /// Aborts all tasks still running in the set.
    pub fn abort_all(&mut self) {
        self.handles.abort_all();
    }

    /// Returns `true` if no tasks are currently in the set.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Returns the number of tasks currently in the set.
    pub fn len(&self) -> usize {
        self.handles.len()
    }
}

impl Tasks<anyhow::Result<()>> {
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
