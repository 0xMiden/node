use std::collections::HashMap;
use std::future::Future;

use tokio::task::{Id, JoinError, JoinSet};

/// Result of a completed named task.
pub struct TaskResult<T> {
    /// Human-readable task name supplied when the task was spawned.
    pub name: String,
    /// Task output, or a join error if the task panicked or was cancelled.
    pub result: Result<T, JoinError>,
}

/// A named task set for supervising concurrently-running Tokio tasks.
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
    pub async fn join_next(&mut self) -> Option<TaskResult<T>> {
        let result = self.handles.join_next_with_id().await?;
        let id = match &result {
            Ok((id, _)) => *id,
            Err(err) => err.id(),
        };
        let name = self.names.remove(&id).unwrap_or_else(|| "unknown".to_string());
        let result = result.map(|(_, output)| output);

        Some(TaskResult { name, result })
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
