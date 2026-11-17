use std::time::Duration;

use miden_node_tracing::instrument;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::domain::batch::SelectedBatch;
use crate::errors::BuildBatchError;
use crate::mempool::SharedMempool;

#[cfg(test)]
mod tests;

/// Selects batches when mempool changes make work available.
///
/// A pending partial batch keeps its deadline across notifications and worker completions. An
/// unsuccessful partial selection waits for a state change before another attempt is scheduled.
pub(super) struct BatchScheduler {
    mempool: SharedMempool,
    updates: watch::Receiver<usize>,
    batch_interval: Duration,
    partial_deadline: Option<Instant>,
}

impl BatchScheduler {
    pub(super) fn new(
        mempool: SharedMempool,
        batch_interval: Duration,
    ) -> Result<Self, BuildBatchError> {
        let updates = mempool.subscribe().map_err(BuildBatchError::MempoolPoisoned)?;
        Ok(Self {
            mempool,
            updates,
            batch_interval: batch_interval.max(Duration::from_millis(50)),
            partial_deadline: None,
        })
    }

    /// Waits for a full batch or the deadline for a partial batch.
    ///
    /// While workers are busy, notifications still establish the partial-batch deadline, but no
    /// transactions are selected. Dropping this future preserves the deadline for the next worker.
    pub(super) async fn next_batch(
        &mut self,
        worker_available: bool,
    ) -> Result<SelectedBatch, BuildBatchError> {
        loop {
            let has_transactions = *self.updates.borrow_and_update() > 0;
            if !has_transactions {
                self.partial_deadline = None;
                self.wait_for_change().await;
                continue;
            }

            let deadline = *self
                .partial_deadline
                .get_or_insert_with(|| Instant::now() + self.batch_interval);
            if !worker_available {
                self.wait_for_change().await;
                continue;
            }

            if let Some(batch) = self.select_full_batch()? {
                self.partial_deadline = None;
                return Ok(batch);
            }

            tokio::select! {
                () = self.wait_for_change() => {},
                () = tokio::time::sleep_until(deadline) => {
                    let has_transactions = *self.updates.borrow_and_update() > 0;
                    self.partial_deadline = None;
                    if !has_transactions {
                        continue;
                    }
                    if let Some(batch) = self.select_any_batch()? {
                        return Ok(batch);
                    }
                    self.wait_for_change().await;
                },
            }
        }
    }

    async fn wait_for_change(&mut self) {
        self.updates.changed().await.expect("scheduler retains the mempool's sender");
    }

    #[instrument(name = "select_full_batch")]
    fn select_full_batch(&self) -> Result<Option<SelectedBatch>, BuildBatchError> {
        Ok(self
            .mempool
            .lock()
            .map_err(BuildBatchError::MempoolPoisoned)?
            .select_full_batch())
    }

    #[instrument(name = "select_any_batch")]
    fn select_any_batch(&self) -> Result<Option<SelectedBatch>, BuildBatchError> {
        Ok(self
            .mempool
            .lock()
            .map_err(BuildBatchError::MempoolPoisoned)?
            .select_any_batch())
    }
}
