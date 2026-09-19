use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::core::{ArtifactSlot, BoardCore, PublishAction, SlotValues, validate_artifact_length};

#[derive(Clone)]
pub(super) struct BoardNode {
    inner: Arc<Inner>,
}

struct Inner {
    core: BoardCore,
    changed: tokio::sync::Notify,
    values: tokio::sync::Mutex<BTreeMap<String, Vec<Vec<u8>>>>,
}

pub(super) fn create(participant_count: usize) -> anyhow::Result<Vec<BoardNode>> {
    let inner = Arc::new(Inner {
        core: BoardCore::new(participant_count)?,
        changed: tokio::sync::Notify::new(),
        values: tokio::sync::Mutex::new(BTreeMap::new()),
    });
    Ok((0..=participant_count).map(|_| BoardNode { inner: inner.clone() }).collect())
}

impl BoardNode {
    pub(super) async fn publish(&self, slot: &ArtifactSlot, value: &[u8]) -> anyhow::Result<()> {
        validate_artifact_length(value.len())?;
        self.inner.core.validate_slot(slot)?;
        let mut state = self.inner.values.lock().await;
        let values = state.entry(slot.prefix()).or_default();
        match SlotValues::from_values(values.iter().cloned()).publish(&value.to_vec())? {
            PublishAction::AlreadyPresent => return Ok(()),
            PublishAction::Insert => values.push(value.to_vec()),
        }
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(())
    }

    pub(super) async fn read_unique(&self, slot: &ArtifactSlot) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner.core.validate_slot(slot)?;
        let state = self.inner.values.lock().await;
        let values = state.get(&slot.prefix()).cloned().unwrap_or_default();
        SlotValues::from_values(values).into_unique(slot)
    }

    pub(super) async fn wait_unique(
        &self,
        slot: &ArtifactSlot,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        tokio::time::timeout(timeout, async {
            loop {
                let changed = self.inner.changed.notified();
                if let Some(value) = self.read_unique(slot).await? {
                    return Ok(value);
                }
                changed.await;
            }
        })
        .await
        .map_err(Into::into)
        .and_then(|result| result)
    }
}
