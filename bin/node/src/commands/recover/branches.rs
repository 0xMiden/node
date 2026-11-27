//! Selects the highest reachable chain from successive levels of verified candidates.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

use anyhow::Context;
use miden_node_proto::prost::Message;
use miden_node_store::{BlockWriter, State};
use miden_protocol::Word;
use tempfile::TempDir;

use super::{BlockSubscriptionResponse, RecoveredBlock, decode_entry};

pub(super) enum SelectedBlock {
    Direct(Box<RecoveredBlock>),
    Staged(PathBuf),
}

impl SelectedBlock {
    pub(super) async fn apply(self, state: &State, writer: &mut BlockWriter) -> anyhow::Result<()> {
        let staged = matches!(self, Self::Staged(_));
        let recovered = self.load().await?;
        if staged {
            let (parent, _) =
                state.view().get_block_header(Some(state.committed_tip()), false).await?;
            recovered.block.validate(Some(&parent.context("missing recovery parent")?))?;
        }
        super::inputs::apply_recovered(state, writer, recovered).await
    }

    pub(super) async fn load(self) -> anyhow::Result<RecoveredBlock> {
        match self {
            Self::Direct(block) => Ok(*block),
            Self::Staged(path) => {
                let bytes = tokio::fs::read(&path).await?;
                let event = BlockSubscriptionResponse::decode(bytes.as_slice())?;
                let block = decode_entry(event, None)?;
                anyhow::ensure!(
                    path.file_name().and_then(|name| name.to_str())
                        == Some(&block.block.header().commitment().to_hex()),
                    "staged block commitment mismatch"
                );
                tokio::fs::remove_file(path).await?;
                Ok(block)
            },
        }
    }
}

struct Branch {
    parent: Word,
    children: usize,
    path: PathBuf,
}

/// Keeps one level of metadata per unresolved height. Payloads stay on disk until selected.
#[derive(Default)]
pub(super) struct Branches {
    levels: VecDeque<BTreeMap<Word, Branch>>,
    directory: Option<TempDir>,
}

impl Branches {
    /// Advances by one fully accounted height and releases the prefix common to all survivors.
    pub(super) async fn advance(
        &mut self,
        mut candidates: Vec<RecoveredBlock>,
    ) -> anyhow::Result<Vec<SelectedBlock>> {
        anyhow::ensure!(!candidates.is_empty(), "cannot advance without a candidate");
        if self.levels.is_empty() && candidates.len() == 1 {
            return Ok(vec![SelectedBlock::Direct(Box::new(candidates.pop().unwrap()))]);
        }
        let mut level = BTreeMap::new();
        let mut parents = BTreeSet::new();
        for candidate in candidates {
            let header = candidate.block.header();
            let id = header.commitment();
            let parent = header.prev_block_commitment();
            parents.insert(parent);
            if let Some(previous) = self.levels.back_mut() {
                previous.get_mut(&parent).context("missing staged parent")?.children += 1;
            }
            if self.directory.is_none() {
                self.directory = Some(tempfile::tempdir()?);
            }
            let path = self.directory.as_ref().unwrap().path().join(id.to_hex());
            let event = BlockSubscriptionResponse {
                committed_chain_tip: header.block_num().as_u32(),
                block: Some(candidate.block.into()),
                protocol_config: candidate.protocol_config.as_ref().map(Into::into),
                proving_inputs: candidate.proving_inputs.as_ref().map(Into::into),
            };
            tokio::fs::write(&path, event.encode_to_vec()).await?;
            level.insert(id, Branch { parent, children: 0, path });
        }
        self.keep_tips(&parents).await?;
        self.levels.push_back(level);
        Ok(self.release_common())
    }

    /// Breaks ties at the deepest reachable height by ascending commitment.
    pub(super) async fn finish(&mut self) -> anyhow::Result<Vec<SelectedBlock>> {
        if let Some(id) = self.levels.back().and_then(|tips| tips.keys().next()).copied() {
            self.keep_tips(&BTreeSet::from([id])).await?;
        }
        Ok(self.release_common())
    }

    async fn keep_tips(&mut self, keep: &BTreeSet<Word>) -> anyhow::Result<()> {
        let Some(last) = self.levels.len().checked_sub(1) else {
            return Ok(());
        };
        let dead: Vec<_> =
            self.levels[last].keys().filter(|id| !keep.contains(id)).copied().collect();
        for mut id in dead {
            for index in (0..=last).rev() {
                let node = self.levels[index].remove(&id).context("missing staged branch")?;
                tokio::fs::remove_file(node.path).await?;
                if index == 0 {
                    break;
                }
                id = node.parent;
                let parent =
                    self.levels[index - 1].get_mut(&id).context("missing staged ancestor")?;
                parent.children -= 1;
                if parent.children != 0 {
                    break;
                }
            }
        }
        Ok(())
    }

    fn release_common(&mut self) -> Vec<SelectedBlock> {
        let mut selected = Vec::new();
        while self.levels.front().is_some_and(|level| level.len() == 1) {
            let (_, node) = self.levels.pop_front().unwrap().pop_first().unwrap();
            selected.push(SelectedBlock::Staged(node.path));
        }
        selected
    }
}
