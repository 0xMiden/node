use std::collections::{BTreeMap, BTreeSet};

use miden_node_db::sqlite::InList;
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};
use miden_protocol::block::{BlockNoteIndex, BlockNumber};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{NoteId, NoteInclusionProof};

use super::ReadTransaction;
use crate::errors::DatabaseError;

const SQL: &str = include_str!("query.sql");

impl ReadTransaction<'_> {
    /// Returns inclusion proofs for the requested notes committed at or before `up_to_block`.
    ///
    /// Notes that are absent or committed after `up_to_block` are omitted from the result.
    pub fn select_note_inclusion_proofs(
        &self,
        note_ids: &BTreeSet<NoteId>,
        up_to_block: BlockNumber,
    ) -> Result<BTreeMap<NoteId, NoteInclusionProof>, DatabaseError> {
        QueryParamNoteCommitmentLimit::check(note_ids.len())?;

        let note_commitments = InList::from_values(note_ids.iter().map(NoteId::as_word));

        let rows = self.inner.query(SQL, &[&note_commitments, &up_to_block], |row| {
            Ok((
                row.get::<BlockNumber>(0)?,
                row.get::<NoteId>(1)?,
                row.get::<u32>(2)? as usize,
                row.get::<u32>(3)? as usize,
                row.get::<SparseMerklePath>(4)?,
            ))
        })?;

        rows.into_iter()
            .map(|(block_num, note_id, batch_index, note_index, merkle_path)| {
                let node_index_in_block = BlockNoteIndex::new(batch_index, note_index)
                    .expect("batch and note index from DB should be valid")
                    .leaf_index_value();
                let proof = NoteInclusionProof::new(block_num, node_index_in_block, merkle_path)?;
                Ok((note_id, proof))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
