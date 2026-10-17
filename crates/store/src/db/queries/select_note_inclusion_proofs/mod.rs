//! Returns inclusion proofs for a set of notes.

use std::collections::{BTreeMap, BTreeSet};

use miden_node_db::sqlite::{InList, ReadTx};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};
use miden_protocol::Word;
use miden_protocol::block::{BlockNoteIndex, BlockNumber};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{NoteId, NoteInclusionProof};

use crate::errors::DatabaseError;

const SQL: &str = include_str!("select_note_inclusion_proofs.sql");

/// Select note inclusion proofs matching the note commitments, restricted to notes committed at
/// or before `up_to_block`.
///
/// # Parameters
/// * `note_commitments`: Set of note commitments to query
///     - Limit: 0 <= count <= 1000
/// * `up_to_block`: Only notes committed at or before this block are returned
///
/// # Returns
///
/// - Empty map if no matching `note`.
/// - Otherwise, note inclusion proofs keyed by [`NoteId`].
pub(crate) fn select_note_inclusion_proofs(
    tx: &ReadTx<'_>,
    note_commitments: &BTreeSet<Word>,
    up_to_block: BlockNumber,
) -> Result<BTreeMap<NoteId, NoteInclusionProof>, DatabaseError> {
    QueryParamNoteCommitmentLimit::check(note_commitments.len())?;

    let note_commitments = InList::from_values(note_commitments);

    let rows = tx.query(SQL, &[&note_commitments, &up_to_block], |row| {
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
