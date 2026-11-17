use std::collections::{BTreeMap, BTreeSet};

use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, NoteInclusionProof};

use super::ReadTransaction;
use crate::DatabaseError;

impl ReadTransaction<'_> {
    /// Returns inclusion proofs for the requested notes committed at or before `up_to_block`.
    ///
    /// Notes that are absent or committed after `up_to_block` are omitted from the result.
    pub fn select_note_inclusion_proofs(
        &self,
        note_ids: &BTreeSet<NoteId>,
        up_to_block: BlockNumber,
    ) -> Result<BTreeMap<NoteId, NoteInclusionProof>, DatabaseError> {
        let note_commitments = note_ids.iter().map(NoteId::as_word).collect();
        crate::db::queries::select_note_inclusion_proofs(self.inner, &note_commitments, up_to_block)
    }
}
