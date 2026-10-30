use std::collections::HashSet;

use miden_protocol::Word;
use miden_protocol::block::{BlockHeader, BlockNoteIndex, BlockSignatures};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{Note, NoteId};

use super::ReadTransaction;
use crate::DatabaseError;
use crate::db::{NoteRecord, TestDb, queries};

#[test]
fn returns_only_requested_existing_notes_without_duplicates() {
    let db = TestDb::new();
    let notes = [1u32, 2, 3].map(|n| Note::mock_noop(Word::from([n, 0, 0, 0])));
    let ids = notes.each_ref().map(Note::id);
    db.write(move |tx| -> Result<(), DatabaseError> {
        for (note, number) in notes.into_iter().zip(1..=3) {
            let header = BlockHeader::mock(number, None, None, &[]);
            queries::insert_block_header(tx, &header, &BlockSignatures::new(vec![]).unwrap())?;
            let record = NoteRecord {
                block_num: number.into(),
                note_index: BlockNoteIndex::new(0, 0).unwrap(),
                note_id: note.id().as_word(),
                metadata: *note.metadata(),
                details: None,
                attachments: note.attachments().clone(),
                inclusion_path: SparseMerklePath::default(),
            };
            queries::insert_notes(tx, &[(record, None)])?;
        }
        Ok(())
    })
    .unwrap();
    db.read(move |tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        let missing = NoteId::from_raw(Word::from([4u32, 0, 0, 0]));
        assert_eq!(
            tx.select_existing_note_ids(&[ids[1], ids[2], missing, ids[1]])?,
            HashSet::from([ids[1], ids[2]])
        );
        assert!(tx.select_existing_note_ids(&[])?.is_empty());
        Ok(())
    })
    .unwrap();
}

#[test]
fn rejects_note_lists_above_the_query_limit() {
    use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};

    let db = TestDb::new();
    db.read(|tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        let note = NoteId::from_raw(Word::from([1u32, 0, 0, 0]));
        let ids = vec![note; QueryParamNoteCommitmentLimit::LIMIT + 1];
        assert!(matches!(
            tx.select_existing_note_ids(&ids),
            Err(DatabaseError::QueryParamLimit(_))
        ));
        Ok(())
    })
    .unwrap();
}
