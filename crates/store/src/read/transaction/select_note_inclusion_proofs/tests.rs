use std::collections::BTreeSet;

use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};
use miden_protocol::Word;
use miden_protocol::block::{BlockHeader, BlockNoteIndex, BlockNumber, BlockSignatures};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{Note, NoteId};

use super::ReadTransaction;
use crate::DatabaseError;
use crate::db::{NoteRecord, TestDb, queries};

#[test]
fn returns_proofs_of_requested_notes_committed_up_to_the_block() {
    let db = TestDb::new();
    let notes = [1u32, 2].map(|n| Note::mock_noop(Word::from([n, 0, 0, 0])));
    let ids = notes.each_ref().map(Note::id);
    db.write(move |tx| -> Result<(), DatabaseError> {
        for (note, number) in notes.into_iter().zip(1..=2) {
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
        let missing = NoteId::from_raw(Word::from([3u32, 0, 0, 0]));
        let requested = BTreeSet::from([ids[0], ids[1], missing]);

        let proofs = tx.select_note_inclusion_proofs(&requested, 1.into())?;
        assert_eq!(proofs.keys().copied().collect::<Vec<_>>(), [ids[0]]);
        assert_eq!(proofs[&ids[0]].location().block_num(), BlockNumber::from(1));

        let proofs = tx.select_note_inclusion_proofs(&requested, 2.into())?;
        assert_eq!(proofs.keys().copied().collect::<BTreeSet<_>>(), BTreeSet::from(ids));
        Ok(())
    })
    .unwrap();
}

#[test]
fn rejects_note_lists_above_the_query_limit() {
    let db = TestDb::new();
    db.read(|tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        let limit = u32::try_from(QueryParamNoteCommitmentLimit::LIMIT).unwrap();
        let ids = (0..=limit).map(|n| NoteId::from_raw(Word::from([n, 0, 0, 0]))).collect();
        assert!(matches!(
            tx.select_note_inclusion_proofs(&ids, BlockNumber::GENESIS),
            Err(DatabaseError::QueryParamLimit(_))
        ));
        Ok(())
    })
    .unwrap();
}
