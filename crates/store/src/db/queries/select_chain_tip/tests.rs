use miden_protocol::block::{BlockHeader, BlockSignatures};

use super::select_chain_tip;
use crate::db::{TestDb, queries};

#[test]
fn empty_database_has_no_tip() {
    let db = TestDb::new();
    assert_eq!(db.read(select_chain_tip).unwrap(), None);
}

#[test]
fn returns_the_header_with_the_highest_block_number() {
    let db = TestDb::new();
    let first = BlockHeader::mock(0, None, None, &[]);
    let latest = BlockHeader::mock(1, None, None, &[]);
    let expected = latest.clone();
    db.write(move |tx| -> Result<(), crate::DatabaseError> {
        let signatures = BlockSignatures::new(vec![]).unwrap();
        queries::insert_block_header(tx, &first, &signatures)?;
        queries::insert_block_header(tx, &latest, &signatures)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(db.read(select_chain_tip).unwrap(), Some(expected));
}
