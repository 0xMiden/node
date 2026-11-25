use miden_protocol::block::{BlockHeader, BlockNumber, BlockSignatures};

use super::ReadTransaction;
use crate::DatabaseError;
use crate::db::{TestDb, queries};

#[test]
fn reads_existing_headers_and_returns_none_for_missing_blocks() {
    let db = TestDb::new();
    let header = BlockHeader::mock(0, None, None, &[]);
    let expected = header.clone();
    db.write(move |tx| {
        queries::insert_block_header(tx, &header, &BlockSignatures::new(vec![]).unwrap())
    })
    .unwrap();
    db.read(move |tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        assert_eq!(tx.select_block_header(BlockNumber::GENESIS)?, Some(expected));
        assert_eq!(tx.select_block_header(1.into())?, None);
        Ok(())
    })
    .unwrap();
}

#[test]
fn missing_header_returns_none() {
    let db = TestDb::new();
    db.read(|tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        assert_eq!(tx.select_block_header(BlockNumber::GENESIS)?, None);
        Ok(())
    })
    .unwrap();
}
