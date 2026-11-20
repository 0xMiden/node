use miden_node_utils::limiter::{QueryParamBlockLimit, QueryParamLimiter};
use miden_protocol::block::{BlockHeader, BlockNumber, BlockSignatures};

use super::ReadTransaction;
use crate::DatabaseError;
use crate::db::{TestDb, queries};

#[test]
fn returns_stored_headers_in_block_order_and_omits_missing_blocks() {
    let db = TestDb::new();
    let headers = [0u32, 1, 2].map(|number| BlockHeader::mock(number, None, None, &[]));
    let expected = [headers[0].clone(), headers[2].clone()];
    db.write(move |tx| -> Result<(), DatabaseError> {
        for header in &headers {
            queries::insert_block_header(tx, header, &BlockSignatures::new(vec![]).unwrap())?;
        }
        Ok(())
    })
    .unwrap();
    db.read(move |tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        let blocks = [2u32, 5, 0].map(BlockNumber::from);
        assert_eq!(tx.select_block_headers(blocks.into_iter())?, expected);
        Ok(())
    })
    .unwrap();
}

#[test]
fn rejects_block_lists_above_the_query_limit() {
    let db = TestDb::new();
    db.read(|tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        let limit = u32::try_from(QueryParamBlockLimit::LIMIT).unwrap();
        let blocks = (0..=limit).map(BlockNumber::from);
        assert!(matches!(
            tx.select_block_headers(blocks),
            Err(DatabaseError::QueryParamLimit(_))
        ));
        Ok(())
    })
    .unwrap();
}
