use miden_protocol::block::{BlockHeader, BlockNumber, BlockSignatures};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;

use super::ReadTransaction;
use crate::DatabaseError;
use crate::db::{TestDb, queries};

#[test]
fn returns_the_requested_header_and_its_signatures() {
    let db = TestDb::new();
    let header = BlockHeader::mock(0, None, None, &[]);
    let signatures = BlockSignatures::sign(&[SigningKey::new()], header.commitment());
    let expected = (header.clone(), signatures.clone());
    db.write(move |tx| queries::insert_block_header(tx, &header, &signatures))
        .unwrap();

    db.read(move |tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        assert_eq!(tx.select_block_header_and_signatures(BlockNumber::GENESIS)?, Some(expected));
        assert_eq!(tx.select_block_header_and_signatures(1.into())?, None);
        Ok(())
    })
    .unwrap();
}
