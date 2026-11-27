use miden_protocol::Word;
use miden_protocol::account::AccountCode;

use super::ReadTransaction;
use crate::DatabaseError;
use crate::db::TestDb;

#[test]
fn returns_the_code_stored_under_a_commitment() {
    let db = TestDb::new();
    let code = AccountCode::mock();
    let stored = code.clone();
    db.write(move |tx| -> Result<usize, DatabaseError> {
        Ok(tx.execute(
            "INSERT INTO account_codes (code_commitment, code) VALUES (?1, ?2)",
            &[&stored.commitment(), &stored],
        )?)
    })
    .unwrap();

    db.read(move |tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        assert_eq!(tx.select_account_code(code.commitment())?, Some(code));
        assert_eq!(tx.select_account_code(Word::empty())?, None);
        Ok(())
    })
    .unwrap();
}
