use miden_protocol::account::{
    AccountHeader,
    AccountId,
    AccountIdVersion,
    AccountStorageHeader,
    AccountType,
    AssetCallbackFlag,
    StorageSlotHeader,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::{Felt, Word};

use super::ReadTransaction;
use crate::DatabaseError;
use crate::db::TestDb;

fn account_id(seed: u8, account_type: AccountType) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        account_type,
        AssetCallbackFlag::Disabled,
    )
}

/// Stores `header` as the state of its account from `block_num` on, or a private account row if
/// `header` is `None`.
fn insert_account_row(
    db: &TestDb,
    account_id: AccountId,
    block_num: BlockNumber,
    header: Option<(AccountHeader, AccountStorageHeader)>,
) {
    db.write(move |tx| -> Result<usize, DatabaseError> {
        let commitment = header.as_ref().map_or(Word::empty(), |(header, _)| header.to_commitment());
        Ok(tx.execute(
            "INSERT INTO accounts (account_id, network_account_type, block_num, account_commitment, \
             code_commitment, nonce, storage_header, vault_root, created_at_block) \
             VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, ?2)",
            &[
                &account_id,
                &block_num,
                &commitment,
                &header.as_ref().map(|(header, _)| header.code_commitment()),
                &header.as_ref().map(|(header, _)| header.nonce()),
                &header.as_ref().map(|(_, storage)| storage.clone()),
                &header.as_ref().map(|(header, _)| header.vault_root()),
            ],
        )?)
    })
    .unwrap();
}

fn public_state(account_id: AccountId, nonce: u32) -> (AccountHeader, AccountStorageHeader) {
    let storage = AccountStorageHeader::new(vec![StorageSlotHeader::new(
        StorageSlotName::new("test::slot").unwrap(),
        StorageSlotType::Value,
        Word::from([nonce, 0, 0, 0]),
    )])
    .unwrap();
    let header = AccountHeader::new(
        account_id,
        Felt::from(nonce),
        Word::from([0, nonce, 0, 0]),
        storage.to_commitment(),
        Word::from([0, 0, nonce, 0]),
    );
    (header, storage)
}

#[test]
fn returns_the_state_in_force_at_the_block() {
    let db = TestDb::new();
    let id = account_id(1, AccountType::Public);
    let first = public_state(id, 1);
    let second = public_state(id, 2);
    insert_account_row(&db, id, 1.into(), Some(first.clone()));
    insert_account_row(&db, id, 3.into(), Some(second.clone()));

    db.read(move |tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        assert_eq!(tx.select_account_header_with_storage_header(id, 0.into())?, None);
        for (block, expected) in [(1, &first), (2, &first), (3, &second), (4, &second)] {
            assert_eq!(
                tx.select_account_header_with_storage_header(id, block.into())?.as_ref(),
                Some(expected),
            );
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn returns_an_empty_header_for_a_private_account() {
    let db = TestDb::new();
    let id = account_id(2, AccountType::Private);
    insert_account_row(&db, id, 1.into(), None);

    db.read(move |tx| -> Result<(), DatabaseError> {
        let tx = ReadTransaction::new(tx);
        let (header, storage) = tx
            .select_account_header_with_storage_header(id, 1.into())?
            .expect("the private account exists at block 1");
        assert_eq!(header.nonce(), Felt::ZERO);
        assert_eq!(header.code_commitment(), Word::default());
        assert_eq!(header.vault_root(), Word::default());
        assert_eq!(storage, AccountStorageHeader::new(Vec::new()).unwrap());
        Ok(())
    })
    .unwrap();
}
