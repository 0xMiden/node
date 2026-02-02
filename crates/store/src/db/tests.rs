#![allow(clippy::similar_names, reason = "naming dummy test values is hard")]
#![allow(clippy::too_many_lines, reason = "test code can be long")]

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use diesel::{Connection, SqliteConnection};
use miden_node_proto::domain::account::AccountSummary;
use miden_node_utils::fee::{test_fee, test_fee_params};
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountCode,
    AccountComponent,
    AccountDelta,
    AccountId,
    AccountIdVersion,
    AccountStorageDelta,
    AccountStorageMode,
    AccountType,
    AccountVaultDelta,
    StorageSlot,
    StorageSlotContent,
    StorageSlotDelta,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetVaultKey, FungibleAsset};
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockHeader,
    BlockNoteIndex,
    BlockNoteTree,
    BlockNumber,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::crypto::rand::RpoRandomCoin;
use miden_protocol::note::{
    Note,
    NoteAttachment,
    NoteDetails,
    NoteExecutionHint,
    NoteHeader,
    NoteId,
    NoteMetadata,
    NoteTag,
    NoteType,
    Nullifier,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use miden_protocol::testing::random_signer::RandomBlockSigner;
use miden_protocol::transaction::{
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    TransactionHeader,
    TransactionId,
};
use miden_protocol::utils::{Deserializable, Serializable};
use miden_protocol::{EMPTY_WORD, Felt, FieldElement, Word};
use miden_standards::account::auth::AuthFalcon512Rpo;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{NetworkAccountTarget, create_p2id_note};
use pretty_assertions::assert_eq;
use rand::Rng;

use super::{AccountInfo, NoteRecord, NullifierInfo};
use crate::db::TransactionSummary;
use crate::db::migrations::apply_migrations;
use crate::db::models::queries::{StorageMapValue, insert_account_storage_map_value};
use crate::db::models::{Page, queries, utils};
use crate::errors::DatabaseError;

fn create_db() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("In memory sqlite always works");
    apply_migrations(&mut conn).expect("Migrations always work on an empty database");
    conn
}

fn create_block(conn: &mut SqliteConnection, block_num: BlockNumber) {
    let block_header = BlockHeader::new(
        1_u8.into(),
        num_to_word(2),
        block_num,
        num_to_word(4),
        num_to_word(5),
        num_to_word(6),
        num_to_word(7),
        num_to_word(8),
        num_to_word(9),
        SecretKey::new().public_key(),
        test_fee_params(),
        11_u8.into(),
    );

    let dummy_signature = SecretKey::new().sign(block_header.commitment());
    conn.transaction(|conn| queries::insert_block_header(conn, &block_header, &dummy_signature))
        .unwrap();
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_insert_nullifiers_for_block() {
    let mut conn = create_db();
    let conn = &mut conn;
    let nullifiers = [num_to_nullifier(1 << 48)];

    let block_num = 1.into();
    create_block(conn, block_num);

    // Insert a new nullifier succeeds
    {
        conn.transaction(|conn| {
            let res = queries::insert_nullifiers_for_block(conn, &nullifiers, block_num);
            assert_eq!(res.unwrap(), nullifiers.len(), "There should be one entry");
            Ok::<_, DatabaseError>(())
        })
        .unwrap();
    }

    // Inserting the nullifier twice is an error
    {
        let res = queries::insert_nullifiers_for_block(conn, &nullifiers, block_num);
        assert!(res.is_err(), "Inserting the same nullifier twice is an error");
    }

    // even if the block number is different
    {
        let res = queries::insert_nullifiers_for_block(conn, &nullifiers, block_num + 1);

        assert!(
            res.is_err(),
            "Inserting the same nullifier twice is an error, even if with a different block number"
        );
    }

    // test inserting multiple nullifiers
    {
        let nullifiers: Vec<_> = (0..10).map(num_to_nullifier).collect();
        let block_num = 1.into();

        let res = queries::insert_nullifiers_for_block(conn, &nullifiers, block_num);

        assert_eq!(res.unwrap(), nullifiers.len(), "There should be 10 entries");
    }
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_insert_transactions() {
    let mut conn = create_db();
    let conn = &mut conn;
    let count = insert_transactions(conn);

    assert_eq!(count, 2, "Two elements must have been inserted");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_select_transactions() {
    fn query_transactions(conn: &mut SqliteConnection) -> Vec<TransactionSummary> {
        queries::select_transactions_by_accounts_and_block_range(
            conn,
            &[AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap()],
            BlockNumber::GENESIS..=BlockNumber::from(2),
        )
        .unwrap()
    }

    let mut conn = create_db();
    let conn = &mut conn;
    let transactions = query_transactions(conn);

    assert!(transactions.is_empty(), "No elements must be initially in the DB");

    let count = insert_transactions(conn);

    assert_eq!(count, 2, "Two elements must have been inserted");

    let transactions = query_transactions(conn);

    assert_eq!(transactions.len(), 2, "Two elements must be in the DB");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_select_nullifiers() {
    let mut conn = create_db();
    let conn = &mut conn;
    let block_num = 1.into();
    create_block(conn, block_num);

    // test querying empty table
    let nullifiers = queries::select_all_nullifiers(conn).unwrap();
    assert!(nullifiers.is_empty());

    // test multiple entries
    let mut state = vec![];
    for i in 0..10 {
        let nullifier = num_to_nullifier(i);
        state.push(NullifierInfo { nullifier, block_num });

        let res = queries::insert_nullifiers_for_block(conn, &[nullifier], block_num);
        assert_eq!(res.unwrap(), 1, "One element must have been inserted");

        let nullifiers = queries::select_all_nullifiers(conn).unwrap();
        assert_eq!(nullifiers, state);
    }
}

pub fn create_note(account_id: AccountId) -> Note {
    let coin_seed: [u64; 4] = rand::rng().random();
    let rng = Arc::new(Mutex::new(RpoRandomCoin::new(coin_seed.map(Felt::new).into())));
    let mut rng = rng.lock().unwrap();
    create_p2id_note(
        account_id,
        account_id,
        vec![Asset::Fungible(
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 10).unwrap(),
        )],
        NoteType::Public,
        NoteAttachment::default(),
        &mut *rng,
    )
    .expect("Failed to create note")
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_select_notes() {
    let mut conn = create_db();
    let conn = &mut conn;
    let block_num = BlockNumber::from(1);
    create_block(conn, block_num);

    // test querying empty table
    let notes = queries::select_all_notes(conn).unwrap();
    assert!(notes.is_empty());

    let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();

    queries::upsert_accounts(conn, &[mock_block_account_update(account_id, 0)], block_num).unwrap();

    let new_note = create_note(account_id);

    // test multiple entries
    let mut state = vec![];
    for i in 0..10 {
        let note = NoteRecord {
            block_num,
            note_index: BlockNoteIndex::new(0, i.try_into().unwrap()).unwrap(),
            note_id: num_to_word(u64::try_from(i).unwrap()),
            note_commitment: num_to_word(u64::try_from(i).unwrap()),
            metadata: new_note.metadata().clone(),
            details: Some(NoteDetails::from(&new_note)),
            inclusion_path: SparseMerklePath::default(),
        };
        state.push(note.clone());

        // insert scripts (after the first iteration the script is already in the db)
        let res = queries::insert_scripts(conn, [&note]);
        if i == 0 {
            assert_eq!(res.unwrap(), 1, "One element must have been inserted");
        } else {
            assert_eq!(res.unwrap(), 0, "No new elements must have been inserted");
        }

        // insert notes
        let res = queries::insert_notes(conn, &[(note, None)]);
        assert_eq!(res.unwrap(), 1, "One element must have been inserted");

        let notes = queries::select_all_notes(conn).unwrap();
        assert_eq!(notes, state);
    }
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_select_note_script_by_root() {
    let mut conn = create_db();
    let conn = &mut conn;
    let block_num = BlockNumber::from(1);
    create_block(conn, block_num);

    let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();

    queries::upsert_accounts(conn, &[mock_block_account_update(account_id, 0)], block_num).unwrap();

    let new_note = create_note(account_id);

    // test multiple entries
    let mut state = vec![];
    let note = NoteRecord {
        block_num,
        note_index: BlockNoteIndex::new(0, 0.try_into().unwrap()).unwrap(),
        note_id: num_to_word(0),
        note_commitment: num_to_word(0),
        metadata: new_note.metadata().clone(),
        details: Some(NoteDetails::from(&new_note)),
        inclusion_path: SparseMerklePath::default(),
    };
    state.push(note.clone());

    let res = queries::insert_scripts(conn, [&note]);
    assert_eq!(res.unwrap(), 1, "One element must have been inserted");

    // test querying the script by the root
    let note_script = queries::select_note_script_by_root(conn, new_note.script().root()).unwrap();
    assert_eq!(note_script, Some(new_note.script().clone()));

    // test querying the script by the root that is not in the database
    let note_script = queries::select_note_script_by_root(conn, [0_u16; 4].into()).unwrap();
    assert_eq!(note_script, None);
}

// Generates an account, inserts into the database, and creates a note for it.
fn make_account_and_note(
    conn: &mut SqliteConnection,
    block_num: BlockNumber,
    init_seed: [u8; 32],
    storage_mode: AccountStorageMode,
) -> (AccountId, Note) {
    conn.transaction(|conn| {
        let account = mock_account_code_and_storage(
            AccountType::RegularAccountUpdatableCode,
            storage_mode,
            [],
            Some(init_seed),
        );
        let account_id = account.id();
        queries::upsert_accounts(
            conn,
            &[BlockAccountUpdate::new(
                account_id,
                account.commitment(),
                AccountUpdateDetails::Delta(AccountDelta::try_from(account).unwrap()),
            )],
            block_num,
        )
        .unwrap();

        let new_note = create_note(account_id);
        Ok::<_, DatabaseError>((account_id, new_note))
    })
    .unwrap()
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_unconsumed_network_notes() {
    let mut conn = create_db();

    // Create account.
    let account_note =
        make_account_and_note(&mut conn, 0.into(), [1u8; 32], AccountStorageMode::Network);

    // Create 2 blocks.
    create_block(&mut conn, 0.into());
    create_block(&mut conn, 1.into());

    // Create a NetworkAccountTarget attachment for the network account
    let target = NetworkAccountTarget::new(account_note.0, NoteExecutionHint::Always)
        .expect("NetworkAccountTarget creation should succeed for network account");
    let attachment: NoteAttachment = target.into();

    // Create an unconsumed note in each block.
    let notes = Vec::from_iter((0..2).map(|i: u32| {
        let note = NoteRecord {
            block_num: 0.into(), // Created on same block.
            note_index: BlockNoteIndex::new(0, i as usize).unwrap(),
            note_id: num_to_word(i.into()),
            note_commitment: num_to_word(i.into()),
            metadata: NoteMetadata::new(
                account_note.0,
                NoteType::Public,
                NoteTag::with_account_target(account_note.0),
            )
            .with_attachment(attachment.clone()),
            details: None,
            inclusion_path: SparseMerklePath::default(),
        };
        (note, Some(num_to_nullifier(i.into())))
    }));
    queries::insert_scripts(&mut conn, notes.iter().map(|(note, _)| note)).unwrap();
    queries::insert_notes(&mut conn, &notes).unwrap();

    // Both notes are unconsumed, query should return both notes on both blocks.
    (0..2).for_each(|i: u32| {
        let (result, _) = queries::select_unconsumed_network_notes_by_account_id(
            &mut conn,
            account_note.0,
            i.into(),
            Page {
                token: None,
                size: NonZeroUsize::new(10).unwrap(),
            },
        )
        .unwrap();
        assert_eq!(result.len(), 2);
    });

    // Consume the 2nd note on the 2nd block.
    queries::insert_nullifiers_for_block(&mut conn, &[notes[1].1.unwrap()], 1.into()).unwrap();

    // Query against first block should return both notes.
    let (result, _) = queries::select_unconsumed_network_notes_by_account_id(
        &mut conn,
        account_note.0,
        0.into(),
        Page {
            token: None,
            size: NonZeroUsize::new(10).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(result.len(), 2);

    // Query against second block should return only first note.
    let (result, _) = queries::select_unconsumed_network_notes_by_account_id(
        &mut conn,
        account_note.0,
        1.into(),
        Page {
            token: None,
            size: NonZeroUsize::new(10).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].note_id, num_to_word(0));
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_select_accounts() {
    let mut conn = create_db();
    let conn = &mut conn;
    let block_num = 1.into();
    create_block(conn, block_num);

    // test querying empty table
    let accounts = queries::select_all_accounts(conn).unwrap();
    assert!(accounts.is_empty());
    // test multiple entries
    let mut state = vec![];
    for i in 0..10u8 {
        let account_id = AccountId::dummy(
            [i; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );
        let account_commitment = num_to_word(u64::from(i));
        state.push(AccountInfo {
            summary: AccountSummary {
                account_id,
                account_commitment,
                block_num,
            },
            details: None,
        });

        let res = queries::upsert_accounts(
            conn,
            &[BlockAccountUpdate::new(
                account_id,
                account_commitment,
                AccountUpdateDetails::Private,
            )],
            block_num,
        );
        assert_eq!(res.unwrap(), 1, "One element must have been inserted");

        let accounts = queries::select_all_accounts(conn).unwrap();
        assert_eq!(accounts, state);
    }
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sync_account_vault_basic_validation() {
    let mut conn = create_db();
    let conn = &mut conn;

    // Create a public account for vault testing
    let public_account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let block_from: BlockNumber = 1.into();
    let block_to: BlockNumber = 5.into();
    let block_mid: BlockNumber = 3.into();
    let invalid_block_from: BlockNumber = 10.into();

    // Create blocks
    create_block(conn, block_from);
    create_block(conn, block_mid);
    create_block(conn, block_to);

    // Create accounts - one public for vault assets, one private for testing
    queries::upsert_accounts(conn, &[mock_block_account_update(public_account_id, 0)], block_from)
        .unwrap();

    // Create some test vault assets
    let vault_key_1 = AssetVaultKey::new_unchecked(num_to_word(100));
    let vault_key_2 = AssetVaultKey::new_unchecked(num_to_word(200));
    let fungible_asset_1 = Asset::Fungible(FungibleAsset::new(public_account_id, 1000).unwrap());
    let fungible_asset_2 = Asset::Fungible(FungibleAsset::new(public_account_id, 2000).unwrap());

    // Insert vault assets for the public account at different blocks
    queries::insert_account_vault_asset(
        conn,
        public_account_id,
        block_from,
        vault_key_1,
        Some(fungible_asset_1),
    )
    .unwrap();
    queries::insert_account_vault_asset(
        conn,
        public_account_id,
        block_mid,
        vault_key_2,
        Some(fungible_asset_2),
    )
    .unwrap();

    // Update an existing vault asset (sets previous as not latest)
    let updated_fungible_asset_1 =
        Asset::Fungible(FungibleAsset::new(public_account_id, 1500).unwrap());
    queries::insert_account_vault_asset(
        conn,
        public_account_id,
        block_to,
        vault_key_1,
        Some(updated_fungible_asset_1),
    )
    .unwrap();

    // Test invalid block range - should return error
    let result = queries::select_account_vault_assets(
        conn,
        public_account_id,
        invalid_block_from..=block_to,
    );
    assert!(result.is_err(), "expected error for invalid block range");

    let Err(crate::errors::DatabaseError::InvalidBlockRange { .. }) = result else {
        panic!("expected error, got Ok");
    };

    // Test with valid block range - should return vault assets
    let (last_block, values) =
        queries::select_account_vault_assets(conn, public_account_id, block_from..=block_to)
            .unwrap();

    // Should return assets we inserted
    assert!(!values.is_empty(), "vault assets should have data");
    assert!(last_block >= block_from, "response block num should be higher than request");

    // Verify that we get the updated asset for vault_key_1
    let vault_key_1_asset =
        values.iter().find(|v| v.vault_key == vault_key_1 && v.block_num == block_to);
    assert!(vault_key_1_asset.is_some(), "should find updated vault asset");
    assert_eq!(vault_key_1_asset.unwrap().asset, Some(updated_fungible_asset_1));
}

#[test]
#[miden_node_test_macro::enable_logging]
fn select_nullifiers_by_prefix_works() {
    const PREFIX_LEN: u8 = 16;
    let mut conn = create_db();
    let conn = &mut conn; // test empty table
    let block_number0 = 0.into();
    let block_number10 = 10.into();
    let (nullifiers, block_number_reached) =
        queries::select_nullifiers_by_prefix(conn, PREFIX_LEN, &[], block_number0..=block_number10)
            .unwrap();
    assert!(nullifiers.is_empty());
    assert_eq!(block_number_reached, block_number10);

    // test single item
    let nullifier1 = num_to_nullifier(1 << 48);
    let block_number1 = 1.into();
    create_block(conn, block_number1);

    queries::insert_nullifiers_for_block(conn, &[nullifier1], block_number1).unwrap();

    let (nullifiers, block_number_reached) = queries::select_nullifiers_by_prefix(
        conn,
        PREFIX_LEN,
        &[utils::get_nullifier_prefix(&nullifier1)],
        block_number0..=block_number10,
    )
    .unwrap();
    assert_eq!(
        nullifiers,
        vec![NullifierInfo {
            nullifier: nullifier1,
            block_num: block_number1
        }]
    );
    // Block number reached should be the last block number (the block number of the last nullifier)
    assert_eq!(block_number_reached, block_number10);

    // test two elements
    let nullifier2 = num_to_nullifier(2 << 48);
    let block_number2 = 2.into();
    create_block(conn, block_number2);

    queries::insert_nullifiers_for_block(conn, &[nullifier2], block_number2).unwrap();

    let nullifiers = queries::select_all_nullifiers(conn).unwrap();
    assert_eq!(nullifiers, vec![(nullifier1, block_number1), (nullifier2, block_number2)]);

    // only the nullifiers matching the prefix are included
    let (nullifiers, _) = queries::select_nullifiers_by_prefix(
        conn,
        PREFIX_LEN,
        &[utils::get_nullifier_prefix(&nullifier1)],
        block_number0..=block_number10,
    )
    .unwrap();
    assert_eq!(
        nullifiers,
        vec![NullifierInfo {
            nullifier: nullifier1,
            block_num: block_number1
        }]
    );
    let (nullifiers, _) = queries::select_nullifiers_by_prefix(
        conn,
        PREFIX_LEN,
        &[utils::get_nullifier_prefix(&nullifier2)],
        block_number0..=block_number10,
    )
    .unwrap();
    assert_eq!(
        nullifiers,
        vec![NullifierInfo {
            nullifier: nullifier2,
            block_num: block_number2
        }]
    );

    // All matching nullifiers are included
    let (nullifiers, _) = queries::select_nullifiers_by_prefix(
        conn,
        PREFIX_LEN,
        &[
            utils::get_nullifier_prefix(&nullifier1),
            utils::get_nullifier_prefix(&nullifier2),
        ],
        block_number0..=block_number10,
    )
    .unwrap();
    assert_eq!(
        nullifiers,
        vec![
            NullifierInfo {
                nullifier: nullifier1,
                block_num: block_number1
            },
            NullifierInfo {
                nullifier: nullifier2,
                block_num: block_number2
            }
        ]
    );

    // If a non-matching prefix is provided, no nullifiers are returned
    let (nullifiers, _) = queries::select_nullifiers_by_prefix(
        conn,
        PREFIX_LEN,
        &[utils::get_nullifier_prefix(&num_to_nullifier(3 << 48))],
        block_number0..=block_number10,
    )
    .unwrap();
    assert!(nullifiers.is_empty());

    // If a block number is provided, only matching nullifiers created at or after that block are
    // returned
    let (nullifiers, _) = queries::select_nullifiers_by_prefix(
        conn,
        PREFIX_LEN,
        &[
            utils::get_nullifier_prefix(&nullifier1),
            utils::get_nullifier_prefix(&nullifier2),
        ],
        block_number2..=block_number10,
    )
    .unwrap();
    assert_eq!(
        nullifiers,
        vec![NullifierInfo {
            nullifier: nullifier2,
            block_num: block_number2
        }]
    );

    // Nullifiers are not returned if the block number is after the last nullifier
    let nullifier3 = num_to_nullifier(3 << 48);
    let block_number3 = 3.into();
    create_block(conn, block_number3);

    queries::insert_nullifiers_for_block(conn, &[nullifier3], block_number3).unwrap();

    let (nullifiers, block_number_reached) = queries::select_nullifiers_by_prefix(
        conn,
        PREFIX_LEN,
        &[
            utils::get_nullifier_prefix(&nullifier1),
            utils::get_nullifier_prefix(&nullifier2),
            utils::get_nullifier_prefix(&nullifier3),
        ],
        block_number0..=block_number2,
    )
    .unwrap();
    assert_eq!(
        nullifiers,
        vec![
            NullifierInfo {
                nullifier: nullifier1,
                block_num: block_number1
            },
            NullifierInfo {
                nullifier: nullifier2,
                block_num: block_number2
            }
        ]
    );
    assert_eq!(block_number_reached, block_number2);
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_block_header() {
    let mut conn = create_db();
    let conn = &mut conn; // test querying empty table
    let block_number = 1;
    let res = queries::select_block_header_by_block_num(conn, Some(block_number.into())).unwrap();
    assert!(res.is_none());

    let res = queries::select_block_header_by_block_num(conn, None).unwrap();
    assert!(res.is_none());

    let res = queries::select_all_block_headers(conn).unwrap();
    assert!(res.is_empty());

    let block_header = BlockHeader::new(
        1_u8.into(),
        num_to_word(2),
        3.into(),
        num_to_word(4),
        num_to_word(5),
        num_to_word(6),
        num_to_word(7),
        num_to_word(8),
        num_to_word(9),
        SecretKey::new().public_key(),
        test_fee_params(),
        11_u8.into(),
    );
    // test insertion

    let dummy_signature = SecretKey::new().sign(block_header.commitment());
    queries::insert_block_header(conn, &block_header, &dummy_signature).unwrap();

    // test fetch unknown block header
    let block_number = 1;
    let res = queries::select_block_header_by_block_num(conn, Some(block_number.into())).unwrap();
    assert!(res.is_none());

    // test fetch block header by block number
    let res =
        queries::select_block_header_by_block_num(conn, Some(block_header.block_num())).unwrap();
    assert_eq!(res.unwrap(), block_header);

    // test fetch latest block header
    let res = queries::select_block_header_by_block_num(conn, None).unwrap();
    assert_eq!(res.unwrap(), block_header);

    let block_header2 = BlockHeader::new(
        11_u8.into(),
        num_to_word(12),
        13.into(),
        num_to_word(14),
        num_to_word(15),
        num_to_word(16),
        num_to_word(17),
        num_to_word(18),
        num_to_word(19),
        SecretKey::new().public_key(),
        test_fee_params(),
        21_u8.into(),
    );

    let dummy_signature = SecretKey::new().sign(block_header2.commitment());
    queries::insert_block_header(conn, &block_header2, &dummy_signature).unwrap();

    let res = queries::select_block_header_by_block_num(conn, None).unwrap();
    assert_eq!(res.unwrap(), block_header2);

    let res = queries::select_all_block_headers(conn).unwrap();
    assert_eq!(res, [block_header, block_header2]);
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_account() {
    let mut conn = create_db();
    let conn = &mut conn;
    let block_num: BlockNumber = 1.into();
    create_block(conn, block_num);

    // test empty table
    let account_ids: Vec<AccountId> =
        [ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE, 1, 2, 3, 4, 5]
            .iter()
            .map(|acc_id| (*acc_id).try_into().unwrap())
            .collect();
    let res = queries::select_accounts_by_block_range(
        conn,
        &account_ids,
        BlockNumber::GENESIS..=u32::MAX.into(),
    )
    .unwrap();
    assert!(res.is_empty());

    // test insertion
    let account_id = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE;
    let account_commitment = num_to_word(0);

    let row_count = queries::upsert_accounts(
        conn,
        &[BlockAccountUpdate::new(
            account_id.try_into().unwrap(),
            account_commitment,
            AccountUpdateDetails::Private,
        )],
        block_num,
    )
    .unwrap();

    assert_eq!(row_count, 1);

    // test successful query
    let res = queries::select_accounts_by_block_range(
        conn,
        &account_ids,
        BlockNumber::GENESIS..=u32::MAX.into(),
    )
    .unwrap();
    assert_eq!(
        res,
        vec![AccountSummary {
            account_id: account_id.try_into().unwrap(),
            account_commitment,
            block_num,
        }]
    );

    // test query for update outside the block range
    let res = queries::select_accounts_by_block_range(
        conn,
        &account_ids,
        (block_num.as_u32() + 1).into()..=u32::MAX.into(),
    )
    .unwrap();
    assert!(res.is_empty());

    // test query with unknown accounts
    let res = queries::select_accounts_by_block_range(
        conn,
        &[6.try_into().unwrap(), 7.try_into().unwrap(), 8.try_into().unwrap()],
        (block_num + 1)..=u32::MAX.into(),
    )
    .unwrap();
    assert!(res.is_empty());
}

#[test]
#[miden_node_test_macro::enable_logging]
fn notes() {
    let mut conn = create_db();
    let conn = &mut conn;
    let block_num_1 = 1.into();
    create_block(conn, block_num_1);

    let block_range = BlockNumber::GENESIS..=BlockNumber::from(1);

    // test empty table
    let (res, last_included_block) =
        queries::select_notes_since_block_by_tag_and_sender(conn, &[], &[], block_range.clone())
            .unwrap();

    assert!(res.is_empty());
    assert_eq!(last_included_block, 1.into());

    let (res, last_included_block) = queries::select_notes_since_block_by_tag_and_sender(
        conn,
        &[],
        &[1, 2, 3],
        block_range.clone(),
    )
    .unwrap();
    assert!(res.is_empty());
    assert_eq!(last_included_block, 1.into());

    let sender = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();

    // test insertion

    queries::upsert_accounts(conn, &[mock_block_account_update(sender, 0)], block_num_1).unwrap();

    let new_note = create_note(sender);
    let note_index = BlockNoteIndex::new(0, 2).unwrap();
    let tag = 5u32;
    let note_metadata = NoteMetadata::new(sender, NoteType::Public, tag.into());

    let values = [(note_index, new_note.id(), &note_metadata)];
    let notes_db = BlockNoteTree::with_entries(values).unwrap();
    let inclusion_path = notes_db.open(note_index);

    let note = NoteRecord {
        block_num: block_num_1,
        note_index,
        note_id: new_note.id().as_word(),
        note_commitment: new_note.commitment(),
        metadata: NoteMetadata::new(sender, NoteType::Public, tag.into()),
        details: Some(NoteDetails::from(&new_note)),
        inclusion_path: inclusion_path.clone(),
    };

    queries::insert_scripts(conn, [&note]).unwrap();
    queries::insert_notes(conn, &[(note.clone(), None)]).unwrap();

    // test empty tags
    let (res, last_included_block) =
        queries::select_notes_since_block_by_tag_and_sender(conn, &[], &[], block_range.clone())
            .unwrap();
    assert!(res.is_empty());
    assert_eq!(last_included_block, 1.into());

    let block_range_1 = 1.into()..=1.into();

    // test no updates
    let (res, last_included_block) =
        queries::select_notes_since_block_by_tag_and_sender(conn, &[], &[tag], block_range_1)
            .unwrap();
    assert!(res.is_empty());
    assert_eq!(last_included_block, 1.into());

    // test match
    let (res, last_included_block) =
        queries::select_notes_since_block_by_tag_and_sender(conn, &[], &[tag], block_range.clone())
            .unwrap();
    assert_eq!(res, vec![note.clone().into()]);
    assert_eq!(last_included_block, 1.into());

    let block_num_2 = note.block_num + 1;
    create_block(conn, block_num_2);

    // insertion second note with same tag, but on higher block
    let note2 = NoteRecord {
        block_num: block_num_2,
        note_index: note.note_index,
        note_id: new_note.id().as_word(),
        note_commitment: new_note.commitment(),
        metadata: note.metadata.clone(),
        details: None,
        inclusion_path: inclusion_path.clone(),
    };

    queries::insert_notes(conn, &[(note2.clone(), None)]).unwrap();

    let block_range = 0.into()..=2.into();

    // only first note is returned
    let (res, last_included_block) =
        queries::select_notes_since_block_by_tag_and_sender(conn, &[], &[tag], block_range)
            .unwrap();
    assert_eq!(res, vec![note.clone().into()]);
    assert_eq!(last_included_block, 1.into());

    let block_range = 1.into()..=2.into();

    // only the second note is returned
    let (res, last_included_block) =
        queries::select_notes_since_block_by_tag_and_sender(conn, &[], &[tag], block_range)
            .unwrap();
    assert_eq!(res, vec![note2.clone().into()]);
    assert_eq!(last_included_block, 2.into());

    // test query notes by id
    let notes = vec![note.clone(), note2];

    let note_ids = Vec::from_iter(notes.iter().map(|note| NoteId::from_raw(note.note_id)));

    let res = queries::select_notes_by_id(conn, &note_ids).unwrap();
    assert_eq!(res, notes);

    // test notes have correct details
    let note_0 = res[0].clone();
    let note_1 = res[1].clone();
    assert_eq!(note_0.details, note.details);
    assert_eq!(note_1.details, None);
}

fn insert_account_delta(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_number: BlockNumber,
    delta: &AccountDelta,
) {
    for (slot_name, slot_delta) in delta.storage().maps() {
        for (k, v) in slot_delta.entries() {
            insert_account_storage_map_value(
                conn,
                account_id,
                block_number,
                slot_name.clone(),
                *k.inner(),
                *v,
            )
            .unwrap();
        }
    }
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_account_storage_map_values_insertion() {
    use std::collections::BTreeMap;

    use miden_protocol::account::StorageMapDelta;

    let mut conn = create_db();
    let conn = &mut conn;

    let block1: BlockNumber = 1.into();
    let block2: BlockNumber = 2.into();
    create_block(conn, block1);
    create_block(conn, block2);

    let account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();

    let slot_name = StorageSlotName::mock(3);
    let key1 = Word::from([1u32, 2, 3, 4]);
    let key2 = Word::from([5u32, 6, 7, 8]);
    let value1 = Word::from([10u32, 11, 12, 13]);
    let value2 = Word::from([20u32, 21, 22, 23]);
    let value3 = Word::from([30u32, 31, 32, 33]);

    // Insert at block 1
    let mut map1 = StorageMapDelta::default();
    map1.insert(key1, value1);
    map1.insert(key2, value2);
    let delta1 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map1))]);
    let storage1 = AccountStorageDelta::from_raw(delta1);
    let delta1 =
        AccountDelta::new(account_id, storage1, AccountVaultDelta::default(), Felt::ONE).unwrap();
    insert_account_delta(conn, account_id, block1, &delta1);

    let storage_map_page =
        queries::select_account_storage_map_values(conn, account_id, BlockNumber::GENESIS..=block1)
            .unwrap();
    assert_eq!(storage_map_page.values.len(), 2, "expect 2 initial rows");

    // Update key1 at block 2
    let mut map2 = StorageMapDelta::default();
    map2.insert(key1, value3);
    let delta2 = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map2))]);
    let storage2 = AccountStorageDelta::from_raw(delta2);
    let delta2 =
        AccountDelta::new(account_id, storage2, AccountVaultDelta::default(), Felt::new(2))
            .unwrap();
    insert_account_delta(conn, account_id, block2, &delta2);

    let storage_map_values =
        queries::select_account_storage_map_values(conn, account_id, BlockNumber::GENESIS..=block2)
            .unwrap();

    assert_eq!(storage_map_values.values.len(), 3, "three rows (with duplicate key)");
    // key1 should now be value3 at block2; key2 remains value2 at block1
    assert!(
        storage_map_values
            .values
            .iter()
            .any(|val| val.slot_name == slot_name && val.key == key1 && val.value == value3),
        "key1 should point to new value at block2"
    );
    assert!(
        storage_map_values
            .values
            .iter()
            .any(|val| val.slot_name == slot_name && val.key == key2 && val.value == value2),
        "key2 should stay the same (from block1)"
    );
}

#[test]
fn select_storage_map_sync_values() {
    let mut conn = create_db();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let slot_name = StorageSlotName::mock(5);

    let key1 = num_to_word(1);
    let key2 = num_to_word(2);
    let key3 = num_to_word(3);
    let value1 = num_to_word(10);
    let value2 = num_to_word(20);
    let value3 = num_to_word(30);

    let block1 = BlockNumber::from(1);
    let block2 = BlockNumber::from(2);
    let block3 = BlockNumber::from(3);

    // Insert data across multiple blocks using individual inserts
    // Block 1: key1 -> value1, key2 -> value2
    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block1,
        slot_name.clone(),
        key1,
        value1,
    )
    .unwrap();
    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block1,
        slot_name.clone(),
        key2,
        value2,
    )
    .unwrap();

    // Block 2: key2 -> value3 (update), key3 -> value3 (new)
    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block2,
        slot_name.clone(),
        key2,
        value3,
    )
    .unwrap();
    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block2,
        slot_name.clone(),
        key3,
        value3,
    )
    .unwrap();

    // Block 3: key1 -> value2 (update)
    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block3,
        slot_name.clone(),
        key1,
        value2,
    )
    .unwrap();

    let page = queries::select_account_storage_map_values(
        &mut conn,
        account_id,
        BlockNumber::from(2)..=BlockNumber::from(3),
    )
    .unwrap();

    assert_eq!(page.values.len(), 3, "should return latest values");

    // Compare ordered by key using a tuple view to avoid relying on the concrete struct name
    let expected = vec![
        StorageMapValue {
            slot_name: slot_name.clone(),
            key: key2,
            value: value3,
            block_num: block2,
        },
        StorageMapValue {
            slot_name: slot_name.clone(),
            key: key3,
            value: value3,
            block_num: block2,
        },
        StorageMapValue {
            slot_name,
            key: key1,
            value: value2,
            block_num: block3,
        },
    ];

    assert_eq!(page.values, expected, "should return latest values ordered by key");
}

// UTILITIES
// -------------------------------------------------------------------------------------------
fn num_to_word(n: u64) -> Word {
    [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::new(n)].into()
}

fn num_to_nullifier(n: u64) -> Nullifier {
    Nullifier::from_raw(num_to_word(n))
}

fn mock_block_account_update(account_id: AccountId, num: u64) -> BlockAccountUpdate {
    BlockAccountUpdate::new(account_id, num_to_word(num), AccountUpdateDetails::Private)
}

// Helper function to create account with specific code for tests
fn create_account_with_code(code_str: &str, seed: [u8; 32]) -> Account {
    let component_storage = vec![
        StorageSlot::with_value(StorageSlotName::mock(0), Word::empty()),
        StorageSlot::with_value(StorageSlotName::mock(1), num_to_word(1)),
    ];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", code_str)
        .unwrap();

    let component = AccountComponent::new(account_component_code, component_storage)
        .unwrap()
        .with_supported_type(AccountType::RegularAccountUpdatableCode);

    AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap()
}

fn mock_block_transaction(account_id: AccountId, num: u64) -> TransactionHeader {
    let initial_state_commitment = Word::try_from([num, 0, 0, 0]).unwrap();
    let final_account_commitment = Word::try_from([0, num, 0, 0]).unwrap();
    let input_notes_commitment = Word::try_from([0, 0, num, 0]).unwrap();
    let output_notes_commitment = Word::try_from([0, 0, 0, num]).unwrap();

    let notes = vec![InputNoteCommitment::from(num_to_nullifier(num))];
    let input_notes = InputNotes::new_unchecked(notes);

    let output_notes = vec![NoteHeader::new(
        NoteId::new(
            Word::try_from([num, num, 0, 0]).unwrap(),
            Word::try_from([0, 0, num, num]).unwrap(),
        ),
        NoteMetadata::new(account_id, NoteType::Public, NoteTag::new(num as u32)),
    )];

    TransactionHeader::new_unchecked(
        TransactionId::new(
            initial_state_commitment,
            final_account_commitment,
            input_notes_commitment,
            output_notes_commitment,
        ),
        account_id,
        initial_state_commitment,
        final_account_commitment,
        input_notes,
        output_notes,
        test_fee(),
    )
}

fn insert_transactions(conn: &mut SqliteConnection) -> usize {
    let block_num = 1.into();
    create_block(conn, block_num);

    conn.transaction(|conn| {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();

        let account_updates = vec![mock_block_account_update(account_id, 1)];

        let mock_tx1 =
            mock_block_transaction(AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap(), 1);
        let mock_tx2 =
            mock_block_transaction(AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap(), 2);
        let ordered_tx_headers = OrderedTransactionHeaders::new_unchecked(vec![mock_tx1, mock_tx2]);

        queries::upsert_accounts(conn, &account_updates, block_num).unwrap();

        let count = queries::insert_transactions(conn, block_num, &ordered_tx_headers).unwrap();
        Ok::<_, DatabaseError>(count)
    })
    .unwrap()
}

fn mock_account_code_and_storage(
    account_type: AccountType,
    storage_mode: AccountStorageMode,
    assets: impl IntoIterator<Item = Asset>,
    init_seed: Option<[u8; 32]>,
) -> Account {
    let component_code = "\
    pub proc account_procedure_1
        push.1.2
        add
    end
    ";

    let component_storage = vec![
        StorageSlot::with_value(StorageSlotName::mock(0), Word::empty()),
        StorageSlot::with_value(StorageSlotName::mock(1), num_to_word(1)),
        StorageSlot::with_value(StorageSlotName::mock(2), Word::empty()),
        StorageSlot::with_value(StorageSlotName::mock(3), num_to_word(3)),
        StorageSlot::with_value(StorageSlotName::mock(4), Word::empty()),
        StorageSlot::with_value(StorageSlotName::mock(5), num_to_word(5)),
    ];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("counter_contract::interface", component_code)
        .unwrap();
    let account_component = AccountComponent::new(account_component_code, component_storage)
        .unwrap()
        .with_supports_all_types();

    AccountBuilder::new(init_seed.unwrap_or([0; 32]))
        .account_type(account_type)
        .storage_mode(storage_mode)
        .with_assets(assets)
        .with_component(account_component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap()
}

// ACCOUNT CODE TESTS
// ================================================================================================

#[test]
fn test_select_account_code_by_commitment() {
    let mut conn = create_db();

    let block_num_1 = BlockNumber::from(1);

    // Create block 1
    create_block(&mut conn, block_num_1);

    // Create an account with code at block 1 using the existing mock function
    let account = mock_account_code_and_storage(
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
        [],
        None,
    );

    // Get the code commitment and bytes before inserting
    let code_commitment = account.code().commitment();
    let expected_code = account.code().to_bytes();

    // Insert the account at block 1
    queries::upsert_accounts(
        &mut conn,
        &[BlockAccountUpdate::new(
            account.id(),
            account.commitment(),
            AccountUpdateDetails::Delta(AccountDelta::try_from(account).unwrap()),
        )],
        block_num_1,
    )
    .unwrap();

    // Query code by commitment - should return the code
    let code = queries::select_account_code_by_commitment(&mut conn, code_commitment)
        .unwrap()
        .expect("Code should exist");
    assert_eq!(code, expected_code);

    // Query code for non-existent commitment - should return None
    let non_existent_commitment = [0u8; 32];
    let non_existent_commitment = Word::read_from_bytes(&non_existent_commitment).unwrap();
    let code_other =
        queries::select_account_code_by_commitment(&mut conn, non_existent_commitment).unwrap();
    assert!(code_other.is_none(), "Code should not exist for non-existent commitment");
}

#[test]
fn test_select_account_code_by_commitment_multiple_codes() {
    let mut conn = create_db();

    let block_num_1 = BlockNumber::from(1);
    let block_num_2 = BlockNumber::from(2);

    // Create blocks
    create_block(&mut conn, block_num_1);
    create_block(&mut conn, block_num_2);

    // Create account with code v1 at block 1
    let code_v1_str = "\
        pub proc account_procedure_1
            push.1.2
            add
        end
    ";
    let account_v1 = create_account_with_code(code_v1_str, [1u8; 32]);
    let code_v1_commitment = account_v1.code().commitment();
    let code_v1 = account_v1.code().to_bytes();

    // Insert the account at block 1
    queries::upsert_accounts(
        &mut conn,
        &[BlockAccountUpdate::new(
            account_v1.id(),
            account_v1.commitment(),
            AccountUpdateDetails::Delta(AccountDelta::try_from(account_v1).unwrap()),
        )],
        block_num_1,
    )
    .unwrap();

    // Create account with different code v2 at block 2
    let code_v2_str = "\
        pub proc account_procedure_1
            push.3.4
            mul
        end
    ";
    let account_v2 = create_account_with_code(code_v2_str, [1u8; 32]); // Same seed to keep same account_id
    let code_v2_commitment = account_v2.code().commitment();
    let code_v2 = account_v2.code().to_bytes();

    // Verify that the codes are actually different
    assert_ne!(
        code_v1, code_v2,
        "Test setup error: codes should be different for different code strings"
    );
    assert_ne!(
        code_v1_commitment, code_v2_commitment,
        "Test setup error: code commitments should be different"
    );

    // Insert the updated account at block 2
    queries::upsert_accounts(
        &mut conn,
        &[BlockAccountUpdate::new(
            account_v2.id(),
            account_v2.commitment(),
            AccountUpdateDetails::Delta(AccountDelta::try_from(account_v2).unwrap()),
        )],
        block_num_2,
    )
    .unwrap();

    // Both codes should be retrievable by their respective commitments
    let code_from_v1_commitment =
        queries::select_account_code_by_commitment(&mut conn, code_v1_commitment)
            .unwrap()
            .expect("v1 code should exist");
    assert_eq!(code_from_v1_commitment, code_v1, "v1 commitment should return v1 code");

    let code_from_v2_commitment =
        queries::select_account_code_by_commitment(&mut conn, code_v2_commitment)
            .unwrap()
            .expect("v2 code should exist");
    assert_eq!(code_from_v2_commitment, code_v2, "v2 commitment should return v2 code");
}

// GENESIS REGRESSION TESTS
// ================================================================================================

/// Verifies genesis block with account containing vault assets can be inserted.
#[test]
#[miden_node_test_macro::enable_logging]
fn genesis_with_account_assets() {
    use crate::genesis::GenesisState;
    let component_code = "pub proc foo push.1 end";

    let account_component_code = CodeBuilder::default()
        .compile_component_code("foo::interface", component_code)
        .unwrap();
    let account_component = AccountComponent::new(account_component_code, Vec::new())
        .unwrap()
        .with_supports_all_types();

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let fungible_asset = FungibleAsset::new(faucet_id, 1000).unwrap();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component)
        .with_assets([fungible_asset.into()])
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let genesis_state =
        GenesisState::new(vec![account], test_fee_params(), 1, 0, SecretKey::random());
    let genesis_block = genesis_state.into_block().unwrap();

    crate::db::Db::bootstrap(":memory:".into(), &genesis_block).unwrap();
}

/// Verifies genesis block with account containing storage maps can be inserted.
#[test]
#[miden_node_test_macro::enable_logging]
fn genesis_with_account_storage_map() {
    use miden_protocol::account::StorageMap;

    use crate::genesis::GenesisState;

    let storage_map = StorageMap::with_entries(vec![
        (
            Word::from([Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            Word::from([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]),
        ),
        (
            Word::from([Felt::new(2), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            Word::from([Felt::new(50), Felt::new(60), Felt::new(70), Felt::new(80)]),
        ),
    ])
    .unwrap();

    let component_storage = vec![
        StorageSlot::with_map(StorageSlotName::mock(0), storage_map),
        StorageSlot::with_empty_value(StorageSlotName::mock(1)),
    ];

    let component_code = "pub proc foo push.1 end";

    let account_component_code = CodeBuilder::default()
        .compile_component_code("foo::interface", component_code)
        .unwrap();
    let account_component = AccountComponent::new(account_component_code, component_storage)
        .unwrap()
        .with_supports_all_types();

    let account = AccountBuilder::new([2u8; 32])
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let genesis_state =
        GenesisState::new(vec![account], test_fee_params(), 1, 0, SecretKey::random());
    let genesis_block = genesis_state.into_block().unwrap();

    crate::db::Db::bootstrap(":memory:".into(), &genesis_block).unwrap();
}

/// Verifies genesis block with account containing both vault assets and storage maps.
#[test]
#[miden_node_test_macro::enable_logging]
fn genesis_with_account_assets_and_storage() {
    use miden_protocol::account::StorageMap;

    use crate::genesis::GenesisState;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let fungible_asset = FungibleAsset::new(faucet_id, 5000).unwrap();

    let storage_map = StorageMap::with_entries(vec![(
        Word::from([Felt::new(100), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
    )])
    .unwrap();

    let component_storage = vec![
        StorageSlot::with_empty_value(StorageSlotName::mock(0)),
        StorageSlot::with_map(StorageSlotName::mock(2), storage_map),
    ];

    let component_code = "pub proc foo push.1 end";

    let account_component_code = CodeBuilder::default()
        .compile_component_code("foo::interface", component_code)
        .unwrap();
    let account_component = AccountComponent::new(account_component_code, component_storage)
        .unwrap()
        .with_supports_all_types();

    let account = AccountBuilder::new([3u8; 32])
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component)
        .with_assets([fungible_asset.into()])
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let genesis_state =
        GenesisState::new(vec![account], test_fee_params(), 1, 0, SecretKey::random());
    let genesis_block = genesis_state.into_block().unwrap();

    crate::db::Db::bootstrap(":memory:".into(), &genesis_block).unwrap();
}

/// Verifies genesis block with multiple accounts of different types.
/// Tests realistic genesis scenario with basic accounts, assets, and storage.
#[test]
#[miden_node_test_macro::enable_logging]
fn genesis_with_multiple_accounts() {
    use miden_protocol::account::StorageMap;

    use crate::genesis::GenesisState;

    let account_component_code = CodeBuilder::default()
        .compile_component_code("foo::interface", "pub proc foo push.1 end")
        .unwrap();
    let account_component1 = AccountComponent::new(account_component_code, Vec::new())
        .unwrap()
        .with_supports_all_types();

    let account1 = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component1)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let fungible_asset = FungibleAsset::new(faucet_id, 2000).unwrap();

    let account_component_code = CodeBuilder::default()
        .compile_component_code("bar::interface", "pub proc bar push.2 end")
        .unwrap();
    let account_component2 = AccountComponent::new(account_component_code, Vec::new())
        .unwrap()
        .with_supports_all_types();

    let account2 = AccountBuilder::new([2u8; 32])
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component2)
        .with_assets([fungible_asset.into()])
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let storage_map = StorageMap::with_entries(vec![(
        Word::from([Felt::new(5), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        Word::from([Felt::new(15), Felt::new(25), Felt::new(35), Felt::new(45)]),
    )])
    .unwrap();

    let component_storage = vec![StorageSlot::with_map(StorageSlotName::mock(0), storage_map)];

    let account_component_code = CodeBuilder::default()
        .compile_component_code("baz::interface", "pub proc baz push.3 end")
        .unwrap();
    let account_component3 = AccountComponent::new(account_component_code, component_storage)
        .unwrap()
        .with_supports_all_types();

    let account3 = AccountBuilder::new([3u8; 32])
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component3)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let genesis_state = GenesisState::new(
        vec![account1, account2, account3],
        test_fee_params(),
        1,
        0,
        SecretKey::random(),
    );
    let genesis_block = genesis_state.into_block().unwrap();

    crate::db::Db::bootstrap(":memory:".into(), &genesis_block).unwrap();
}

#[test]
#[miden_node_test_macro::enable_logging]
fn regression_1461_full_state_delta_inserts_vault_assets() {
    let mut conn = create_db();
    let block_num: BlockNumber = 1.into();
    create_block(&mut conn, block_num);

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let fungible_asset = FungibleAsset::new(faucet_id, 5000).unwrap();

    let account = mock_account_code_and_storage(
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
        [fungible_asset.into()],
        Some([42u8; 32]),
    );
    let account_id = account.id();

    // Convert to full state delta, same as genesis
    let account_delta = AccountDelta::try_from(account.clone()).unwrap();
    assert!(account_delta.is_full_state());

    let block_update = BlockAccountUpdate::new(
        account_id,
        account.commitment(),
        AccountUpdateDetails::Delta(account_delta),
    );

    queries::upsert_accounts(&mut conn, &[block_update], block_num).unwrap();

    let (_, vault_assets) = queries::select_account_vault_assets(
        &mut conn,
        account_id,
        BlockNumber::GENESIS..=block_num,
    )
    .unwrap();

    // Before the fix, vault_assets was empty
    let vault_asset = vault_assets.first().unwrap();
    let expected_asset: Asset = fungible_asset.into();
    assert_eq!(vault_asset.block_num, block_num);
    assert_eq!(vault_asset.asset, Some(expected_asset));
    assert_eq!(vault_asset.vault_key, expected_asset.vault_key());
}

// SERIALIZATION SYMMETRY TESTS
// ================================================================================================
//
// These tests ensure that `to_bytes` and `from_bytes`/`read_from_bytes` are symmetric for all
// types used in database operations. This guarantees that data inserted into the database can
// always be correctly retrieved.

#[test]
fn serialization_symmetry_core_types() {
    // AccountId
    let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
    let bytes = account_id.to_bytes();
    let restored = AccountId::read_from_bytes(&bytes).unwrap();
    assert_eq!(account_id, restored, "AccountId serialization must be symmetric");

    // Word
    let word = num_to_word(0x1234_5678_9ABC_DEF0);
    let bytes = word.to_bytes();
    let restored = Word::read_from_bytes(&bytes).unwrap();
    assert_eq!(word, restored, "Word serialization must be symmetric");

    // Nullifier
    let nullifier = num_to_nullifier(0xDEAD_BEEF);
    let bytes = nullifier.to_bytes();
    let restored = Nullifier::read_from_bytes(&bytes).unwrap();
    assert_eq!(nullifier, restored, "Nullifier serialization must be symmetric");

    // TransactionId
    let tx_id = TransactionId::new(num_to_word(1), num_to_word(2), num_to_word(3), num_to_word(4));
    let bytes = tx_id.to_bytes();
    let restored = TransactionId::read_from_bytes(&bytes).unwrap();
    assert_eq!(tx_id, restored, "TransactionId serialization must be symmetric");

    // NoteId
    let note_id = NoteId::new(num_to_word(1), num_to_word(2));
    let bytes = note_id.to_bytes();
    let restored = NoteId::read_from_bytes(&bytes).unwrap();
    assert_eq!(note_id, restored, "NoteId serialization must be symmetric");
}

#[test]
fn serialization_symmetry_block_header() {
    let block_header = BlockHeader::new(
        1_u8.into(),
        num_to_word(2),
        3.into(),
        num_to_word(4),
        num_to_word(5),
        num_to_word(6),
        num_to_word(7),
        num_to_word(8),
        num_to_word(9),
        SecretKey::new().public_key(),
        test_fee_params(),
        11_u8.into(),
    );

    let bytes = block_header.to_bytes();
    let restored = BlockHeader::read_from_bytes(&bytes).unwrap();
    assert_eq!(block_header, restored, "BlockHeader serialization must be symmetric");
}

#[test]
fn serialization_symmetry_assets() {
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    // FungibleAsset
    let fungible = FungibleAsset::new(faucet_id, 1000).unwrap();
    let asset: Asset = fungible.into();
    let bytes = asset.to_bytes();
    let restored = Asset::read_from_bytes(&bytes).unwrap();
    assert_eq!(asset, restored, "Asset (fungible) serialization must be symmetric");
}

#[test]
fn serialization_symmetry_account_code() {
    let account = mock_account_code_and_storage(
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
        [],
        None,
    );

    let code = account.code();
    let bytes = code.to_bytes();
    let restored = AccountCode::read_from_bytes(&bytes).unwrap();
    assert_eq!(*code, restored, "AccountCode serialization must be symmetric");
}

#[test]
fn serialization_symmetry_sparse_merkle_path() {
    let path = SparseMerklePath::default();
    let bytes = path.to_bytes();
    let restored = SparseMerklePath::read_from_bytes(&bytes).unwrap();
    assert_eq!(path, restored, "SparseMerklePath serialization must be symmetric");
}

#[test]
fn serialization_symmetry_note_metadata() {
    let sender = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
    // Use a tag that roundtrips properly - NoteTag::LocalAny stores the full u32 including type
    // bits
    let tag = NoteTag::with_account_target(sender);
    let metadata = NoteMetadata::new(sender, NoteType::Public, tag);

    let bytes = metadata.to_bytes();
    let restored = NoteMetadata::read_from_bytes(&bytes).unwrap();
    assert_eq!(metadata, restored, "NoteMetadata serialization must be symmetric");
}

#[test]
fn serialization_symmetry_nullifier_vec() {
    let nullifiers: Vec<Nullifier> = (0..5).map(num_to_nullifier).collect();
    let bytes = nullifiers.to_bytes();
    let restored: Vec<Nullifier> = Deserializable::read_from_bytes(&bytes).unwrap();
    assert_eq!(nullifiers, restored, "Vec<Nullifier> serialization must be symmetric");
}

#[test]
fn serialization_symmetry_note_id_vec() {
    let note_ids: Vec<NoteId> =
        (0..5).map(|i| NoteId::new(num_to_word(i), num_to_word(i + 100))).collect();
    let bytes = note_ids.to_bytes();
    let restored: Vec<NoteId> = Deserializable::read_from_bytes(&bytes).unwrap();
    assert_eq!(note_ids, restored, "Vec<NoteId> serialization must be symmetric");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_roundtrip_block_header() {
    let mut conn = create_db();

    let block_header = BlockHeader::new(
        1_u8.into(),
        num_to_word(2),
        BlockNumber::from(42),
        num_to_word(4),
        num_to_word(5),
        num_to_word(6),
        num_to_word(7),
        num_to_word(8),
        num_to_word(9),
        SecretKey::new().public_key(),
        test_fee_params(),
        11_u8.into(),
    );

    // Insert
    let dummy_signature = SecretKey::new().sign(block_header.commitment());
    queries::insert_block_header(&mut conn, &block_header, &dummy_signature).unwrap();

    // Retrieve
    let retrieved =
        queries::select_block_header_by_block_num(&mut conn, Some(block_header.block_num()))
            .unwrap()
            .expect("Block header should exist");

    assert_eq!(block_header, retrieved, "BlockHeader DB roundtrip must be symmetric");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_roundtrip_nullifiers() {
    let mut conn = create_db();
    let block_num = BlockNumber::from(1);
    create_block(&mut conn, block_num);

    let nullifiers: Vec<Nullifier> = (0..5).map(|i| num_to_nullifier(i << 48)).collect();

    // Insert
    queries::insert_nullifiers_for_block(&mut conn, &nullifiers, block_num).unwrap();

    // Retrieve
    let retrieved = queries::select_all_nullifiers(&mut conn).unwrap();

    assert_eq!(nullifiers.len(), retrieved.len(), "Should retrieve same number of nullifiers");
    for (orig, info) in nullifiers.iter().zip(retrieved.iter()) {
        assert_eq!(*orig, info.nullifier, "Nullifier DB roundtrip must be symmetric");
        assert_eq!(block_num, info.block_num, "Block number must match");
    }
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_roundtrip_account() {
    let mut conn = create_db();
    let block_num = BlockNumber::from(1);
    create_block(&mut conn, block_num);

    let account = mock_account_code_and_storage(
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Public,
        [],
        Some([99u8; 32]),
    );
    let account_id = account.id();
    let account_commitment = account.commitment();

    // Insert with full delta (like genesis)
    let account_delta = AccountDelta::try_from(account.clone()).unwrap();
    let block_update = BlockAccountUpdate::new(
        account_id,
        account_commitment,
        AccountUpdateDetails::Delta(account_delta),
    );
    queries::upsert_accounts(&mut conn, &[block_update], block_num).unwrap();

    // Retrieve
    let retrieved = queries::select_all_accounts(&mut conn).unwrap();
    assert_eq!(retrieved.len(), 1, "Should have one account");

    let retrieved_info = &retrieved[0];
    assert_eq!(
        retrieved_info.summary.account_id, account_id,
        "AccountId DB roundtrip must be symmetric"
    );
    assert_eq!(
        retrieved_info.summary.account_commitment, account_commitment,
        "Account commitment DB roundtrip must be symmetric"
    );
    assert_eq!(retrieved_info.summary.block_num, block_num, "Block number must match");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_roundtrip_notes() {
    let mut conn = create_db();
    let block_num = BlockNumber::from(1);
    create_block(&mut conn, block_num);

    let sender = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
    queries::upsert_accounts(&mut conn, &[mock_block_account_update(sender, 0)], block_num)
        .unwrap();

    let new_note = create_note(sender);
    let note_index = BlockNoteIndex::new(0, 0).unwrap();

    let note = NoteRecord {
        block_num,
        note_index,
        note_id: new_note.id().as_word(),
        note_commitment: new_note.commitment(),
        metadata: new_note.metadata().clone(),
        details: Some(NoteDetails::from(&new_note)),
        inclusion_path: SparseMerklePath::default(),
    };

    // Insert
    queries::insert_scripts(&mut conn, [&note]).unwrap();
    queries::insert_notes(&mut conn, &[(note.clone(), None)]).unwrap();

    // Retrieve
    let note_ids = vec![NoteId::from_raw(note.note_id)];
    let retrieved = queries::select_notes_by_id(&mut conn, &note_ids).unwrap();

    assert_eq!(retrieved.len(), 1, "Should have one note");
    let retrieved_note = &retrieved[0];

    assert_eq!(note.note_id, retrieved_note.note_id, "NoteId DB roundtrip must be symmetric");
    assert_eq!(
        note.note_commitment, retrieved_note.note_commitment,
        "Note commitment DB roundtrip must be symmetric"
    );
    assert_eq!(
        note.metadata, retrieved_note.metadata,
        "Metadata DB roundtrip must be symmetric"
    );
    assert_eq!(
        note.inclusion_path, retrieved_note.inclusion_path,
        "Inclusion path DB roundtrip must be symmetric"
    );
    assert_eq!(
        note.details, retrieved_note.details,
        "Note details DB roundtrip must be symmetric"
    );
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_roundtrip_transactions() {
    let mut conn = create_db();
    let block_num = BlockNumber::from(1);
    create_block(&mut conn, block_num);

    let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 1)], block_num)
        .unwrap();

    let tx = mock_block_transaction(account_id, 1);
    let ordered_tx = OrderedTransactionHeaders::new_unchecked(vec![tx.clone()]);

    // Insert
    queries::insert_transactions(&mut conn, block_num, &ordered_tx).unwrap();

    // Retrieve
    let retrieved = queries::select_transactions_by_accounts_and_block_range(
        &mut conn,
        &[account_id],
        BlockNumber::GENESIS..=BlockNumber::from(2),
    )
    .unwrap();

    assert_eq!(retrieved.len(), 1, "Should have one transaction");
    let retrieved_tx = &retrieved[0];

    assert_eq!(
        tx.account_id(),
        retrieved_tx.account_id,
        "AccountId DB roundtrip must be symmetric"
    );
    assert_eq!(
        tx.id(),
        retrieved_tx.transaction_id,
        "TransactionId DB roundtrip must be symmetric"
    );
    assert_eq!(block_num, retrieved_tx.block_num, "Block number must match");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_roundtrip_vault_assets() {
    let mut conn = create_db();
    let block_num = BlockNumber::from(1);
    create_block(&mut conn, block_num);

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();

    // Create account first
    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 0)], block_num)
        .unwrap();

    let fungible_asset = FungibleAsset::new(faucet_id, 5000).unwrap();
    let asset: Asset = fungible_asset.into();
    let vault_key = asset.vault_key();

    // Insert vault asset
    queries::insert_account_vault_asset(&mut conn, account_id, block_num, vault_key, Some(asset))
        .unwrap();

    // Retrieve
    let (_, vault_assets) = queries::select_account_vault_assets(
        &mut conn,
        account_id,
        BlockNumber::GENESIS..=block_num,
    )
    .unwrap();

    assert_eq!(vault_assets.len(), 1, "Should have one vault asset");
    let retrieved = &vault_assets[0];

    assert_eq!(retrieved.asset, Some(asset), "Asset DB roundtrip must be symmetric");
    assert_eq!(retrieved.vault_key, vault_key, "VaultKey DB roundtrip must be symmetric");
    assert_eq!(retrieved.block_num, block_num, "Block number must match");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_roundtrip_storage_map_values() {
    let mut conn = create_db();
    let block_num = BlockNumber::from(1);
    create_block(&mut conn, block_num);

    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let slot_name = StorageSlotName::mock(5);
    let key = num_to_word(12345);
    let value = num_to_word(67890);

    // Insert
    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block_num,
        slot_name.clone(),
        key,
        value,
    )
    .unwrap();

    // Retrieve
    let page = queries::select_account_storage_map_values(
        &mut conn,
        account_id,
        BlockNumber::GENESIS..=block_num,
    )
    .unwrap();

    assert_eq!(page.values.len(), 1, "Should have one storage map value");
    let retrieved = &page.values[0];

    assert_eq!(retrieved.slot_name, slot_name, "StorageSlotName DB roundtrip must be symmetric");
    assert_eq!(retrieved.key, key, "Key (Word) DB roundtrip must be symmetric");
    assert_eq!(retrieved.value, value, "Value (Word) DB roundtrip must be symmetric");
    assert_eq!(retrieved.block_num, block_num, "Block number must match");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn db_roundtrip_account_storage_with_maps() {
    use miden_protocol::account::StorageMap;

    let mut conn = create_db();
    let block_num = BlockNumber::from(1);
    create_block(&mut conn, block_num);

    // Create storage with both value slots and map slots
    let storage_map = StorageMap::with_entries(vec![
        (
            Word::from([Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            Word::from([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]),
        ),
        (
            Word::from([Felt::new(2), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            Word::from([Felt::new(50), Felt::new(60), Felt::new(70), Felt::new(80)]),
        ),
    ])
    .unwrap();

    let component_storage = vec![
        StorageSlot::with_value(StorageSlotName::mock(0), num_to_word(42)),
        StorageSlot::with_map(StorageSlotName::mock(1), storage_map),
        StorageSlot::with_empty_value(StorageSlotName::mock(2)),
    ];

    let component_code = "pub proc foo push.1 end";
    let account_component_code = CodeBuilder::default()
        .compile_component_code("test::interface", component_code)
        .unwrap();
    let account_component = AccountComponent::new(account_component_code, component_storage)
        .unwrap()
        .with_supports_all_types();

    let account = AccountBuilder::new([50u8; 32])
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap();

    let account_id = account.id();
    let original_storage = account.storage().clone();
    let original_commitment = original_storage.to_commitment();

    // Insert the account (this should store header + map values separately)
    let account_delta = AccountDelta::try_from(account.clone()).unwrap();
    let block_update = BlockAccountUpdate::new(
        account_id,
        account.commitment(),
        AccountUpdateDetails::Delta(account_delta),
    );
    queries::upsert_accounts(&mut conn, &[block_update], block_num).unwrap();

    // Retrieve the storage using select_latest_account_storage (reconstructs from header + map
    // values)
    let retrieved_storage = queries::select_latest_account_storage(&mut conn, account_id).unwrap();
    let retrieved_commitment = retrieved_storage.to_commitment();

    // Verify the commitment matches (this proves the reconstruction is correct)
    assert_eq!(
        original_commitment, retrieved_commitment,
        "Storage commitment must match after DB roundtrip"
    );

    // Verify slot count matches
    assert_eq!(
        original_storage.slots().len(),
        retrieved_storage.slots().len(),
        "Number of slots must match"
    );

    // Verify each slot
    for (original_slot, retrieved_slot) in
        original_storage.slots().iter().zip(retrieved_storage.slots().iter())
    {
        assert_eq!(original_slot.name(), retrieved_slot.name(), "Slot names must match");
        assert_eq!(original_slot.slot_type(), retrieved_slot.slot_type(), "Slot types must match");

        match (original_slot.content(), retrieved_slot.content()) {
            (StorageSlotContent::Value(orig), StorageSlotContent::Value(retr)) => {
                assert_eq!(orig, retr, "Value slot contents must match");
            },
            (StorageSlotContent::Map(orig_map), StorageSlotContent::Map(retr_map)) => {
                assert_eq!(orig_map.root(), retr_map.root(), "Map slot roots must match");
                for (key, value) in orig_map.entries() {
                    let retrieved_value = retr_map.get(key);
                    assert_eq!(*value, retrieved_value, "Map entry for key {:?} must match", key);
                }
            },
            // The slot_type assertion above guarantees matching variants, so this is unreachable
            _ => unreachable!(),
        }
    }

    // Also verify full account reconstruction via select_account (which calls select_full_account)
    let account_info = queries::select_account(&mut conn, account_id).unwrap();
    assert!(account_info.details.is_some(), "Public account should have details");
    let retrieved_account = account_info.details.unwrap();
    assert_eq!(
        account.commitment(),
        retrieved_account.commitment(),
        "Full account commitment must match after DB roundtrip"
    );
}

#[test]
#[miden_node_test_macro::enable_logging]
fn test_note_metadata_with_attachment_roundtrip() {
    let mut conn = create_db();
    let block_num = BlockNumber::from(1);
    create_block(&mut conn, block_num);

    let (account_id, _) =
        make_account_and_note(&mut conn, block_num, [1u8; 32], AccountStorageMode::Network);

    let target = NetworkAccountTarget::new(account_id, NoteExecutionHint::Always)
        .expect("NetworkAccountTarget creation should succeed for network account");
    let attachment: NoteAttachment = target.into();

    // Create NoteMetadata with the attachment
    let metadata =
        NoteMetadata::new(account_id, NoteType::Public, NoteTag::with_account_target(account_id))
            .with_attachment(attachment.clone());

    let note = NoteRecord {
        block_num,
        note_index: BlockNoteIndex::new(0, 0).unwrap(),
        note_id: num_to_word(1),
        note_commitment: num_to_word(1),
        metadata: metadata.clone(),
        details: None,
        inclusion_path: SparseMerklePath::default(),
    };

    queries::insert_scripts(&mut conn, [&note]).unwrap();
    queries::insert_notes(&mut conn, &[(note.clone(), None)]).unwrap();

    // Fetch the note back and verify the attachment is preserved
    let retrieved = queries::select_notes_by_id(&mut conn, &[NoteId::from_raw(note.note_id)])
        .expect("select_notes_by_id should succeed");

    assert_eq!(retrieved.len(), 1, "Should retrieve exactly one note");

    let retrieved_metadata = &retrieved[0].metadata;
    assert_eq!(
        retrieved_metadata.attachment(),
        metadata.attachment(),
        "Attachment should be preserved after DB roundtrip"
    );

    let retrieved_target = NetworkAccountTarget::try_from(retrieved_metadata.attachment())
        .expect("Should be able to parse NetworkAccountTarget from retrieved attachment");
    assert_eq!(
        retrieved_target.target_id(),
        account_id,
        "NetworkAccountTarget should have the correct target account ID"
    );
}
