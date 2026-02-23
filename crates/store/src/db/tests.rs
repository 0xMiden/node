#![allow(clippy::similar_names, reason = "naming dummy test values is hard")]
#![allow(clippy::too_many_lines, reason = "test code can be long")]

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use assert_matches::assert_matches;
use diesel::{Connection, SqliteConnection};
use miden_node_proto::domain::account::{AccountSummary, StorageMapEntries};
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
use miden_protocol::crypto::merkle::smt::SmtProof;
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
use tempfile::tempdir;

use super::{AccountInfo, NoteRecord, NullifierInfo};
use crate::db::TransactionSummary;
use crate::db::migrations::apply_migrations;
use crate::db::models::queries::{StorageMapValue, insert_account_storage_map_value};
use crate::db::models::{Page, queries, utils};
use crate::errors::DatabaseError;
use crate::inner_forest::HISTORICAL_BLOCK_RETENTION;

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

    conn.transaction(|conn| queries::insert_block_header(conn, &block_header))
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
            BlockNumber::from(0)..=BlockNumber::from(2),
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

    for block in [block_from, block_mid, block_to] {
        queries::upsert_accounts(conn, &[mock_block_account_update(public_account_id, 0)], block)
            .unwrap();
    }

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

    queries::insert_block_header(conn, &block_header).unwrap();

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

    queries::insert_block_header(conn, &block_header2).unwrap();

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
        BlockNumber::from(0)..=u32::MAX.into(),
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
        BlockNumber::from(0)..=u32::MAX.into(),
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

    let block_range = BlockNumber::from(0)..=BlockNumber::from(1);

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

    queries::upsert_accounts(conn, &[mock_block_account_update(account_id, 0)], block1).unwrap();
    queries::upsert_accounts(conn, &[mock_block_account_update(account_id, 0)], block2).unwrap();

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

    let storage_map_page = queries::select_account_storage_map_values_paged(
        conn,
        account_id,
        BlockNumber::GENESIS..=block1,
        1024,
    )
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

    let storage_map_values = queries::select_account_storage_map_values_paged(
        conn,
        account_id,
        BlockNumber::GENESIS..=block2,
        1024,
    )
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

    for block in [block1, block2, block3] {
        queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 0)], block)
            .unwrap();
    }

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

    let page = queries::select_account_storage_map_values_paged(
        &mut conn,
        account_id,
        BlockNumber::from(2)..=BlockNumber::from(3),
        1024,
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

#[test]
fn select_storage_map_sync_values_paginates_until_last_block() {
    let mut conn = create_db();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let slot_name = StorageSlotName::mock(7);

    let block1 = BlockNumber::from(1);
    let block2 = BlockNumber::from(2);
    let block3 = BlockNumber::from(3);

    create_block(&mut conn, block1);
    create_block(&mut conn, block2);
    create_block(&mut conn, block3);

    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 0)], block1)
        .unwrap();
    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 1)], block2)
        .unwrap();
    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 2)], block3)
        .unwrap();

    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block1,
        slot_name.clone(),
        num_to_word(1),
        num_to_word(11),
    )
    .unwrap();
    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block2,
        slot_name.clone(),
        num_to_word(2),
        num_to_word(22),
    )
    .unwrap();
    queries::insert_account_storage_map_value(
        &mut conn,
        account_id,
        block3,
        slot_name.clone(),
        num_to_word(3),
        num_to_word(33),
    )
    .unwrap();

    let page = queries::select_account_storage_map_values_paged(
        &mut conn,
        account_id,
        BlockNumber::GENESIS..=block3,
        1,
    )
    .unwrap();

    assert_eq!(page.last_block_included, block1, "should truncate at block 1");
    assert_eq!(page.values.len(), 1, "should include block 1 only");
}

#[tokio::test]
#[miden_node_test_macro::enable_logging]
async fn reconstruct_storage_map_from_db_pages_until_latest() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("store.sqlite");

    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let slot_name = StorageSlotName::mock(9);

    let block1 = BlockNumber::from(1);
    let block2 = BlockNumber::from(2);
    let block3 = BlockNumber::from(3);

    let db = crate::db::Db::load(db_path).await.unwrap();
    let slot_name_for_db = slot_name.clone();
    db.query("insert paged values", move |db_conn| {
        db_conn.transaction(|db_conn| {
            apply_migrations(db_conn)?;
            create_block(db_conn, block1);
            create_block(db_conn, block2);
            create_block(db_conn, block3);

            queries::upsert_accounts(db_conn, &[mock_block_account_update(account_id, 0)], block1)?;
            queries::upsert_accounts(db_conn, &[mock_block_account_update(account_id, 1)], block2)?;
            queries::upsert_accounts(db_conn, &[mock_block_account_update(account_id, 2)], block3)?;

            queries::insert_account_storage_map_value(
                db_conn,
                account_id,
                block1,
                slot_name_for_db.clone(),
                num_to_word(1),
                num_to_word(10),
            )?;
            queries::insert_account_storage_map_value(
                db_conn,
                account_id,
                block2,
                slot_name_for_db.clone(),
                num_to_word(2),
                num_to_word(20),
            )?;
            queries::insert_account_storage_map_value(
                db_conn,
                account_id,
                block3,
                slot_name_for_db.clone(),
                num_to_word(3),
                num_to_word(30),
            )?;
            Ok::<_, DatabaseError>(())
        })
    })
    .await
    .unwrap();

    let details = db
        .reconstruct_storage_map_from_db(account_id, slot_name.clone(), block3, Some(1))
        .await
        .unwrap();

    assert_matches!(details.entries, StorageMapEntries::AllEntries(entries) => {
        assert_eq!(entries.len(), 3);
    });
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
    queries::insert_block_header(&mut conn, &block_header).unwrap();

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
        BlockNumber::from(0)..=BlockNumber::from(2),
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
    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 0)], block_num)
        .unwrap();
    let slot_name = StorageSlotName::mock(5);
    let key = num_to_word(12345);
    let value = num_to_word(67890);

    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 1)], block_num)
        .unwrap();

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
    let page = queries::select_account_storage_map_values_paged(
        &mut conn,
        account_id,
        BlockNumber::GENESIS..=block_num,
        1024,
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
fn db_roundtrip_note_metadata_attachment() {
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

#[test]
#[miden_node_test_macro::enable_logging]
fn inner_forest_matches_db_storage_map_roots_across_updates() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};
    use miden_protocol::crypto::merkle::smt::Smt;

    use crate::inner_forest::InnerForest;

    /// Reconstructs storage map root from DB entries at a specific block.
    fn reconstruct_storage_map_root_from_db(
        conn: &mut SqliteConnection,
        account_id: AccountId,
        slot_name: &StorageSlotName,
        block_num: BlockNumber,
    ) -> Option<Word> {
        let storage_values = queries::select_account_storage_map_values_paged(
            conn,
            account_id,
            BlockNumber::GENESIS..=block_num,
            1024,
        )
        .unwrap();

        // Filter to the specific slot and get most recent value for each key
        let mut latest_values: BTreeMap<Word, Word> = BTreeMap::new();
        for value in storage_values.values {
            if value.slot_name == *slot_name {
                latest_values.insert(value.key, value.value);
            }
        }

        if latest_values.is_empty() {
            return None;
        }

        // Build SMT from entries
        let entries: Vec<(Word, Word)> = latest_values
            .into_iter()
            .filter_map(|(key, value)| {
                if value == EMPTY_WORD {
                    None
                } else {
                    // Keys are stored unhashed in DB, match InnerForest behavior
                    Some((key, value))
                }
            })
            .collect();

        if entries.is_empty() {
            use miden_protocol::crypto::merkle::EmptySubtreeRoots;
            use miden_protocol::crypto::merkle::smt::SMT_DEPTH;
            return Some(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));
        }

        let mut smt = Smt::default();
        for (key, value) in entries {
            smt.insert(miden_protocol::account::StorageMap::hash_key(key), value).unwrap();
        }

        Some(smt.root())
    }

    let mut conn = create_db();
    let mut forest = InnerForest::new();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();

    let block1 = BlockNumber::from(1);
    let block2 = BlockNumber::from(2);
    let block3 = BlockNumber::from(3);

    create_block(&mut conn, block1);
    create_block(&mut conn, block2);
    create_block(&mut conn, block3);

    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 0)], block1)
        .unwrap();
    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 1)], block2)
        .unwrap();
    queries::upsert_accounts(&mut conn, &[mock_block_account_update(account_id, 2)], block3)
        .unwrap();

    let slot_map = StorageSlotName::mock(1);
    let slot_value = StorageSlotName::mock(2);

    let key1 = num_to_word(100);
    let key2 = num_to_word(200);
    let value1 = num_to_word(1000);
    let value2 = num_to_word(2000);
    let value3 = num_to_word(3000);

    // Block 1: Add storage map entries and a storage value
    let mut map_delta_1 = StorageMapDelta::default();
    map_delta_1.insert(key1, value1);
    map_delta_1.insert(key2, value2);

    let raw_1 = BTreeMap::from_iter([
        (slot_map.clone(), StorageSlotDelta::Map(map_delta_1)),
        (slot_value.clone(), StorageSlotDelta::Value(value1)),
    ]);
    let storage_1 = AccountStorageDelta::from_raw(raw_1);
    let delta_1 =
        AccountDelta::new(account_id, storage_1.clone(), AccountVaultDelta::default(), Felt::ONE)
            .unwrap();

    insert_account_delta(&mut conn, account_id, block1, &delta_1);
    forest.update_account(block1, &delta_1).unwrap();

    // Verify forest matches DB for block 1
    let forest_root_1 = forest.get_storage_map_root(account_id, &slot_map, block1).unwrap();
    let db_root_1 = reconstruct_storage_map_root_from_db(&mut conn, account_id, &slot_map, block1)
        .expect("DB should have storage map root");

    assert_eq!(
        forest_root_1, db_root_1,
        "Storage map root at block 1 should match between InnerForest and DB"
    );

    // Block 2: Delete storage map entry (set to EMPTY_WORD) and delete storage value
    let mut map_delta_2 = StorageMapDelta::default();
    map_delta_2.insert(key1, EMPTY_WORD);

    let raw_2 = BTreeMap::from_iter([
        (slot_map.clone(), StorageSlotDelta::Map(map_delta_2)),
        (slot_value.clone(), StorageSlotDelta::Value(EMPTY_WORD)),
    ]);
    let storage_2 = AccountStorageDelta::from_raw(raw_2);
    let delta_2 = AccountDelta::new(
        account_id,
        storage_2.clone(),
        AccountVaultDelta::default(),
        Felt::new(2),
    )
    .unwrap();

    insert_account_delta(&mut conn, account_id, block2, &delta_2);
    forest.update_account(block2, &delta_2).unwrap();

    // Verify forest matches DB for block 2
    let forest_root_2 = forest.get_storage_map_root(account_id, &slot_map, block2).unwrap();
    let db_root_2 = reconstruct_storage_map_root_from_db(&mut conn, account_id, &slot_map, block2)
        .expect("DB should have storage map root");

    assert_eq!(
        forest_root_2, db_root_2,
        "Storage map root at block 2 should match between InnerForest and DB"
    );

    // Block 3: Re-add same value as block 1 and add different map entry
    let mut map_delta_3 = StorageMapDelta::default();
    map_delta_3.insert(key2, value3); // Update existing key

    let raw_3 = BTreeMap::from_iter([
        (slot_map.clone(), StorageSlotDelta::Map(map_delta_3)),
        (slot_value.clone(), StorageSlotDelta::Value(value1)), // Same as block 1
    ]);
    let storage_3 = AccountStorageDelta::from_raw(raw_3);
    let delta_3 = AccountDelta::new(
        account_id,
        storage_3.clone(),
        AccountVaultDelta::default(),
        Felt::new(3),
    )
    .unwrap();

    insert_account_delta(&mut conn, account_id, block3, &delta_3);
    forest.update_account(block3, &delta_3).unwrap();

    // Verify forest matches DB for block 3
    let forest_root_3 = forest.get_storage_map_root(account_id, &slot_map, block3).unwrap();
    let db_root_3 = reconstruct_storage_map_root_from_db(&mut conn, account_id, &slot_map, block3)
        .expect("DB should have storage map root");

    assert_eq!(
        forest_root_3, db_root_3,
        "Storage map root at block 3 should match between InnerForest and DB"
    );

    // Verify we can query historical roots
    let forest_root_1_check = forest.get_storage_map_root(account_id, &slot_map, block1).unwrap();
    let db_root_1_check =
        reconstruct_storage_map_root_from_db(&mut conn, account_id, &slot_map, block1)
            .expect("DB should have storage map root");
    assert_eq!(
        forest_root_1_check, db_root_1_check,
        "Historical query for block 1 should match"
    );

    // Verify roots are different across blocks (since we modified the map)
    assert_ne!(forest_root_1, forest_root_2, "Roots should differ after deletion");
    assert_ne!(forest_root_2, forest_root_3, "Roots should differ after modification");
}

#[test]
#[miden_node_test_macro::enable_logging]
fn inner_forest_shared_roots_not_deleted_prematurely() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
    };

    use crate::inner_forest::InnerForest;

    let mut forest = InnerForest::new();
    let account1 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let account2 = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();
    let account3 = AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE).unwrap();

    let block01 = BlockNumber::from(1);
    let block02 = BlockNumber::from(2);
    let block50 = BlockNumber::from(HISTORICAL_BLOCK_RETENTION);
    let block51 = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 1);
    let block52 = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 2);
    let block53 = BlockNumber::from(HISTORICAL_BLOCK_RETENTION + 3);
    let slot_name = StorageSlotName::mock(1);

    let key1 = num_to_word(100);
    let key2 = num_to_word(200);
    let value1 = num_to_word(1000);
    let value2 = num_to_word(2000);

    // All three accounts add identical storage maps at block 1
    let mut map_delta = StorageMapDelta::default();
    map_delta.insert(key1, value1);
    map_delta.insert(key2, value2);

    // Setups a single slot with a map and two key-value-pairs
    let raw = BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta.clone()))]);
    let storage = AccountStorageDelta::from_raw(raw);

    // Account 1
    let delta1 =
        AccountDelta::new(account1, storage.clone(), AccountVaultDelta::default(), Felt::ONE)
            .unwrap();
    forest.update_account(block01, &delta1).unwrap();

    // Account 2 (same storage)
    let delta2 =
        AccountDelta::new(account2, storage.clone(), AccountVaultDelta::default(), Felt::ONE)
            .unwrap();
    forest.update_account(block02, &delta2).unwrap();

    // Account 3 (same storage)
    let delta3 =
        AccountDelta::new(account3, storage.clone(), AccountVaultDelta::default(), Felt::ONE)
            .unwrap();
    forest.update_account(block02, &delta3).unwrap();

    // All three accounts should have the same root (structural sharing in SmtForest)
    let root1 = forest.get_storage_map_root(account1, &slot_name, block01).unwrap();
    let root2 = forest.get_storage_map_root(account2, &slot_name, block02).unwrap();
    let root3 = forest.get_storage_map_root(account3, &slot_name, block02).unwrap();

    // identical maps means identical roots
    assert_eq!(root1, root2);
    assert_eq!(root2, root3);

    // Verify we can get witnesses for all three accounts and verify them against roots
    let witness1 = forest
        .get_storage_map_witness(account1, &slot_name, block01, key1)
        .expect("Account1 should have accessible storage map");
    let witness2 = forest
        .get_storage_map_witness(account2, &slot_name, block02, key1)
        .expect("Account2 should have accessible storage map");
    let witness3 = forest
        .get_storage_map_witness(account3, &slot_name, block02, key1)
        .expect("Account3 should have accessible storage map");

    // Verify witnesses against storage map roots using SmtProof::compute_root
    let proof1: SmtProof = witness1.into();
    assert_eq!(proof1.compute_root(), root1, "Witness1 must verify against root1");

    let proof2: SmtProof = witness2.into();
    assert_eq!(proof2.compute_root(), root2, "Witness2 must verify against root2");

    let proof3: SmtProof = witness3.into();
    assert_eq!(proof3.compute_root(), root3, "Witness3 must verify against root3");

    let (_, storage_roots_removed) = forest.prune(block50);
    // nothing should be pruned yet, it's still in the window
    assert_eq!(storage_roots_removed, 0);

    // Update accounts 1,2,3
    let mut map_delta_update = StorageMapDelta::default();
    map_delta_update.insert(key1, num_to_word(1001)); // Slight change
    let raw_update =
        BTreeMap::from_iter([(slot_name.clone(), StorageSlotDelta::Map(map_delta_update))]);
    let storage_update = AccountStorageDelta::from_raw(raw_update);
    let delta2_update = AccountDelta::new(
        account2,
        storage_update.clone(),
        AccountVaultDelta::default(),
        Felt::new(2),
    )
    .unwrap();
    forest.update_account(block51, &delta2_update).unwrap();

    let delta3_update = AccountDelta::new(
        account3,
        storage_update.clone(),
        AccountVaultDelta::default(),
        Felt::new(2),
    )
    .unwrap();
    forest.update_account(block52, &delta3_update).unwrap();

    // Prune at block 52
    let (_, storage_roots_removed) = forest.prune(block52);
    // the root for  account01 is the most recent, which is the same as the other two, so nothing
    // should be pruned
    assert_eq!(storage_roots_removed, 0);

    // ensure the root is still accessible
    let account1_root_after_prune = forest.get_storage_map_root(account1, &slot_name, block01);
    assert!(account1_root_after_prune.is_some());

    let delta1_update =
        AccountDelta::new(account1, storage_update, AccountVaultDelta::default(), Felt::new(2))
            .unwrap();
    forest.update_account(block53, &delta1_update).unwrap();

    // Prune at block 53
    let (_, storage_roots_removed) = forest.prune(block53);
    // the roots from block01 and block02 are now all obsolete and should be pruned
    assert_eq!(storage_roots_removed, 0);

    // Account2 and Account3 should still be accessible at their recent blocks
    let account1_root = forest.get_storage_map_root(account1, &slot_name, block53).unwrap();
    let account2_root = forest.get_storage_map_root(account2, &slot_name, block51).unwrap();
    let account3_root = forest.get_storage_map_root(account3, &slot_name, block52).unwrap();

    // Verify we can still get witnesses for account2 and account3 and verify against roots
    let witness1_after = forest
        .get_storage_map_witness(account2, &slot_name, block51, key1)
        .expect("Account2 should still have accessible storage map after pruning account1");
    let witness2_after = forest
        .get_storage_map_witness(account3, &slot_name, block52, key1)
        .expect("Account3 should still have accessible storage map after pruning account1");

    // Verify witnesses against storage map roots
    let proof1: SmtProof = witness1_after.into();
    assert_eq!(proof1.compute_root(), account2_root,);
    let proof2: SmtProof = witness2_after.into();
    assert_eq!(proof2.compute_root(), account3_root,);
    let account1_witness = forest
        .get_storage_map_witness(account1, &slot_name, block53, key1)
        .expect("Account1 should still have accessible storage map after pruning");
    let account1_proof: SmtProof = account1_witness.into();
    assert_eq!(account1_proof.compute_root(), account1_root,);
}

#[test]
#[miden_node_test_macro::enable_logging]
fn inner_forest_retains_latest_after_100_blocks_and_pruning() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    use crate::inner_forest::{HISTORICAL_BLOCK_RETENTION, InnerForest};

    let mut forest = InnerForest::new();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    let slot_map = StorageSlotName::mock(1);

    let key1 = num_to_word(100);
    let key2 = num_to_word(200);
    let value1 = num_to_word(1000);
    let value2 = num_to_word(2000);

    // Block 1: Apply initial update with vault and storage
    let block_1 = BlockNumber::from(1);

    // Create storage map with two entries
    let mut map_delta = StorageMapDelta::default();
    map_delta.insert(key1, value1);
    map_delta.insert(key2, value2);

    let raw = BTreeMap::from_iter([(slot_map.clone(), StorageSlotDelta::Map(map_delta))]);
    let storage_delta = AccountStorageDelta::from_raw(raw);

    // Create vault with one asset
    let asset = FungibleAsset::new(faucet_id, 100).unwrap();
    let mut vault_delta = AccountVaultDelta::default();
    vault_delta.add_asset(asset.into()).unwrap();

    let delta_1 = AccountDelta::new(account_id, storage_delta, vault_delta, Felt::ONE).unwrap();

    forest.update_account(block_1, &delta_1).unwrap();

    // Capture the roots from block 1
    let initial_vault_root = forest.get_vault_root(account_id, block_1).unwrap();
    let initial_storage_map_root =
        forest.get_storage_map_root(account_id, &slot_map, block_1).unwrap();

    // Blocks 2-100: Do nothing (no updates to this account)
    // Simulate other activity by just advancing to block 100

    let block_100 = BlockNumber::from(100);

    assert!(forest.get_vault_root(account_id, block_100).is_some());
    assert_matches!(
        forest.get_storage_map_root(account_id, &slot_map, block_100),
        Some(root) if root == initial_storage_map_root
    );

    let (vault_roots_removed, storage_roots_removed) = forest.prune(block_100);

    let cutoff_block = 100 - HISTORICAL_BLOCK_RETENTION;
    assert_eq!(cutoff_block, 50, "Cutoff should be block 50 (100 - HISTORICAL_BLOCK_RETENTION)");
    assert_eq!(vault_roots_removed, 0);
    assert_eq!(storage_roots_removed, 0);

    assert!(forest.get_vault_root(account_id, block_100).is_some());
    assert_matches!(
        forest.get_storage_map_root(account_id, &slot_map, block_100),
        Some(root) if root == initial_storage_map_root
    );

    let witness = forest.get_storage_map_witness(account_id, &slot_map, block_100, key1);
    assert!(witness.is_ok());

    // Now add an update at block 51 (within retention window) to test that old entries
    // get pruned when newer entries exist
    let block_51 = BlockNumber::from(51);

    // Update with new values
    let value1_new = num_to_word(3000);
    let mut map_delta_51 = StorageMapDelta::default();
    map_delta_51.insert(key1, value1_new);

    let raw_51 = BTreeMap::from_iter([(slot_map.clone(), StorageSlotDelta::Map(map_delta_51))]);
    let storage_delta_51 = AccountStorageDelta::from_raw(raw_51);

    let asset_51 = FungibleAsset::new(faucet_id, 200).unwrap();
    let mut vault_delta_51 = AccountVaultDelta::default();
    vault_delta_51.add_asset(asset_51.into()).unwrap();

    let delta_51 =
        AccountDelta::new(account_id, storage_delta_51, vault_delta_51, Felt::new(51)).unwrap();

    forest.update_account(block_51, &delta_51).unwrap();

    // Prune again at block 100
    let (vault_roots_removed_2, storage_roots_removed_2) = forest.prune(block_100);

    assert_eq!(vault_roots_removed_2, 0);
    assert_eq!(storage_roots_removed_2, 0);

    let vault_root_at_51 = forest
        .get_vault_root(account_id, block_51)
        .expect("Should have vault root at block 51");
    let storage_root_at_51 = forest
        .get_storage_map_root(account_id, &slot_map, block_51)
        .expect("Should have storage root at block 51");

    assert_ne!(vault_root_at_51, initial_vault_root);

    let witness = forest
        .get_storage_map_witness(account_id, &slot_map, block_51, key1)
        .expect("Should be able to get witness for key1");

    let proof: SmtProof = witness.into();
    assert_eq!(proof.compute_root(), storage_root_at_51, "Witness must verify against storage root");

    let vault_root_at_1 = forest.get_vault_root(account_id, block_1);
    assert!(vault_root_at_1.is_some());
}

#[test]
#[miden_node_test_macro::enable_logging]
fn inner_forest_preserves_most_recent_vault_only() {
    use crate::inner_forest::InnerForest;

    let mut forest = InnerForest::new();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    // Block 1: Create vault with asset
    let block_1 = BlockNumber::from(1);
    let asset = FungibleAsset::new(faucet_id, 500).unwrap();
    let mut vault_delta = AccountVaultDelta::default();
    vault_delta.add_asset(asset.into()).unwrap();

    let delta_1 =
        AccountDelta::new(account_id, AccountStorageDelta::default(), vault_delta, Felt::ONE)
            .unwrap();

    forest.update_account(block_1, &delta_1).unwrap();

    let initial_vault_root = forest.get_vault_root(account_id, block_1).unwrap();

    // Advance 100 blocks without any updates
    let block_100 = BlockNumber::from(100);

    // Prune at block 100
    let (vault_roots_removed, storage_roots_removed) = forest.prune(block_100);

    // Vault from block 1 should NOT be pruned (it's the most recent)
    assert_eq!(
        vault_roots_removed, 0,
        "Should NOT prune vault root (it's the most recent for this account)"
    );
    assert_eq!(storage_roots_removed, 0, "No storage roots to prune");

    // Verify vault is still accessible at block 1
    let vault_root_at_1 = forest
        .get_vault_root(account_id, block_1)
        .expect("Should still have vault root at block 1");
    assert_eq!(vault_root_at_1, initial_vault_root, "Vault root should be preserved");

    // Verify we can get witnesses for the vault and verify against vault root
    let witnesses = forest
        .get_vault_asset_witnesses(
            account_id,
            block_1,
            [AssetVaultKey::new_unchecked(asset.vault_key().into())].into(),
        )
        .expect("Should be able to get vault witness after pruning");

    assert_eq!(witnesses.len(), 1, "Should have one witness");
    let witness = &witnesses[0];
    let proof: SmtProof = witness.clone().into();
    assert_eq!(
        proof.compute_root(),
        vault_root_at_1,
        "Vault witness must verify against vault root"
    );
}

#[test]
#[miden_node_test_macro::enable_logging]
fn inner_forest_preserves_most_recent_storage_map_only() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    use crate::inner_forest::InnerForest;

    let mut forest = InnerForest::new();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();

    let slot_map = StorageSlotName::mock(1);
    let key1 = num_to_word(100);
    let value1 = num_to_word(1000);

    // Block 1: Create storage map
    let block_1 = BlockNumber::from(1);
    let mut map_delta = StorageMapDelta::default();
    map_delta.insert(key1, value1);

    let raw = BTreeMap::from_iter([(slot_map.clone(), StorageSlotDelta::Map(map_delta))]);
    let storage_delta = AccountStorageDelta::from_raw(raw);

    let delta_1 =
        AccountDelta::new(account_id, storage_delta, AccountVaultDelta::default(), Felt::ONE)
            .unwrap();

    forest.update_account(block_1, &delta_1).unwrap();

    let initial_storage_root = forest.get_storage_map_root(account_id, &slot_map, block_1).unwrap();

    // Advance 100 blocks without any updates
    let block_100 = BlockNumber::from(100);

    // Prune at block 100
    let (vault_roots_removed, storage_roots_removed) = forest.prune(block_100);

    // Storage map from block 1 should NOT be pruned (it's the most recent)
    assert_eq!(vault_roots_removed, 0, "No vault roots to prune");
    assert_eq!(
        storage_roots_removed, 0,
        "Should NOT prune storage map root (it's the most recent for this account/slot)"
    );

    // Verify storage map is still accessible at block 1
    let storage_root_at_1 = forest
        .get_storage_map_root(account_id, &slot_map, block_1)
        .expect("Should still have storage root at block 1");
    assert_eq!(storage_root_at_1, initial_storage_root, "Storage root should be preserved");

    // Verify we can get witnesses for the storage map and verify against storage root
    let witness = forest
        .get_storage_map_witness(account_id, &slot_map, block_1, key1)
        .expect("Should be able to get storage witness after pruning");

    let proof: SmtProof = witness.into();
    assert_eq!(
        proof.compute_root(),
        storage_root_at_1,
        "Storage witness must verify against storage root"
    );

    // Verify we can get all entries
}

#[test]
#[miden_node_test_macro::enable_logging]
fn inner_forest_preserves_most_recent_storage_value_slot() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::StorageSlotDelta;

    use crate::inner_forest::InnerForest;

    let mut forest = InnerForest::new();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();

    let slot_value = StorageSlotName::mock(1);
    let value1 = num_to_word(5000);

    // Block 1: Create storage value slot
    let block_1 = BlockNumber::from(1);

    let raw = BTreeMap::from_iter([(slot_value.clone(), StorageSlotDelta::Value(value1))]);
    let storage_delta = AccountStorageDelta::from_raw(raw);

    let delta_1 =
        AccountDelta::new(account_id, storage_delta, AccountVaultDelta::default(), Felt::ONE)
            .unwrap();

    forest.update_account(block_1, &delta_1).unwrap();

    // Note: Value slots don't have roots in InnerForest - they're just part of the
    // account storage header. The InnerForest only tracks map slots.
    // So there's nothing to verify for value slots in the forest.

    // This test documents that value slots are NOT tracked in InnerForest
    // (they don't need to be, since their digest is 1:1 with the value)

    // Advance 100 blocks without any updates
    let block_100 = BlockNumber::from(100);

    // Prune at block 100
    let (vault_roots_removed, storage_roots_removed) = forest.prune(block_100);

    // No roots should be pruned because there are no map slots
    assert_eq!(vault_roots_removed, 0, "No vault roots in this test");
    assert_eq!(
        storage_roots_removed, 0,
        "Value slots don't create storage roots in InnerForest"
    );

    // Verify no storage map roots exist for this account
    let storage_root = forest.get_storage_map_root(account_id, &slot_value, block_1);
    assert!(
        storage_root.is_none(),
        "Value slots don't have storage map roots in InnerForest"
    );
}

#[test]
#[miden_node_test_macro::enable_logging]
fn inner_forest_preserves_mixed_slots_independently() {
    use std::collections::BTreeMap;

    use miden_protocol::account::delta::{StorageMapDelta, StorageSlotDelta};

    use crate::inner_forest::InnerForest;

    let mut forest = InnerForest::new();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    let slot_map_a = StorageSlotName::mock(1);
    let slot_map_b = StorageSlotName::mock(2);
    let slot_value = StorageSlotName::mock(3);

    let key1 = num_to_word(100);
    let value1 = num_to_word(1000);
    let value_slot_data = num_to_word(5000);

    // Block 1: Create vault + two map slots + one value slot
    let block_1 = BlockNumber::from(1);

    let asset = FungibleAsset::new(faucet_id, 100).unwrap();
    let mut vault_delta = AccountVaultDelta::default();
    vault_delta.add_asset(asset.into()).unwrap();

    let mut map_delta_a = StorageMapDelta::default();
    map_delta_a.insert(key1, value1);

    let mut map_delta_b = StorageMapDelta::default();
    map_delta_b.insert(key1, value1);

    let raw = BTreeMap::from_iter([
        (slot_map_a.clone(), StorageSlotDelta::Map(map_delta_a)),
        (slot_map_b.clone(), StorageSlotDelta::Map(map_delta_b)),
        (slot_value.clone(), StorageSlotDelta::Value(value_slot_data)),
    ]);
    let storage_delta = AccountStorageDelta::from_raw(raw);

    let delta_1 = AccountDelta::new(account_id, storage_delta, vault_delta, Felt::ONE).unwrap();

    forest.update_account(block_1, &delta_1).unwrap();

    let initial_vault_root = forest.get_vault_root(account_id, block_1).unwrap();
    let initial_map_a_root = forest.get_storage_map_root(account_id, &slot_map_a, block_1).unwrap();
    let initial_map_b_root = forest.get_storage_map_root(account_id, &slot_map_b, block_1).unwrap();

    // Block 51: Update only map_a (within retention window)
    let block_51 = BlockNumber::from(51);
    let value2 = num_to_word(2000);

    let mut map_delta_a_update = StorageMapDelta::default();
    map_delta_a_update.insert(key1, value2);

    let raw_51 =
        BTreeMap::from_iter([(slot_map_a.clone(), StorageSlotDelta::Map(map_delta_a_update))]);
    let storage_delta_51 = AccountStorageDelta::from_raw(raw_51);

    let delta_51 = AccountDelta::new(
        account_id,
        storage_delta_51,
        AccountVaultDelta::default(),
        Felt::new(51),
    )
    .unwrap();

    forest.update_account(block_51, &delta_51).unwrap();

    // Advance to block 100
    let block_100 = BlockNumber::from(100);

    // Prune at block 100
    let (vault_roots_removed, storage_roots_removed) = forest.prune(block_100);

    // Vault: block 1 is most recent, should NOT be pruned
    // Map A: block 1 is old (block 51 is newer), SHOULD be pruned
    // Map B: block 1 is most recent, should NOT be pruned
    assert_eq!(
        vault_roots_removed, 0,
        "Vault root from block 1 should NOT be pruned (most recent)"
    );
    assert_eq!(
        storage_roots_removed, 0,
        "Map A from block 1 should be pruned (block 51 is newer); Map B should NOT"
    );

    // Verify vault is still accessible
    let vault_root_at_1 = forest
        .get_vault_root(account_id, block_1)
        .expect("Vault should be accessible");
    assert_eq!(vault_root_at_1, initial_vault_root, "Vault should be from block 1");

    // Verify map_a is accessible (from block 51)
    let map_a_root_at_51 = forest
        .get_storage_map_root(account_id, &slot_map_a, block_51)
        .expect("Map A should be accessible");
    assert_ne!(
        map_a_root_at_51, initial_map_a_root,
        "Map A should be from block 51, not block 1"
    );

    // Verify map_b is still accessible (from block 1)
    let map_b_root_at_1 = forest
        .get_storage_map_root(account_id, &slot_map_b, block_1)
        .expect("Map B should be accessible");
    assert_eq!(
        map_b_root_at_1, initial_map_b_root,
        "Map B should still be from block 1 (most recent)"
    );

    // Verify map_a block 1 is no longer accessible
    let map_a_root_at_1 = forest.get_storage_map_root(account_id, &slot_map_a, block_1);
    assert!(map_a_root_at_1.is_some(), "Map A block 1 should be pruned");
}
