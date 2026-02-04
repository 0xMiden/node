#![allow(clippy::similar_names, reason = "naming dummy test values is hard")]
#![allow(clippy::too_many_lines, reason = "test code can be long")]

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use diesel::{Connection, SqliteConnection};
use miden_lib::account::auth::AuthRpoFalcon512;
use miden_lib::note::create_p2id_note;
use miden_lib::transaction::TransactionKernel;
use miden_node_proto::domain::account::AccountSummary;
use miden_node_utils::fee::test_fee_params;
use miden_objects::account::auth::PublicKeyCommitment;
use miden_objects::account::delta::AccountUpdateDetails;
use miden_objects::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountDelta,
    AccountId,
    AccountIdVersion,
    AccountStorageDelta,
    AccountStorageMode,
    AccountType,
    AccountVaultDelta,
    StorageSlot,
};
use miden_objects::asset::{Asset, AssetVaultKey, FungibleAsset};
use miden_objects::block::{
    BlockAccountUpdate,
    BlockHeader,
    BlockNoteIndex,
    BlockNoteTree,
    BlockNumber,
};
use miden_objects::crypto::merkle::SparseMerklePath;
use miden_objects::crypto::rand::RpoRandomCoin;
use miden_objects::note::{
    Note,
    NoteDetails,
    NoteExecutionHint,
    NoteHeader,
    NoteId,
    NoteMetadata,
    NoteTag,
    NoteType,
    Nullifier,
};
use miden_objects::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use miden_objects::transaction::{
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    TransactionHeader,
    TransactionId,
};
use miden_objects::{EMPTY_WORD, Felt, FieldElement, Word, ZERO};
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
        num_to_word(10),
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
        Felt::default(),
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
            metadata: *new_note.metadata(),
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
fn sql_select_notes_different_execution_hints() {
    let mut conn = create_db();
    let conn = &mut conn;

    let block_num = 1.into();
    create_block(conn, block_num);

    // test querying empty table
    let notes = queries::select_all_notes(conn).unwrap();
    assert!(notes.is_empty());

    let sender = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();

    queries::upsert_accounts(conn, &[mock_block_account_update(sender, 0)], block_num).unwrap();

    // test multiple entries
    let mut state = vec![];

    let new_note = create_note(sender);

    let note_none = NoteRecord {
        block_num,
        note_index: BlockNoteIndex::new(0, 0).unwrap(),
        note_id: num_to_word(0),
        note_commitment: num_to_word(0),
        metadata: NoteMetadata::new(
            sender,
            NoteType::Public,
            0.into(),
            NoteExecutionHint::none(),
            Felt::default(),
        )
        .unwrap(),
        details: Some(NoteDetails::from(&new_note)),
        inclusion_path: SparseMerklePath::default(),
    };
    state.push(note_none.clone());

    queries::insert_scripts(conn, [&note_none]).unwrap(); // only necessary for the first note
    let res = queries::insert_notes(conn, &[(note_none, None)]);
    assert_eq!(res.unwrap(), 1, "One element must have been inserted");

    let note = &queries::select_notes_by_id(conn, &[num_to_word(0).into()]).unwrap()[0];

    assert_eq!(note.metadata.execution_hint(), NoteExecutionHint::none());

    let note_always = NoteRecord {
        block_num,
        note_index: BlockNoteIndex::new(0, 1).unwrap(),
        note_id: num_to_word(1),
        note_commitment: num_to_word(1),
        metadata: NoteMetadata::new(
            sender,
            NoteType::Public,
            0.into(),
            NoteExecutionHint::always(),
            Felt::default(),
        )
        .unwrap(),
        details: Some(NoteDetails::from(&new_note)),
        inclusion_path: SparseMerklePath::default(),
    };
    state.push(note_always.clone());

    let res = queries::insert_notes(conn, &[(note_always, None)]);
    assert_eq!(res.unwrap(), 1, "One element must have been inserted");

    let note = &queries::select_notes_by_id(conn, &[num_to_word(1).into()]).unwrap()[0];
    assert_eq!(note.metadata.execution_hint(), NoteExecutionHint::always());

    let note_after_block = NoteRecord {
        block_num,
        note_index: BlockNoteIndex::new(0, 2).unwrap(),
        note_id: num_to_word(2),
        note_commitment: num_to_word(2),
        metadata: NoteMetadata::new(
            sender,
            NoteType::Public,
            2.into(),
            NoteExecutionHint::after_block(12.into()).unwrap(),
            Felt::default(),
        )
        .unwrap(),
        details: Some(NoteDetails::from(&new_note)),
        inclusion_path: SparseMerklePath::default(),
    };
    state.push(note_after_block.clone());

    let res = queries::insert_notes(conn, &[(note_after_block, None)]);
    assert_eq!(res.unwrap(), 1, "One element must have been inserted");
    let note = &queries::select_notes_by_id(conn, &[num_to_word(2).into()]).unwrap()[0];
    assert_eq!(
        note.metadata.execution_hint(),
        NoteExecutionHint::after_block(12.into()).unwrap()
    );
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
        metadata: *new_note.metadata(),
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
    // Number of notes to generate.
    const N: u64 = 32;

    let mut conn = create_db();
    let conn = &mut conn;

    let block_num = BlockNumber::from(1);
    // An arbitrary public account (network note tag requires public account).
    create_block(conn, block_num);

    let account_notes = [
        make_account_and_note(conn, block_num, [0u8; 32], AccountStorageMode::Public),
        make_account_and_note(conn, block_num, [1u8; 32], AccountStorageMode::Network),
    ];
    let network_account_id = account_notes[1].0;

    // Create some notes, of which half are network notes.
    let notes = (0..N)
        .map(|i| {
            let index = (i % 2) as usize;
            let is_network = account_notes[index].0.storage_mode() == AccountStorageMode::Network;
            let account_id = account_notes[index].0;
            let new_note = &account_notes[index].1;
            let note = NoteRecord {
                block_num,
                note_index: BlockNoteIndex::new(0, i as usize).unwrap(),
                note_id: num_to_word(i),
                note_commitment: num_to_word(i),
                metadata: NoteMetadata::new(
                    account_notes[index].0,
                    NoteType::Public,
                    NoteTag::from_account_id(account_id),
                    NoteExecutionHint::none(),
                    Felt::default(),
                )
                .unwrap(),
                details: is_network.then_some(NoteDetails::from(new_note)),
                inclusion_path: SparseMerklePath::default(),
            };

            (note, is_network.then_some(num_to_nullifier(i)))
        })
        .collect::<Vec<_>>();

    // Copy out all network notes to assert against. These will be in chronological order already.
    let network_notes = notes
        .iter()
        .filter_map(|(note, nullifier)| nullifier.is_some().then_some(note.clone()))
        .collect::<Vec<_>>();

    // Insert the set of notes.
    queries::insert_scripts(conn, notes.iter().map(|(note, _)| note)).unwrap();
    queries::insert_notes(conn, &notes).unwrap();

    // Fetch all network notes by setting a limit larger than the amount available.
    let (result, _) = queries::unconsumed_network_notes(
        conn,
        Page {
            token: None,
            size: NonZeroUsize::new(N as usize * 10).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(result, network_notes);
    let (result, _) = queries::select_unconsumed_network_notes_by_tag(
        conn,
        NoteTag::from_account_id(network_account_id).into(),
        block_num,
        Page {
            token: None,
            size: NonZeroUsize::new(N as usize * 10).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(result, network_notes);

    // Check pagination works as expected.
    let limit = 5;
    let mut page = Page {
        token: None,
        size: NonZeroUsize::new(limit).unwrap(),
    };
    network_notes.chunks(limit).for_each(|expected| {
        let (result, new_page) = queries::unconsumed_network_notes(conn, page).unwrap();
        page = new_page;
        assert_eq!(result, expected);
    });
    network_notes.chunks(limit).for_each(|expected| {
        let (result, new_page) = queries::select_unconsumed_network_notes_by_tag(
            conn,
            NoteTag::from_account_id(network_account_id).into(),
            block_num,
            page,
        )
        .unwrap();
        page = new_page;
        assert_eq!(result, expected);
    });
    assert!(page.token.is_none());

    // Consume every third network note and ensure these are now excluded from the results.
    let consumed = notes
        .iter()
        .filter_map(|(_, nullifier)| *nullifier)
        .step_by(3)
        .collect::<Vec<_>>();
    queries::insert_nullifiers_for_block(conn, &consumed, block_num).unwrap();

    let expected = network_notes
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 3 != 0)
        .map(|(_, note)| note.clone())
        .collect::<Vec<_>>();
    let page = Page {
        token: None,
        size: NonZeroUsize::new(N as usize * 10).unwrap(),
    };
    let (result, _) = queries::unconsumed_network_notes(conn, page).unwrap();
    assert_eq!(result, expected);
    let (result, _) = queries::select_unconsumed_network_notes_by_tag(
        conn,
        NoteTag::from_account_id(network_account_id).into(),
        block_num,
        page,
    )
    .unwrap();
    assert_eq!(result, expected);
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_unconsumed_network_notes_for_account() {
    let mut conn = create_db();

    // Create account.
    let account_note =
        make_account_and_note(&mut conn, 0.into(), [1u8; 32], AccountStorageMode::Network);

    // Create 2 blocks.
    create_block(&mut conn, 0.into());
    create_block(&mut conn, 1.into());

    // Create an unconsumed note in each block.
    let notes = (0..2)
        .map(|i: u32| {
            let note = NoteRecord {
                block_num: 0.into(), // Created on same block.
                note_index: BlockNoteIndex::new(0, i as usize).unwrap(),
                note_id: num_to_word(i.into()),
                note_commitment: num_to_word(i.into()),
                metadata: NoteMetadata::new(
                    account_note.0,
                    NoteType::Public,
                    NoteTag::from_account_id(account_note.0),
                    NoteExecutionHint::none(),
                    Felt::default(),
                )
                .unwrap(),
                details: None,
                inclusion_path: SparseMerklePath::default(),
            };
            (note, Some(num_to_nullifier(i.into())))
        })
        .collect::<Vec<_>>();
    queries::insert_scripts(&mut conn, notes.iter().map(|(note, _)| note)).unwrap();
    queries::insert_notes(&mut conn, &notes).unwrap();

    // Both notes are unconsumed, query should return both notes on both blocks.
    (0..2).for_each(|i: u32| {
        let (result, _) = queries::select_unconsumed_network_notes_by_tag(
            &mut conn,
            NoteTag::from_account_id(account_note.0).into(),
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
    let (result, _) = queries::select_unconsumed_network_notes_by_tag(
        &mut conn,
        NoteTag::from_account_id(account_note.0).into(),
        0.into(),
        Page {
            token: None,
            size: NonZeroUsize::new(10).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(result.len(), 2);

    // Query against second block should return only first note.
    let (result, _) = queries::select_unconsumed_network_notes_by_tag(
        &mut conn,
        NoteTag::from_account_id(account_note.0).into(),
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
        num_to_word(10),
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
        num_to_word(20),
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
    let note_metadata =
        NoteMetadata::new(sender, NoteType::Public, tag.into(), NoteExecutionHint::none(), ZERO)
            .unwrap();

    let values = [(note_index, new_note.id(), note_metadata)];
    let notes_db = BlockNoteTree::with_entries(values.iter().copied()).unwrap();
    let inclusion_path = notes_db.open(note_index);

    let note = NoteRecord {
        block_num: block_num_1,
        note_index,
        note_id: new_note.id().into(),
        note_commitment: new_note.commitment(),
        metadata: NoteMetadata::new(
            sender,
            NoteType::Public,
            tag.into(),
            NoteExecutionHint::none(),
            Felt::default(),
        )
        .unwrap(),
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
        note_id: new_note.id().into(),
        note_commitment: new_note.commitment(),
        metadata: note.metadata,
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

    let note_ids = Vec::from_iter(notes.iter().map(|note| NoteId::from(note.note_id)));

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
    for (slot, slot_delta) in delta.storage().maps() {
        for (k, v) in slot_delta.entries() {
            insert_account_storage_map_value(conn, account_id, block_number, *slot, *k.inner(), *v)
                .unwrap();
        }
    }
}

#[test]
#[miden_node_test_macro::enable_logging]
fn sql_account_storage_map_values_insertion() {
    use std::collections::BTreeMap;

    use miden_objects::account::StorageMapDelta;

    let mut conn = create_db();
    let conn = &mut conn;

    let block1: BlockNumber = 1.into();
    let block2: BlockNumber = 2.into();
    create_block(conn, block1);
    create_block(conn, block2);

    let account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();

    let slot = 3u8;
    let key1 = Word::from([1u32, 2, 3, 4]);
    let key2 = Word::from([5u32, 6, 7, 8]);
    let value1 = Word::from([10u32, 11, 12, 13]);
    let value2 = Word::from([20u32, 21, 22, 23]);
    let value3 = Word::from([30u32, 31, 32, 33]);

    // Insert at block 1
    let mut map1 = StorageMapDelta::default();
    map1.insert(key1, value1);
    map1.insert(key2, value2);
    let maps1: BTreeMap<_, _> = [(slot, map1)].into_iter().collect();
    let storage1 = AccountStorageDelta::from_parts(BTreeMap::new(), maps1).unwrap();
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
    let maps2 = BTreeMap::from_iter([(slot, map2)]);
    let storage2 = AccountStorageDelta::from_parts(BTreeMap::new(), maps2).unwrap();
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
            .any(|val| val.slot_index == slot && val.key == key1 && val.value == value3),
        "key1 should point to new value at block2"
    );
    assert!(
        storage_map_values
            .values
            .iter()
            .any(|val| val.slot_index == slot && val.key == key2 && val.value == value2),
        "key2 should stay the same (from block1)"
    );
}

#[test]
fn select_storage_map_sync_values() {
    let mut conn = create_db();
    let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let slot = 5u8;

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
    queries::insert_account_storage_map_value(&mut conn, account_id, block1, slot, key1, value1)
        .unwrap();
    queries::insert_account_storage_map_value(&mut conn, account_id, block1, slot, key2, value2)
        .unwrap();

    // Block 2: key2 -> value3 (update), key3 -> value3 (new)
    queries::insert_account_storage_map_value(&mut conn, account_id, block2, slot, key2, value3)
        .unwrap();
    queries::insert_account_storage_map_value(&mut conn, account_id, block2, slot, key3, value3)
        .unwrap();

    // Block 3: key1 -> value2 (update)
    queries::insert_account_storage_map_value(&mut conn, account_id, block3, slot, key1, value2)
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
            slot_index: slot,
            key: key2,
            value: value3,
            block_num: block2,
        },
        StorageMapValue {
            slot_index: slot,
            key: key3,
            value: value3,
            block_num: block2,
        },
        StorageMapValue {
            slot_index: slot,
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
    Nullifier::from(num_to_word(n))
}

fn mock_block_account_update(account_id: AccountId, num: u64) -> BlockAccountUpdate {
    BlockAccountUpdate::new(account_id, num_to_word(num), AccountUpdateDetails::Private)
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
        NoteMetadata::new(
            account_id,
            NoteType::Public,
            NoteTag::LocalAny(num as u32),
            NoteExecutionHint::None,
            Felt::default(),
        )
        .unwrap(),
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
    export.account_procedure_1
        push.1.2
        add
    end
    ";

    let component_storage = vec![
        StorageSlot::Value(Word::empty()),
        StorageSlot::Value(num_to_word(1)),
        StorageSlot::Value(Word::empty()),
        StorageSlot::Value(num_to_word(3)),
        StorageSlot::Value(Word::empty()),
        StorageSlot::Value(num_to_word(5)),
    ];

    let component = AccountComponent::compile(
        component_code,
        TransactionKernel::assembler(),
        component_storage,
    )
    .unwrap()
    .with_supported_type(account_type);

    AccountBuilder::new(init_seed.unwrap_or([0; 32]))
        .account_type(account_type)
        .storage_mode(storage_mode)
        .with_assets(assets)
        .with_component(component)
        .with_auth_component(AuthRpoFalcon512::new(PublicKeyCommitment::from(EMPTY_WORD)))
        .build_existing()
        .unwrap()
}
