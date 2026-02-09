use std::sync::Arc;

use miden_protocol::account::Account;
use miden_protocol::block::BlockHeader;
use miden_protocol::transaction::PartialBlockchain;

use crate::actor::inflight_note::InflightNetworkNote;

// TRANSACTION CANDIDATE
// ================================================================================================

/// A candidate network transaction.
///
/// Contains the data pertaining to a specific network account which can be used to build a network
/// transaction.
#[derive(Clone, Debug)]
pub struct TransactionCandidate {
    /// The current inflight state of the account.
    pub account: Account,

    /// A set of notes addressed to this network account.
    pub notes: Vec<InflightNetworkNote>,

    /// The latest locally committed block header.
    ///
    /// This should be used as the reference block during transaction execution.
    pub chain_tip_header: BlockHeader,

    /// The chain MMR, which lags behind the tip by one block.
    ///
    /// Wrapped in `Arc` to avoid expensive clones when reading the chain state.
    pub chain_mmr: Arc<PartialBlockchain>,
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use std::sync::{Arc, Mutex};

    use diesel::Connection;
    use miden_node_proto::domain::account::NetworkAccountId;
    use miden_node_proto::domain::note::SingleTargetNetworkNote;
    use miden_protocol::account::{Account, AccountBuilder, AccountStorageMode, AccountType};
    use miden_protocol::asset::{Asset, FungibleAsset};
    use miden_protocol::block::BlockNumber;
    use miden_protocol::crypto::rand::RpoRandomCoin;
    use miden_protocol::note::{Note, NoteAttachment, NoteExecutionHint, NoteType};
    use miden_protocol::testing::account_id::AccountIdBuilder;
    use miden_protocol::transaction::TransactionId;
    use miden_protocol::{EMPTY_WORD, Felt, Hasher};
    use miden_standards::note::{NetworkAccountTarget, create_p2id_note};

    use crate::db::Db;
    use crate::db::models::queries;

    // HELPERS
    // ============================================================================================

    /// Creates a network account for testing.
    fn create_network_account(seed: u8) -> Account {
        use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
        use miden_standards::account::wallets::BasicWallet;

        AccountBuilder::new([seed; 32])
            .account_type(AccountType::RegularAccountUpdatableCode)
            .storage_mode(AccountStorageMode::Network)
            .with_component(BasicWallet)
            .with_auth_component(NoopAuthComponent)
            .build_existing()
            .expect("should be able to build test account")
    }

    /// Creates a faucet account ID for testing.
    fn create_faucet_id(seed: u8) -> miden_protocol::account::AccountId {
        AccountIdBuilder::new()
            .account_type(AccountType::FungibleFaucet)
            .storage_mode(AccountStorageMode::Public)
            .build_with_seed([seed; 32])
    }

    /// Creates a note targeted at the given network account.
    fn create_network_note(
        target_account_id: miden_protocol::account::AccountId,
        seed: u8,
    ) -> Note {
        let coin_seed: [u64; 4] =
            [u64::from(seed), u64::from(seed) + 1, u64::from(seed) + 2, u64::from(seed) + 3];
        let rng = Arc::new(Mutex::new(RpoRandomCoin::new(coin_seed.map(Felt::new).into())));
        let mut rng = rng.lock().unwrap();

        let faucet_id = create_faucet_id(seed.wrapping_add(100));

        let target = NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
            .expect("NetworkAccountTarget creation should succeed for network account");
        let attachment: NoteAttachment = target.into();

        create_p2id_note(
            target_account_id,
            target_account_id,
            vec![Asset::Fungible(FungibleAsset::new(faucet_id, 10).unwrap())],
            NoteType::Public,
            attachment,
            &mut *rng,
        )
        .expect("note creation should succeed")
    }

    /// Creates a `SingleTargetNetworkNote` from a `Note`.
    fn to_single_target_note(note: Note) -> SingleTargetNetworkNote {
        SingleTargetNetworkNote::try_from(note).expect("should convert to SingleTargetNetworkNote")
    }

    /// Creates a mock `TransactionId` for testing.
    fn mock_tx_id(seed: u8) -> TransactionId {
        TransactionId::new(
            Hasher::hash(&[seed; 32]),
            Hasher::hash(&[seed.wrapping_add(1); 32]),
            EMPTY_WORD,
            EMPTY_WORD,
        )
    }

    /// Creates a mock `BlockHeader` for testing.
    fn mock_block_header(block_num: u32) -> miden_protocol::block::BlockHeader {
        use miden_node_utils::fee::test_fee_params;
        use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;

        miden_protocol::block::BlockHeader::new(
            0,
            EMPTY_WORD,
            BlockNumber::from(block_num),
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            SecretKey::new().public_key(),
            test_fee_params(),
            0,
        )
    }

    // TESTS
    // ============================================================================================

    /// Tests that committed notes can be loaded and queried from the DB.
    #[test]
    fn test_committed_notes_round_trip() {
        let mut conn = Db::test_conn();
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let note1 = to_single_target_note(create_network_note(account_id, 1));
        let note2 = to_single_target_note(create_network_note(account_id, 2));

        conn.transaction(|conn| {
            queries::upsert_committed_account(conn, &account)?;
            queries::insert_committed_notes(conn, network_account_id, &[note1, note2])?;
            Ok::<(), crate::db::errors::DatabaseError>(())
        })
        .expect("should insert account and notes");

        let available =
            queries::available_notes(&mut conn, network_account_id, BlockNumber::from(0), 30)
                .expect("should query available notes");

        assert_eq!(available.len(), 2, "should have 2 available notes");
    }

    /// Tests that `handle_transaction_added` properly nullifies notes.
    #[test]
    fn test_transaction_added_nullifies_notes() {
        let mut conn = Db::test_conn();
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let note1 = to_single_target_note(create_network_note(account_id, 1));
        let note2 = to_single_target_note(create_network_note(account_id, 2));
        let nullifier1 = note1.nullifier();

        conn.transaction(|conn| {
            queries::upsert_committed_account(conn, &account)?;
            queries::insert_committed_notes(conn, network_account_id, &[note1, note2])?;
            Ok::<(), crate::db::errors::DatabaseError>(())
        })
        .expect("should insert state");

        let tx_id = mock_tx_id(1);
        queries::handle_transaction_added(&mut conn, &tx_id, None, &[], &[nullifier1])
            .expect("should handle transaction added");

        let available =
            queries::available_notes(&mut conn, network_account_id, BlockNumber::from(0), 30)
                .expect("should query available notes");

        assert_eq!(available.len(), 1, "only one note should be available");
    }

    /// Tests that committing a transaction moves state appropriately.
    #[test]
    fn test_block_committed_removes_nullified_notes() {
        let mut conn = Db::test_conn();
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let note1 = to_single_target_note(create_network_note(account_id, 1));
        let nullifier1 = note1.nullifier();

        conn.transaction(|conn| {
            queries::upsert_committed_account(conn, &account)?;
            queries::insert_committed_notes(conn, network_account_id, &[note1])?;
            Ok::<(), crate::db::errors::DatabaseError>(())
        })
        .expect("should insert state");

        let tx_id = mock_tx_id(1);
        queries::handle_transaction_added(&mut conn, &tx_id, None, &[], &[nullifier1])
            .expect("should handle transaction added");

        let header = mock_block_header(1);
        queries::handle_block_committed(&mut conn, &[tx_id], BlockNumber::from(1), &header)
            .expect("should handle block committed");

        let available =
            queries::available_notes(&mut conn, network_account_id, BlockNumber::from(1), 30)
                .expect("should query available notes");

        assert!(available.is_empty(), "no notes should be available after commit");
    }

    /// Tests that reverting a transaction restores nullified notes.
    #[test]
    fn test_revert_restores_notes() {
        let mut conn = Db::test_conn();
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        let note1 = to_single_target_note(create_network_note(account_id, 1));
        let nullifier1 = note1.nullifier();

        conn.transaction(|conn| {
            queries::upsert_committed_account(conn, &account)?;
            queries::insert_committed_notes(conn, network_account_id, &[note1])?;
            Ok::<(), crate::db::errors::DatabaseError>(())
        })
        .expect("should insert state");

        let tx_id = mock_tx_id(1);
        queries::handle_transaction_added(&mut conn, &tx_id, None, &[], &[nullifier1])
            .expect("should handle transaction added");

        queries::handle_transactions_reverted(&mut conn, &[tx_id]).expect("should handle revert");

        let available =
            queries::available_notes(&mut conn, network_account_id, BlockNumber::from(0), 30)
                .expect("should query available notes");

        assert_eq!(available.len(), 1, "note should be available after revert");
    }

    /// Tests that dynamically added inflight notes are available.
    #[test]
    fn test_inflight_notes_are_available() {
        let mut conn = Db::test_conn();
        let account = create_network_account(1);
        let account_id = account.id();
        let network_account_id =
            NetworkAccountId::try_from(account_id).expect("should be a network account");

        queries::upsert_committed_account(&mut conn, &account).expect("should insert account");

        let new_note = to_single_target_note(create_network_note(account_id, 1));
        let tx_id = mock_tx_id(1);
        queries::handle_transaction_added(&mut conn, &tx_id, None, &[new_note], &[])
            .expect("should handle transaction added");

        let available =
            queries::available_notes(&mut conn, network_account_id, BlockNumber::from(0), 30)
                .expect("should query available notes");

        assert_eq!(available.len(), 1, "inflight note should be available");
    }
}
