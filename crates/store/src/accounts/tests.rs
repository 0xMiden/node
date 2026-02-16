//! Tests for `AccountTreeWithHistory`

#[cfg(test)]
#[expect(clippy::needless_range_loop)]
#[expect(clippy::uninlined_format_args)]
#[expect(clippy::cast_sign_loss)]
mod account_tree_with_history_tests {
    use miden_protocol::Word;
    use miden_protocol::account::AccountId;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::block::account_tree::{AccountTree, account_id_to_smt_key};
    use miden_protocol::crypto::merkle::smt::{LargeSmt, MemoryStorage};
    use miden_protocol::testing::account_id::AccountIdBuilder;

    use super::super::*;

    /// Helper function to create an `AccountTree` from entries using the new API
    fn create_account_tree(
        entries: impl IntoIterator<Item = (AccountId, Word)>,
    ) -> InMemoryAccountTree {
        let smt_entries = entries
            .into_iter()
            .map(|(id, commitment)| (account_id_to_smt_key(id), commitment));
        let smt = LargeSmt::with_entries(MemoryStorage::default(), smt_entries)
            .expect("Failed to create LargeSmt from entries");
        AccountTree::new(smt).expect("Failed to create AccountTree")
    }

    /// Helper function to verify a Merkle proof
    fn assert_verify(root: Word, witness: AccountWitness) {
        let proof = witness.into_proof();
        let (path, leaf) = proof.into_parts();
        path.verify(leaf.index().value(), leaf.hash(), &root).unwrap();
    }

    #[test]
    fn test_historical_queries() {
        let ids = [
            AccountIdBuilder::new().build_with_seed([1; 32]),
            AccountIdBuilder::new().build_with_seed([2; 32]),
            AccountIdBuilder::new().build_with_seed([3; 32]),
        ];

        let states = [
            vec![
                (ids[0], Word::from([1u32, 0, 0, 0])),
                (ids[1], Word::from([2u32, 0, 0, 0])),
                (ids[2], Word::from([3u32, 0, 0, 0])),
            ],
            vec![
                (ids[0], Word::from([10u32, 0, 0, 0])),
                (ids[1], Word::from([2u32, 0, 0, 0])),
                (ids[2], Word::from([30u32, 0, 0, 0])),
            ],
            vec![
                (ids[0], Word::from([10u32, 0, 0, 0])),
                (ids[1], Word::from([200u32, 0, 0, 0])),
                (ids[2], Word::from([30u32, 0, 0, 0])),
            ],
        ];

        let trees: Vec<_> = states.iter().map(|s| create_account_tree(s.clone())).collect();

        // Create a separate tree for history tracking
        let hist_tree = create_account_tree(states[0].clone());
        let mut hist = AccountTreeWithHistory::new(hist_tree, BlockNumber::GENESIS);
        hist.compute_and_apply_mutations([(ids[0], states[1][0].1), (ids[2], states[1][2].1)])
            .unwrap();
        hist.compute_and_apply_mutations([(ids[1], states[2][1].1)]).unwrap();

        for (block, tree) in trees.iter().enumerate() {
            let hist_root = hist.root_at(BlockNumber::from(block as u32)).unwrap();
            assert_eq!(hist_root, tree.root());

            for &id in &ids {
                let hist_witness = hist.open_at(id, BlockNumber::from(block as u32)).unwrap();
                let actual = tree.open(id);
                assert_eq!(hist_witness.state_commitment(), actual.state_commitment());
                assert_eq!(hist_witness.path(), actual.path());
            }
        }
    }

    #[test]
    fn test_history_limits() {
        const MAX_HIST: u32 = AccountTreeWithHistory::<MemoryStorage>::MAX_HISTORY as u32;
        use assert_matches::assert_matches;

        let id = AccountIdBuilder::new().build_with_seed([30; 32]);
        let tree = create_account_tree([(id, Word::from([1u32, 0, 0, 0]))]);
        let mut hist = AccountTreeWithHistory::new(tree, BlockNumber::GENESIS);

        for i in 1..=(MAX_HIST + 5) {
            hist.compute_and_apply_mutations([(id, Word::from([dbg!(i) as u32, 0, 0, 0]))])
                .unwrap();
            assert_eq!(hist.block_number_latest(), BlockNumber::from(i));
        }

        let current = hist.block_number_latest();
        assert_matches!(hist.open_at(id, current), Some(_));
        assert_matches!(hist.open_at(id, BlockNumber::GENESIS), None);
        assert_matches!(hist.open_at(id, current.child()), None);
    }

    #[test]
    fn test_account_lifecycle() {
        let id0 = AccountIdBuilder::new().build_with_seed([40; 32]);
        let id1 = AccountIdBuilder::new().build_with_seed([41; 32]);
        let v0 = Word::from([0u32; 4]);
        let v1 = Word::from([1u32; 4]);

        // Create separate trees for expected states at each block
        let tree0 = create_account_tree(vec![(id0, v0)]);
        let tree1 = create_account_tree(vec![(id0, v0), (id1, v1)]);
        let tree2 = create_account_tree(vec![(id0, Word::default()), (id1, v1)]);

        // Create separate tree for history tracking
        let hist_tree = create_account_tree(vec![(id0, v0)]);
        let mut hist = AccountTreeWithHistory::new(hist_tree, BlockNumber::GENESIS);
        hist.compute_and_apply_mutations([(id1, v1)]).unwrap();
        hist.compute_and_apply_mutations([(id0, Word::default())]).unwrap();

        assert_eq!(hist.block_number_latest(), BlockNumber::from(2));

        assert_verify(tree2.root(), tree2.open(id0));
        assert_verify(tree2.root(), hist.open_at(id0, BlockNumber::from(2)).unwrap());
        assert_verify(tree1.root(), tree1.open(id0));
        assert_verify(tree1.root(), hist.open_at(id0, BlockNumber::from(1)).unwrap());
        assert_verify(tree0.root(), tree0.open(id0));
        assert_verify(tree0.root(), hist.open_at(id0, BlockNumber::GENESIS).unwrap());

        assert_eq!(hist.open_at(id0, BlockNumber::GENESIS).unwrap(), tree0.open(id0));
        assert_eq!(hist.open_at(id0, BlockNumber::from(1)).unwrap(), tree1.open(id0));
        assert_eq!(hist.open_at(id0, BlockNumber::from(2)).unwrap(), tree2.open(id0));

        assert_eq!(hist.open_at(id1, BlockNumber::GENESIS).unwrap(), tree0.open(id1));
        assert_eq!(hist.open_at(id1, BlockNumber::from(1)).unwrap(), tree1.open(id1));
        assert_eq!(hist.open_at(id1, BlockNumber::from(2)).unwrap(), tree2.open(id1));

        assert_eq!(hist.open_at(id0, BlockNumber::GENESIS).unwrap().state_commitment(), v0);
        assert_eq!(hist.open_at(id0, BlockNumber::from(1)).unwrap().state_commitment(), v0);
        assert_eq!(hist.open_at(id1, BlockNumber::from(1)).unwrap().state_commitment(), v1);
        assert_eq!(
            hist.open_at(id0, BlockNumber::from(2)).unwrap().state_commitment(),
            Word::default()
        );
        assert_eq!(hist.open_at(id1, BlockNumber::from(2)).unwrap().state_commitment(), v1);
    }

    #[test]
    fn test_many_accounts_sequential_updates() {
        // Create 50 different account IDs
        let account_count = 50;
        let ids: Vec<_> = (0..account_count)
            .map(|i| AccountIdBuilder::new().build_with_seed([i as u8; 32]))
            .collect();

        // Create initial state with all accounts having value [i, 0, 0, 0]
        let initial_state: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, Word::from([i as u32, 0, 0, 0])))
            .collect();

        let initial_tree = create_account_tree(initial_state.clone());
        let mut hist = AccountTreeWithHistory::new(initial_tree, BlockNumber::GENESIS);

        // Apply 10 blocks of updates, each updating 5 accounts
        let num_blocks = 5;
        for block in 1..=num_blocks {
            let updates: Vec<_> = (0..5)
                .map(|i| {
                    let idx = ((block - 1) * 5 + i) % account_count;
                    let new_value = Word::from([idx as u32 + block as u32 * 100, 0, 0, 0]);
                    (ids[idx], new_value)
                })
                .collect();
            hist.compute_and_apply_mutations(updates).unwrap();
        }

        // Verify we can query historical states
        assert_eq!(hist.block_number_latest(), BlockNumber::from(num_blocks as u32));

        // Check genesis state for a few accounts
        for i in 0..4 {
            let witness = hist.open_at(ids[i], BlockNumber::GENESIS).unwrap();
            assert_eq!(
                witness.state_commitment(),
                Word::from([i as u32, 0, 0, 0]),
                "Account {} at genesis",
                i
            );
        }

        // Check intermediate block states
        for block in 1..=num_blocks {
            for i in 0..5 {
                let idx = ((block - 1) * 5 + i) % account_count;
                let witness = hist.open_at(ids[idx], BlockNumber::from(block as u32)).unwrap();
                let expected = Word::from([idx as u32 + block as u32 * 100, 0, 0, 0]);
                assert_eq!(
                    witness.state_commitment(),
                    expected,
                    "Account {} at block {}",
                    idx,
                    block
                );
            }
        }
    }

    #[test]
    fn test_many_accounts_concurrent_updates() {
        // Create 100 accounts
        let account_count = 100;
        let ids: Vec<_> = (0..account_count)
            .map(|i| {
                AccountIdBuilder::new().build_with_seed([
                    i as u8,
                    (i >> 8) as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
            })
            .collect();

        // Create initial state
        let initial_state: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, Word::from([i as u32, 0, 0, 0])))
            .collect();

        let initial_tree = create_account_tree(initial_state.clone());
        let mut hist = AccountTreeWithHistory::new(initial_tree, BlockNumber::GENESIS);

        // Apply updates to all accounts in each block
        let num_blocks = 5;
        for block in 1..=num_blocks {
            let updates: Vec<_> = ids
                .iter()
                .enumerate()
                .map(|(i, &id)| {
                    let new_value = Word::from([i as u32, block as u32, 0, 0]);
                    (id, new_value)
                })
                .collect();
            hist.compute_and_apply_mutations(updates).unwrap();
        }

        // Verify all accounts at all blocks
        for block in 0..=num_blocks {
            for (i, &id) in ids.iter().enumerate().take(20) {
                // Check first 20 for speed
                let witness = hist.open_at(id, BlockNumber::from(block as u32)).unwrap();
                let expected = if block == 0 {
                    Word::from([i as u32, 0, 0, 0])
                } else {
                    Word::from([i as u32, block as u32, 0, 0])
                };
                assert_eq!(
                    witness.state_commitment(),
                    expected,
                    "Account {} at block {}",
                    i,
                    block
                );
            }
        }
    }

    #[test]
    fn test_sparse_updates_many_accounts() {
        // Create 200 accounts but only update a few at a time
        let account_count = 200;
        let ids: Vec<_> = (0..account_count)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[1] = (i >> 8) as u8;
                AccountIdBuilder::new().build_with_seed(seed)
            })
            .collect();

        // Create initial state with first 50 accounts
        let initial_state: Vec<_> = ids
            .iter()
            .take(50)
            .enumerate()
            .map(|(i, &id)| (id, Word::from([i as u32, 0, 0, 0])))
            .collect();

        let initial_tree = create_account_tree(initial_state.clone());
        let mut hist = AccountTreeWithHistory::new(initial_tree, BlockNumber::GENESIS);

        // Block 1: Add 50 more accounts
        let updates1: Vec<_> = ids
            .iter()
            .skip(50)
            .take(50)
            .enumerate()
            .map(|(i, &id)| (id, Word::from([(i + 50) as u32, 1, 0, 0])))
            .collect();
        hist.compute_and_apply_mutations(updates1).unwrap();

        // Block 2: Update every 10th account
        let updates2: Vec<_> = ids
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 10 == 0)
            .take(10)
            .map(|(i, &id)| (id, Word::from([i as u32, 2, 0, 0])))
            .collect();
        hist.compute_and_apply_mutations(updates2).unwrap();

        // Block 3: Add remaining accounts
        let updates3: Vec<_> = ids
            .iter()
            .skip(100)
            .enumerate()
            .map(|(i, &id)| (id, Word::from([(i + 100) as u32, 3, 0, 0])))
            .collect();
        hist.compute_and_apply_mutations(updates3).unwrap();

        // Verify states at different blocks
        // Check genesis - first 50 accounts exist, others don't
        for i in 0..50 {
            let witness = hist.open_at(ids[i], BlockNumber::GENESIS).unwrap();
            assert_eq!(witness.state_commitment(), Word::from([i as u32, 0, 0, 0]));
        }

        // Check block 1 - first 100 accounts exist
        for i in 50..100 {
            let witness = hist.open_at(ids[i], BlockNumber::from(1)).unwrap();
            assert_eq!(witness.state_commitment(), Word::from([i as u32, 1, 0, 0]));
        }

        // Check block 2 - every 10th account was updated
        for i in 0..10 {
            let idx = i * 10;
            if idx < 100 {
                let witness = hist.open_at(ids[idx], BlockNumber::from(2)).unwrap();
                assert_eq!(witness.state_commitment(), Word::from([idx as u32, 2, 0, 0]));
            }
        }

        // Check block 3 - all 200 accounts should be accessible
        for i in [0, 50, 100, 150, 199] {
            let witness = hist.open_at(ids[i], BlockNumber::from(3));
            assert!(witness.is_some(), "Account {} should exist at block 3", i);
        }
    }

    #[test]
    fn test_account_deletion_and_recreation() {
        // Test accounts being removed (set to empty) and then recreated
        let ids: Vec<_> = (0..20)
            .map(|i| AccountIdBuilder::new().build_with_seed([i as u8 + 100; 32]))
            .collect();

        // Initial state: all accounts exist
        let initial_state: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, Word::from([i as u32 + 1, 0, 0, 0])))
            .collect();

        let initial_tree = create_account_tree(initial_state.clone());
        let mut hist = AccountTreeWithHistory::new(initial_tree, BlockNumber::GENESIS);

        // Block 1: Delete half the accounts (set to empty word)
        let deletes: Vec<_> = ids.iter().take(10).map(|&id| (id, Word::default())).collect();
        hist.compute_and_apply_mutations(deletes).unwrap();

        // Block 2: Recreate some deleted accounts with new values
        let recreates: Vec<_> =
            ids.iter().take(5).map(|&id| (id, Word::from([999u32, 0, 0, 0]))).collect();
        hist.compute_and_apply_mutations(recreates).unwrap();

        // Verify genesis state
        for (i, &id) in ids.iter().enumerate().take(20) {
            let witness = hist.open_at(id, BlockNumber::GENESIS).unwrap();
            assert_eq!(
                witness.state_commitment(),
                Word::from([i as u32 + 1, 0, 0, 0]),
                "Genesis state for account {}",
                i
            );
        }

        // Verify block 1 - first 10 are deleted
        for i in 0..10 {
            let witness = hist.open_at(ids[i], BlockNumber::from(1)).unwrap();
            assert_eq!(
                witness.state_commitment(),
                Word::default(),
                "Account {} should be deleted at block 1",
                i
            );
        }

        // Verify block 2 - first 5 are recreated
        for i in 0..5 {
            let witness = hist.open_at(ids[i], BlockNumber::from(2)).unwrap();
            assert_eq!(
                witness.state_commitment(),
                Word::from([999u32, 0, 0, 0]),
                "Account {} should be recreated at block 2",
                i
            );
        }

        // Accounts 5-9 should still be empty at block 2
        for i in 5..10 {
            let witness = hist.open_at(ids[i], BlockNumber::from(2)).unwrap();
            assert_eq!(
                witness.state_commitment(),
                Word::default(),
                "Account {} should still be empty at block 2",
                i
            );
        }

        // Accounts 10-19 should never have been deleted
        for i in 10..20 {
            let witness_b1 = hist.open_at(ids[i], BlockNumber::from(1)).unwrap();
            let witness_b2 = hist.open_at(ids[i], BlockNumber::from(2)).unwrap();
            assert_eq!(witness_b1.state_commitment(), Word::from([i as u32 + 1, 0, 0, 0]));
            assert_eq!(witness_b2.state_commitment(), Word::from([i as u32 + 1, 0, 0, 0]));
        }
    }

    #[test]
    fn test_account_tree_with_history_minimal_verify() {
        // Create a single account
        let account_id = AccountIdBuilder::new().build_with_seed([42; 32]);
        let genesis_commitment = Word::from([100u32, 200, 300, 400]);
        let updated_commitment = Word::from([999u32, 888, 777, 666]);

        // Create initial tree with the account
        let tree = create_account_tree(vec![(account_id, genesis_commitment)]);
        let mut hist = AccountTreeWithHistory::new(tree, BlockNumber::GENESIS);

        // Apply a mutation to update the account (moves to block 1)
        hist.compute_and_apply_mutations(vec![(account_id, updated_commitment)])
            .expect("Mutation should succeed");

        // Verify we're now at block 1
        assert_eq!(hist.block_number_latest(), BlockNumber::from(1));

        // Get witness for the account at genesis (tests historical reconstruction)
        let witness = hist
            .open_at(account_id, BlockNumber::GENESIS)
            .expect("Account should exist at genesis");

        // Verify the state commitment matches the genesis value (not the updated value)
        assert_eq!(witness.state_commitment(), genesis_commitment);

        // Get the proof and verify it against the genesis root
        let root = hist.root_at(BlockNumber::GENESIS).expect("Root should exist at genesis");
        let proof = witness.into_proof();
        let (path, leaf) = proof.into_parts();

        // Verify the Merkle proof - this tests the historical reconstruction code path
        path.verify(leaf.index().value(), leaf.hash(), &root)
            .expect("Proof verification should succeed");
    }

    #[test]
    fn test_account_tree_minimal_verify() {
        // Create a single account
        let account_id = AccountIdBuilder::new().build_with_seed([42; 32]);
        let state_commitment = Word::from([100u32, 200, 300, 400]);

        // Create tree with the account
        let tree = create_account_tree(vec![(account_id, state_commitment)]);

        // Get witness for the account
        let witness = tree.open(account_id);

        // Verify the state commitment matches
        assert_eq!(witness.state_commitment(), state_commitment);

        // Get the proof and verify it
        let root = tree.root();
        let proof = witness.into_proof();
        let (path, leaf) = proof.into_parts();

        // Verify the Merkle proof
        path.verify(leaf.index().value(), leaf.hash(), &root)
            .expect("Proof verification should succeed");
    }
}
