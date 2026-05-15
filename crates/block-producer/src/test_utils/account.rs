use std::collections::HashMap;
use std::sync::LazyLock;

use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use miden_protocol::{Hasher, Word};

pub static MOCK_ACCOUNTS: LazyLock<std::sync::Mutex<HashMap<u32, (AccountId, Word)>>> =
    LazyLock::new(Default::default);

/// A mock representation for private accounts. An account starts in state `states[0]`, is modified
/// to state `states[1]`, and so on.
#[derive(Clone, Copy, Debug)]
pub struct MockPrivateAccount<const NUM_STATES: usize = 3> {
    pub id: AccountId,

    // Sequence states that the account goes into.
    pub states: [Word; NUM_STATES],
}

impl<const NUM_STATES: usize> MockPrivateAccount<NUM_STATES> {
    fn new(id: AccountId, initial_state: Word) -> Self {
        let mut states = [Word::empty(); NUM_STATES];

        states[0] = initial_state;

        for idx in 1..NUM_STATES {
            states[idx] = Hasher::hash(&states[idx - 1].as_bytes());
        }

        Self { id, states }
    }

    fn generate(init_seed: [u8; 32], new_account: bool) -> Self {
        let account_seed = AccountId::compute_account_seed(
            init_seed,
            AccountType::RegularAccountUpdatableCode,
            AccountStorageMode::Private,
            AccountIdVersion::Version1,
            Word::empty(),
            Word::empty(),
        )
        .unwrap();

        Self::new(
            AccountId::new(account_seed, AccountIdVersion::Version1, Word::empty(), Word::empty())
                .unwrap(),
            if new_account {
                Word::empty()
            } else {
                Hasher::hash(&init_seed)
            },
        )
    }
}

impl<const NUM_STATES: usize> From<u32> for MockPrivateAccount<NUM_STATES> {
    /// Each index gives rise to a different account ID
    /// Passing index 0 signifies that it's a new account
    fn from(index: u32) -> Self {
        let mut lock = MOCK_ACCOUNTS.lock().expect("Poisoned mutex");
        if let Some(&(account_id, init_state)) = lock.get(&index) {
            return Self::new(account_id, init_state);
        }

        let init_seed: Vec<_> = index.to_be_bytes().into_iter().chain([0u8; 28]).collect();

        // using index 0 signifies that it's a new account
        let account = if index == 0 {
            Self::generate(init_seed.try_into().unwrap(), true)
        } else {
            Self::generate(init_seed.try_into().unwrap(), false)
        };

        lock.insert(index, (account.id, account.states[0]));

        account
    }
}

pub fn mock_account_id(num: u8) -> AccountId {
    MockPrivateAccount::<3>::from(u32::from(num)).id
}
