use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::TransactionId;

mod proven_tx;

pub use proven_tx::MockProvenTxBuilder;

mod account;

pub use account::{MockPrivateAccount, mock_account_id};

pub mod batch;

pub mod note;

/// Generates random values for tests.
///
/// It prints its seed on construction which allows us to reproduce
/// test failures.
pub struct Random(RandomCoin);

impl Random {
    /// Creates a [Random] with a random seed. This seed is logged
    /// so that it is known for test failures.
    pub fn with_random_seed() -> Self {
        let seed: [u32; 4] = rand::random();

        println!("Random::with_random_seed: {seed:?}");

        Self(RandomCoin::new(Word::from(seed)))
    }

    pub fn draw_tx_id(&mut self) -> TransactionId {
        TransactionId::from_raw(self.0.draw_word())
    }

    pub fn draw_account_id(&mut self) -> AccountId {
        AccountIdBuilder::new().build_with_rng(&mut self.0)
    }

    pub fn draw_digest(&mut self) -> Word {
        self.0.draw_word()
    }
}
