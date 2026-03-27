use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::{Felt, Word};
use rand::Rng;

/// Creates a new RPO Random Coin with random seed
pub fn get_rpo_random_coin<T: Rng>(rng: &mut T) -> RandomCoin {
    let auth_seed: [u64; 4] = rng.random();
    let rng_seed = Word::from(auth_seed.map(Felt::new));

    RandomCoin::new(rng_seed)
}
