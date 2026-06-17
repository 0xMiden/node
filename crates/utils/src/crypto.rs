use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::{Felt, Word};
use rand::{Rng, RngCore};

/// Creates a new [`RandomCoin`] with random seed.
pub fn get_random_coin<T: Rng>(rng: &mut T) -> RandomCoin {
    let auth_seed: [u64; 4] = rng.random();
    let rng_seed = Word::from(auth_seed.map(Felt::new_unchecked));

    RandomCoin::new(rng_seed)
}

/// Draws a base field element, uniformly at random, from the provided random number generator.
///
/// Field elements are produced by rejection sampling over `[0, Felt::ORDER)`, yielding a uniform
/// distribution over the field. A single draw is rejected with probability about `2^-32`.
pub fn draw_felt<R: RngCore + ?Sized>(rng: &mut R) -> Felt {
    loop {
        let value = rng.next_u64();
        if value < Felt::ORDER {
            return Felt::new_unchecked(value);
        }
    }
}

/// Draws a [`Word`], uniformly at random, from the provided random number generator.
pub fn draw_word<R: RngCore + ?Sized>(rng: &mut R) -> Word {
    [draw_felt(rng), draw_felt(rng), draw_felt(rng), draw_felt(rng)].into()
}

/// Adapts any [`RngCore`] into a [`FeltRng`].
///
/// Protocol note-creation APIs are generic over [`FeltRng`], while these helpers draw randomness
/// through [`RngCore`]. This shim bridges the two at those call sites without constraining the
/// caller's RNG to be a [`FeltRng`].
#[derive(Debug, Clone)]
pub struct FeltRngAdapter<R>(R);

impl<R: RngCore> FeltRngAdapter<R> {
    /// Wraps the given [`RngCore`] so it can be used as a [`FeltRng`].
    pub fn new(rng: R) -> Self {
        Self(rng)
    }
}

impl<R: RngCore> RngCore for FeltRngAdapter<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
}

impl<R: RngCore> FeltRng for FeltRngAdapter<R> {
    fn draw_element(&mut self) -> Felt {
        draw_felt(&mut self.0)
    }

    fn draw_word(&mut self) -> Word {
        draw_word(&mut self.0)
    }
}
