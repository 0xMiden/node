//! Small conversion helpers shared by the store's queries.

use miden_protocol::note::Nullifier;

/// Returns the high 16 bits of the provided nullifier.
pub fn get_nullifier_prefix(nullifier: &Nullifier) -> u16 {
    // The shift leaves exactly the 16 bits the prefix is defined as.
    (nullifier.most_significant_felt().as_canonical_u64() >> 48) as u16
}
