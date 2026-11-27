//! Transaction arguments of network transactions.

use miden_protocol::transaction::{IesSealSeed, TransactionArgs};
use miden_standards::tx_script::ExpirationTransactionScript;
use rand::{CryptoRng, Rng};

/// The [`TransactionArgs`] of one network transaction attempt.
///
/// They attach the canonical [`ExpirationTransactionScript`] with the `TX_SCRIPT_ARGS` word it
/// reads its expiration delta from, and a fresh [`IesSealSeed`] that answers the IES `seal`
/// requests of the account and note scripts.
///
/// A seal seed must not be shared by two published transactions, so every attempt builds its own
/// arguments and uses them for all of its consumability checks and its execution.
pub(crate) struct NetworkTxArgs(TransactionArgs);

impl NetworkTxArgs {
    /// Builds the arguments of one attempt with a seal seed drawn from `rng`.
    pub(crate) fn new<R: Rng + CryptoRng>(
        expiration: ExpirationTransactionScript,
        rng: &mut R,
    ) -> Self {
        let args = TransactionArgs::default()
            .with_tx_script_and_args(expiration.into(), expiration.tx_script_args())
            .with_ies_seal_seed(IesSealSeed::with_rng(rng));
        Self(args)
    }

    /// Returns the arguments for one execution within this attempt.
    ///
    /// The note consumability checker and the executor take the arguments by value, so every
    /// execution of the attempt receives its own copy of the same arguments.
    pub(crate) fn to_transaction_args(&self) -> TransactionArgs {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use miden_protocol::Felt;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;
    use rstest::rstest;

    use super::*;

    /// Every expiration delta resolves to the single script root that network accounts allowlist,
    /// and the delta travels in the first element of the script's args word.
    #[rstest]
    #[case::one(NonZeroU16::new(1).unwrap())]
    #[case::thirty(NonZeroU16::new(30).unwrap())]
    #[case::max(NonZeroU16::MAX)]
    fn expiration_script_shares_root_and_encodes_delta_in_args(#[case] delta: NonZeroU16) {
        let args = NetworkTxArgs::new(ExpirationTransactionScript::new(delta), &mut rand::rng())
            .to_transaction_args();

        assert_eq!(args.tx_script().unwrap().root(), ExpirationTransactionScript::script_root());
        assert_eq!(args.tx_script_args()[0], Felt::from(delta.get()));
    }

    /// Two attempts never share a seal seed, while executions within one attempt reuse it so that
    /// the consumability checks reproduce the execution.
    #[test]
    fn each_attempt_has_its_own_seal_seed() {
        let expiration = ExpirationTransactionScript::new(NonZeroU16::new(30).unwrap());
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let first = NetworkTxArgs::new(expiration, &mut rng);
        let second = NetworkTxArgs::new(expiration, &mut rng);

        let first_seed = first.to_transaction_args().ies_seal_seed().cloned();
        let second_seed = second.to_transaction_args().ies_seal_seed().cloned();

        assert!(first_seed.is_some(), "network transactions can answer seal requests");
        assert_ne!(first_seed, second_seed);
        assert_eq!(first.to_transaction_args().ies_seal_seed().cloned(), first_seed);
    }
}
