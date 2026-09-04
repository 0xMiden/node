//! State witness query.

use std::collections::BTreeMap;

use miden_protocol::account::AccountId;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::nullifier_tree::NullifierWitness;
use miden_protocol::note::Nullifier;

use super::StateView;

/// State witnesses for the requested accounts and nullifiers.
#[derive(Clone, Debug)]
pub struct StateWitnesses {
    pub account_witnesses: BTreeMap<AccountId, AccountWitness>,
    pub nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness>,
}

impl StateView {
    /// Returns state witnesses for the requested accounts and nullifiers.
    pub fn get_state_witnesses(
        &self,
        account_ids: &[AccountId],
        nullifiers: &[Nullifier],
    ) -> StateWitnesses {
        self.with_inner_read_blocking(|inner| {
            // Fetch witnesses for all accounts.
            let account_witnesses = account_ids
                .iter()
                .copied()
                .map(|account_id| (account_id, inner.account_tree.open_latest(account_id)))
                .collect::<BTreeMap<AccountId, AccountWitness>>();

            // Fetch all nullifier witnesses. Block proposal checks whether each nullifier is spent.
            let nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness> = nullifiers
                .iter()
                .copied()
                .map(|nullifier| (nullifier, inner.nullifier_tree.open(&nullifier)))
                .collect();

            StateWitnesses { account_witnesses, nullifier_witnesses }
        })
    }
}

#[cfg(test)]
mod tests {
    use miden_node_utils::fee::{test_fee_params, test_protocol_config};
    use miden_protocol::Word;
    use miden_protocol::block::ValidatorConfig;
    use miden_protocol::note::Nullifier;
    use miden_protocol::testing::random_secret_key::random_secret_key;

    use crate::GenesisState;
    use crate::state::State;

    #[tokio::test(flavor = "multi_thread")]
    async fn state_witnesses_include_requested_nullifiers() {
        let data_directory = tempfile::tempdir().expect("tempdir should be created");
        bootstrap_store(data_directory.path());
        let (state, _block_writer, _proof_writer) = State::for_tests(data_directory.path()).await;

        let nullifier = Nullifier::from_raw(Word::from([1_u32, 2, 3, 4]));
        let witnesses = state.view().get_state_witnesses(&[], &[nullifier]);

        assert!(witnesses.account_witnesses.is_empty());
        assert!(witnesses.nullifier_witnesses.contains_key(&nullifier));
    }

    fn bootstrap_store(path: &std::path::Path) {
        let signer = random_secret_key();
        let genesis_state = GenesisState::new(
            vec![],
            test_fee_params(),
            1,
            1,
            ValidatorConfig::new(vec![signer.public_key()], 1)
                .expect("validator config should be valid"),
            test_protocol_config(),
        );
        let genesis_block = genesis_state.into_block().expect("genesis block should be created");

        State::bootstrap(genesis_block, path).expect("store should bootstrap");
    }
}
