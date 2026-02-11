use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountDelta, AccountId};

// NETWORK ACCOUNT EFFECT
// ================================================================================================

/// Represents the effect of a transaction on a network account.
#[derive(Clone)]
pub enum NetworkAccountEffect {
    Created(Account),
    Updated(AccountDelta),
}

impl NetworkAccountEffect {
    pub fn from_protocol(update: &AccountUpdateDetails) -> Option<Self> {
        let update = match update {
            AccountUpdateDetails::Private => return None,
            AccountUpdateDetails::Delta(update) if update.is_full_state() => {
                NetworkAccountEffect::Created(
                    Account::try_from(update)
                        .expect("Account should be derivable by full state AccountDelta"),
                )
            },
            AccountUpdateDetails::Delta(update) => NetworkAccountEffect::Updated(update.clone()),
        };

        update.protocol_account_id().is_network().then_some(update)
    }

    pub fn network_account_id(&self) -> NetworkAccountId {
        // SAFETY: This is a network account by construction.
        self.protocol_account_id().try_into().unwrap()
    }

    fn protocol_account_id(&self) -> AccountId {
        match self {
            NetworkAccountEffect::Created(acc) => acc.id(),
            NetworkAccountEffect::Updated(delta) => delta.id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::block::BlockNumber;

    #[rstest::rstest]
    #[test]
    #[case::all_zero(Some(BlockNumber::GENESIS), BlockNumber::GENESIS, 0, true)]
    #[case::no_attempts(None, BlockNumber::GENESIS, 0, true)]
    #[case::one_attempt(Some(BlockNumber::GENESIS), BlockNumber::from(2), 1, true)]
    #[case::three_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(3), 3, true)]
    #[case::ten_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(13), 10, true)]
    #[case::twenty_attempts(Some(BlockNumber::GENESIS), BlockNumber::from(149), 20, true)]
    #[case::one_attempt_false(Some(BlockNumber::GENESIS), BlockNumber::from(1), 1, false)]
    #[case::three_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(2), 3, false)]
    #[case::ten_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(12), 10, false)]
    #[case::twenty_attempts_false(Some(BlockNumber::GENESIS), BlockNumber::from(148), 20, false)]
    fn backoff_has_passed(
        #[case] last_attempt_block_num: Option<BlockNumber>,
        #[case] current_block_num: BlockNumber,
        #[case] attempt_count: usize,
        #[case] backoff_should_have_passed: bool,
    ) {
        use crate::actor::has_backoff_passed;

        assert_eq!(
            backoff_should_have_passed,
            has_backoff_passed(current_block_num, last_attempt_block_num, attempt_count)
        );
    }
}
