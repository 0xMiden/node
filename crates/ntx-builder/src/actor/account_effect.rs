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
