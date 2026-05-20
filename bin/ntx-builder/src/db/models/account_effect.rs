use miden_node_proto::domain::account::NetworkAccountId;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountDelta, AccountId};
use miden_standards::account::auth::NetworkAccountNoteAllowlist;

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
        match update {
            AccountUpdateDetails::Private => None,
            AccountUpdateDetails::Delta(update) if update.is_full_state() => {
                // Only treat full-state creations as network if the storage carries the
                // standardized `NetworkAccountNoteAllowlist` slot.
                let account = Account::try_from(update)
                    .expect("Account should be derivable by full state AccountDelta");
                if account.is_public()
                    && NetworkAccountNoteAllowlist::try_from(account.storage()).is_ok()
                {
                    Some(NetworkAccountEffect::Created(account))
                } else {
                    None
                }
            },
            AccountUpdateDetails::Delta(update) => {
                // Partial updates carry no storage we can inspect here. Forward them as updates
                // and let the coordinator's actor registry filter to known network accounts.
                Some(NetworkAccountEffect::Updated(update.clone()))
            },
        }
    }

    pub fn network_account_id(&self) -> NetworkAccountId {
        // Trusted: constructors only produce this enum for accounts already classified as
        // network (via the allowlist check above) or for updates that the caller filters
        // through the actor registry.
        NetworkAccountId::new_trusted(self.protocol_account_id())
    }

    fn protocol_account_id(&self) -> AccountId {
        match self {
            NetworkAccountEffect::Created(acc) => acc.id(),
            NetworkAccountEffect::Updated(delta) => delta.id(),
        }
    }
}
