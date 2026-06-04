use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountDelta};
use miden_standards::account::auth::NetworkAccount;

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
                NetworkAccount::new(account)
                    .ok()
                    .map(|na| NetworkAccountEffect::Created(na.into_account()))
            },
            AccountUpdateDetails::Delta(update) => {
                // Partial updates carry no storage we can inspect here. Forward them as updates and
                // let the coordinator's actor registry filter to known network accounts.
                Some(NetworkAccountEffect::Updated(update.clone()))
            },
        }
    }
}
