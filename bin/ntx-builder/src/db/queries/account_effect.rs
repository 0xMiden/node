use miden_protocol::account::{Account, AccountPatch, AccountUpdateDetails};
use miden_standards::account::auth::NetworkAccount;

// NETWORK ACCOUNT EFFECT
// ================================================================================================

/// Represents the effect of a transaction on a network account.
///
/// The caller must know from the block if the account is new and select the constructor that matches.
#[derive(Debug, Clone)]
pub enum NetworkAccountEffect {
    Created(Account),
    Updated(AccountPatch),
}

impl NetworkAccountEffect {
    /// Returns the effect of an update that creates an account, or `None` if the new account is
    /// private or is not a network account.
    ///
    /// # Panics
    ///
    /// **WARNING**: Panics if the patch cannot be converted into a new account. Only pass the
    /// update of an account that a committed block creates. The update of an existing account,
    /// including a code upgrade, can panic or produce an incorrect account.
    pub fn from_account_creation(update: &AccountUpdateDetails) -> Option<Self> {
        match update {
            AccountUpdateDetails::Private => None,
            AccountUpdateDetails::Public(patch) => {
                // Only treat creations as network if the storage carries the standardized
                // `NetworkAccountNoteAllowlist` slot.
                let account = patch
                    .try_to_new_account()
                    .expect("the patch of a committed account creation should build an account");
                NetworkAccount::new(account)
                    .ok()
                    .map(|network_account| Self::Created(network_account.into_account()))
            },
        }
    }

    /// Returns the effect of an update to an existing account, or `None` if the account is private.
    pub fn from_account_update(update: &AccountUpdateDetails) -> Option<Self> {
        match update {
            AccountUpdateDetails::Private => None,
            AccountUpdateDetails::Public(patch) => {
                // Updates carry no storage we can inspect here. Forward them as updates;
                // `apply_committed_block` drops the ones whose account is not tracked locally.
                Some(Self::Updated(patch.clone()))
            },
        }
    }
}
