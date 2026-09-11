use std::sync::Arc;

use miden_node_store::allowlist::AccountAllowlist;
use miden_node_tracing::error;
use miden_protocol::account::{Account, AccountUpdateDetails};
use miden_protocol::transaction::TxAccountUpdate;
use miden_standards::account::auth::NetworkAccount;
use tonic::Status;

use crate::LOG_TARGET;

/// Account creation policy shared by the public and internal sequencer APIs.
#[derive(Clone)]
pub struct AccountAdmission {
    pub(crate) allowlist: Arc<AccountAllowlist>,
    disabled: bool,
}

impl AccountAdmission {
    pub fn enabled(allowlist: Arc<AccountAllowlist>) -> Self {
        Self { allowlist, disabled: false }
    }

    pub fn disabled(allowlist: Arc<AccountAllowlist>) -> Self {
        Self { allowlist, disabled: true }
    }

    /// Rejects the submission if it creates an unregistered, non-network account.
    pub(crate) async fn check(&self, update: &TxAccountUpdate) -> tonic::Result<()> {
        if self.disabled || !update.initial_state_commitment().is_empty() {
            return Ok(());
        }

        // New public accounts include their full state. Use the store's network-account
        // classification rule before the account exists on chain.
        if let AccountUpdateDetails::Public(patch) = update.details() {
            let account = Account::try_from(patch)
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            if NetworkAccount::new(account).is_ok() {
                return Ok(());
            }
        }

        let account_id = update.account_id();
        let registered = self.allowlist.contains_account(account_id).await.map_err(|err| {
            error!(err, target: LOG_TARGET, "Account allowlist lookup failed");
            Status::internal("account allowlist lookup failed")
        })?;
        if !registered {
            return Err(Status::permission_denied(format!(
                "account {account_id} is not registered"
            )));
        }

        Ok(())
    }
}
