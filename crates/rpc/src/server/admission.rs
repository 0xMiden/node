use std::sync::Arc;

use miden_node_proto::domain::account::InvitationCodeValidity;
use miden_node_store::DatabaseError;
use miden_node_store::allowlist::{AccountAllowlist, InvitationCode, InvitationStatus};
use miden_node_tracing::instrument_v2;
use miden_protocol::account::{AccountId, AccountUpdateDetails};
use miden_protocol::transaction::TxAccountUpdate;
use miden_standards::account::auth::NetworkAccount;
use tonic::Status;

use crate::FundingClient;
use crate::server::api::log_internal_error;

/// Account creation policy shared by the public and internal sequencer APIs.
#[derive(Clone)]
pub struct AccountAdmission {
    pub(crate) allowlist: Arc<AccountAllowlist>,
    pub(crate) funding: Option<FundingClient>,
    disabled: bool,
}

impl AccountAdmission {
    pub fn enabled(allowlist: Arc<AccountAllowlist>) -> Self {
        Self {
            allowlist,
            funding: None,
            disabled: false,
        }
    }

    pub fn disabled(allowlist: Arc<AccountAllowlist>) -> Self {
        Self { allowlist, funding: None, disabled: true }
    }

    pub(crate) fn is_disabled(&self) -> bool {
        self.disabled
    }

    #[must_use]
    pub fn with_funding_client(mut self, client: Option<FundingClient>) -> Self {
        self.funding = client;
        self
    }

    /// Returns true if enforcement is disabled or the account is allowlisted.
    pub(crate) async fn is_account_allowed(
        &self,
        account_id: AccountId,
    ) -> Result<bool, DatabaseError> {
        if self.disabled {
            return Ok(true);
        }
        self.allowlist.contains_account(account_id).await
    }

    /// Returns whether the invitation code can be used to register an account and the registered
    /// account ID if the code has already been used.
    ///
    /// Returns [`InvitationCodeValidity::Valid`] when account allowlist enforcement is disabled.
    pub(crate) async fn is_invitation_code_valid(
        &self,
        invitation_code: InvitationCode,
    ) -> Result<InvitationCodeValidity, DatabaseError> {
        if self.disabled {
            return Ok(InvitationCodeValidity::Valid);
        }
        let status = self.allowlist.invitation_status(invitation_code).await?;
        Ok(match status {
            InvitationStatus::Unknown => InvitationCodeValidity::Invalid,
            InvitationStatus::Unused => InvitationCodeValidity::Valid,
            InvitationStatus::Registered(account_id) => {
                InvitationCodeValidity::AlreadyUsed(account_id)
            },
        })
    }

    /// Rejects the submission if it creates an unregistered, non-network account.
    #[instrument_v2(
        name = "account_admission.check",
        fields(account.id = update.account_id()),
    )]
    pub(crate) async fn check(&self, update: &TxAccountUpdate) -> tonic::Result<()> {
        if self.disabled || !update.initial_state_commitment().is_empty() {
            return Ok(());
        }

        // New public accounts include their full state. Use the store's network-account
        // classification rule before the account exists on chain.
        if let AccountUpdateDetails::Public(patch) = update.details() {
            let account = patch
                .try_to_new_account()
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            if NetworkAccount::new(account).is_ok() {
                return Ok(());
            }
        }

        let account_id = update.account_id();
        let allowed = self
            .is_account_allowed(account_id)
            .await
            .map_err(|err| log_internal_error(&err))?;
        if !allowed {
            return Err(Status::permission_denied(format!(
                "account {account_id} is not registered"
            )));
        }

        Ok(())
    }
}
