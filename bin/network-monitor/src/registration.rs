//! Finite invitation-code budget for the monitor's submitted accounts.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::path::Path;

use anyhow::{Context, Result};
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::miden::node::v1::RegisterAccountRequest;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;

/// Fresh accounts and the signing key needed to submit wallet transactions.
pub struct MonitorAccountPair {
    pub wallet: Account,
    pub secret_key: SecretKey,
    pub counter: Account,
}

pub(crate) trait RegistrationRpc {
    fn register(
        &mut self,
        code: &str,
        account: AccountId,
    ) -> impl Future<Output = tonic::Result<()>> + Send;
}

/// Operator-supplied invitation codes and registration work retained across retries.
pub struct RegistrationPool {
    codes: VecDeque<String>,
    pending_accounts: Option<MonitorAccountPair>,
    pending_code: Option<String>,
}

impl RegistrationPool {
    /// Loads exact, case-sensitive invitation codes from a JSON array of strings.
    pub fn load(path: &Path) -> Result<Self> {
        let json =
            fs_err::read_to_string(path).context("failed to read registration codes file")?;
        Self::from_json(&json)
    }

    fn from_json(json: &str) -> Result<Self> {
        let codes: Vec<String> = serde_json::from_str(json).map_err(|error| {
            anyhow::anyhow!(
                "registration codes file must be a JSON array of strings (line {}, column {})",
                error.line(),
                error.column()
            )
        })?;
        anyhow::ensure!(
            codes.iter().all(|code| !code.is_empty()),
            "registration codes must not be empty"
        );
        let unique: HashSet<&str> = codes.iter().map(String::as_str).collect();
        anyhow::ensure!(unique.len() == codes.len(), "registration codes must be distinct");
        Ok(Self {
            codes: codes.into(),
            pending_accounts: None,
            pending_code: None,
        })
    }

    /// Registers the wallet, preserving the account pair and any unresolved code on failure.
    ///
    /// Retrying an unresolved registration directly is safe even if its previous response was
    /// lost. Unknown or consumed codes are skipped using the registration response.
    pub async fn register_accounts(
        &mut self,
        rpc: &mut impl RegistrationRpc,
        create: impl FnOnce() -> Result<MonitorAccountPair>,
    ) -> Result<MonitorAccountPair> {
        if self.pending_accounts.is_none() {
            self.pending_accounts = Some(create()?);
        }
        let accounts = self.pending_accounts.as_ref().expect("pending accounts exist");
        let wallet_id = accounts.wallet.id();
        self.register_one(rpc, wallet_id).await?;
        Ok(self.pending_accounts.take().expect("registered accounts exist"))
    }

    async fn register_one(
        &mut self,
        rpc: &mut impl RegistrationRpc,
        account: AccountId,
    ) -> Result<()> {
        loop {
            if self.pending_code.is_none() {
                self.pending_code = self.codes.pop_front();
            }
            let code = self
                .pending_code
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("registration code pool exhausted"))?;
            match rpc.register(code, account).await {
                Ok(()) => {
                    self.pending_code = None;
                    return Ok(());
                },
                Err(status)
                    if matches!(
                        status.code(),
                        tonic::Code::AlreadyExists | tonic::Code::NotFound
                    ) =>
                {
                    // Unknown codes and codes bound to other accounts cannot register this wallet.
                    self.pending_code = None;
                },
                Err(status) => {
                    return Err(status).context("account registration failed");
                },
            }
        }
    }
}

impl RegistrationRpc for RpcClient {
    async fn register(&mut self, code: &str, account: AccountId) -> tonic::Result<()> {
        self.register_account(RegisterAccountRequest {
            invitation_code: code.to_owned(),
            account_id: Some(account.into()),
        })
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::deploy::wallet::create_wallet_account;

    #[derive(Default)]
    struct Registry {
        codes: HashMap<String, Option<AccountId>>,
        lose_response: bool,
        fail_registration: bool,
        failure_message: Option<String>,
        requests: Vec<(String, AccountId)>,
    }

    impl Registry {
        fn with_codes(codes: &[&str]) -> Self {
            Self {
                codes: codes.iter().map(|code| ((*code).to_owned(), None)).collect(),
                ..Self::default()
            }
        }

        fn redeem(&mut self, code: &str, account: AccountId) -> tonic::Result<()> {
            self.requests.push((code.to_owned(), account));
            if let Some(message) = self.failure_message.take() {
                return Err(tonic::Status::unavailable(message));
            }
            if self.fail_registration {
                self.fail_registration = false;
                return Err(tonic::Status::unavailable("registration temporarily unavailable"));
            }
            let entry = self.codes.get_mut(code).ok_or(tonic::Status::not_found("unknown"))?;
            match entry {
                Some(existing) if *existing != account => {
                    return Err(tonic::Status::already_exists("consumed"));
                },
                _ => *entry = Some(account),
            }
            if self.lose_response {
                self.lose_response = false;
                return Err(tonic::Status::unavailable("lost registration response"));
            }
            Ok(())
        }
    }

    impl RegistrationRpc for Registry {
        fn register(
            &mut self,
            code: &str,
            account: AccountId,
        ) -> impl Future<Output = tonic::Result<()>> + Send {
            std::future::ready(self.redeem(code, account))
        }
    }

    fn pair() -> Result<MonitorAccountPair> {
        let (wallet, secret_key) = create_wallet_account()?;
        let (counter, _) = create_wallet_account()?;
        Ok(MonitorAccountPair { wallet, secret_key, counter })
    }

    /// Restarting from the same file must skip codes already bound in the server's registry.
    #[tokio::test]
    async fn skips_consumed_codes_and_exhausts_across_restarts() {
        let json = r#"["used", "wallet"]"#;
        let mut registry = Registry::with_codes(&["used", "wallet"]);
        registry.codes.insert("used".into(), Some(pair().unwrap().wallet.id()));
        let accounts = RegistrationPool::from_json(json)
            .unwrap()
            .register_accounts(&mut registry, pair)
            .await
            .unwrap();
        assert_eq!(registry.codes["wallet"], Some(accounts.wallet.id()));
        let error = RegistrationPool::from_json(json)
            .unwrap()
            .register_accounts(&mut registry, pair)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("exhausted"));
    }

    /// A committed registration with a lost response must retry its original account and code.
    #[tokio::test]
    async fn lost_response_retains_accounts_and_code() {
        let mut registry = Registry::with_codes(&["secret-wallet"]);
        registry.lose_response = true;
        let mut pool = RegistrationPool::from_json(r#"["secret-wallet"]"#).unwrap();
        assert!(pool.register_accounts(&mut registry, pair).await.is_err());
        let accounts = pool
            .register_accounts(&mut registry, || panic!("accounts regenerated"))
            .await
            .unwrap();
        assert_eq!(registry.requests[0], registry.requests[1]);
        assert_eq!(registry.codes["secret-wallet"], Some(accounts.wallet.id()));
        assert!(pool.register_accounts(&mut registry, pair).await.is_err());
    }

    /// Registration must work even when the optional validity endpoint is unavailable.
    #[tokio::test]
    async fn registration_does_not_require_validity_endpoint() {
        let mut registry = Registry::with_codes(&["wallet"]);
        let accounts = RegistrationPool::from_json(r#"["wallet"]"#)
            .unwrap()
            .register_accounts(&mut registry, pair)
            .await
            .unwrap();
        assert_eq!(registry.codes["wallet"], Some(accounts.wallet.id()));
    }

    /// A transient registration failure must retain the code and account for another attempt.
    #[tokio::test]
    async fn transient_registration_does_not_consume_a_code() {
        let mut registry = Registry::with_codes(&["a"]);
        registry.fail_registration = true;
        let mut pool = RegistrationPool::from_json(r#"["a"]"#).unwrap();
        assert!(pool.register_accounts(&mut registry, pair).await.is_err());
        let accounts = pool
            .register_accounts(&mut registry, || panic!("accounts regenerated"))
            .await
            .unwrap();
        assert_eq!(registry.codes["a"], Some(accounts.wallet.id()));
    }

    /// A fresh pair needs only its wallet registered; its network counter must not consume a code.
    #[tokio::test]
    async fn registers_only_the_wallet() {
        let mut registry = Registry::with_codes(&["wallet"]);
        let mut pool = RegistrationPool::from_json(r#"["wallet"]"#).unwrap();
        let accounts = pool.register_accounts(&mut registry, pair).await.unwrap();
        assert_eq!(registry.requests, vec![("wallet".into(), accounts.wallet.id())]);
        assert_ne!(accounts.wallet.id(), accounts.counter.id());
    }

    /// Unknown codes and codes belonging to other accounts must be skipped without changing the
    /// wallet being registered.
    #[tokio::test]
    async fn unavailable_codes_advance_to_an_unused_code() {
        let mut registry = Registry::with_codes(&["consumed", "wallet"]);
        let competitor = pair().unwrap().wallet.id();
        registry.codes.insert("consumed".into(), Some(competitor));
        let mut pool = RegistrationPool::from_json(r#"["unknown", "consumed", "wallet"]"#).unwrap();
        let accounts = pool.register_accounts(&mut registry, pair).await.unwrap();
        assert_eq!(registry.codes["consumed"], Some(competitor));
        assert_eq!(registry.codes["wallet"], Some(accounts.wallet.id()));
        assert_eq!(
            registry.requests,
            vec![
                ("unknown".into(), accounts.wallet.id()),
                ("consumed".into(), accounts.wallet.id()),
                ("wallet".into(), accounts.wallet.id()),
            ]
        );
    }

    /// Repeated deployments share one budget and preserve exact code text, including whitespace.
    #[tokio::test]
    async fn successive_pairs_share_the_budget() {
        let mut registry = Registry::with_codes(&[" Wallet ", "wallet"]);
        let mut pool = RegistrationPool::from_json(r#"[" Wallet ", "wallet"]"#).unwrap();
        let first = pool.register_accounts(&mut registry, pair).await.unwrap();
        let second = pool.register_accounts(&mut registry, pair).await.unwrap();
        assert_ne!(first.wallet.id(), second.wallet.id());
        assert_eq!(registry.codes[" Wallet "], Some(first.wallet.id()));
        assert_eq!(registry.codes["wallet"], Some(second.wallet.id()));
        assert!(
            pool.register_accounts(&mut registry, pair)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("exhausted")
        );
    }

    /// An empty pool must fail explicitly rather than allow an unregistered deployment.
    #[tokio::test]
    async fn empty_pool_reports_exhaustion() {
        let error = RegistrationPool::from_json("[]")
            .unwrap()
            .register_accounts(&mut Registry::default(), pair)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("exhausted"));
    }

    /// Registration failures retain the server's explanation even when an invitation code happens
    /// to match part of an ordinary diagnostic word.
    #[tokio::test]
    async fn registration_diagnostics_preserve_server_message() {
        let mut registry = Registry::with_codes(&["fund"]);
        let mut pool = RegistrationPool::from_json(r#"["fund"]"#).unwrap();
        registry.failure_message = Some("funding service unavailable".into());
        let error = pool.register_accounts(&mut registry, pair).await.err().unwrap();
        assert!(format!("{error:#}").contains("funding service unavailable"));
    }

    /// Invalid JSON diagnostics should identify the location without echoing the code text.
    #[test]
    fn malformed_json_diagnostic_includes_location_without_input() {
        let error = RegistrationPool::from_json("[\"secret\", 3]").err().unwrap();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("line 1"));
        assert!(diagnostic.contains("column"));
        assert!(!diagnostic.contains("secret"));
    }

    /// File-read failures must retain the operating system error for diagnosis.
    #[test]
    fn unreadable_file_preserves_io_error() {
        let error = RegistrationPool::load(Path::new("/nonexistent/monitor-codes.json"))
            .err()
            .unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    /// Invalid files must produce useful diagnostics without echoing secret input.
    #[test]
    fn rejects_empty_duplicate_and_malformed_codes() {
        for json in [r#"[""]"#, r#"["secret", "secret"]"#, r#"["secret", 3]"#, "secret"] {
            let error = RegistrationPool::from_json(json).err().unwrap();
            assert!(!format!("{error:#}").contains("secret"));
        }
    }
}
