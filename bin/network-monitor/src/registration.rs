//! Finite invitation-code budget for the monitor's submitted accounts.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::path::Path;

use anyhow::Result;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::miden::node::v1::{
    IsInvitationCodeValidRequest,
    RegisterAccountRequest,
};
use miden_protocol::account::{Account, AccountId};
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;

/// Fresh accounts and the signing key needed to submit wallet transactions.
pub struct MonitorAccountPair {
    pub wallet: Account,
    pub secret_key: SecretKey,
    pub counter: Account,
}

pub(crate) trait RegistrationRpc {
    fn code_valid(&mut self, code: &str) -> impl Future<Output = tonic::Result<bool>> + Send;
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
    wallet_registered: bool,
    pending_code: Option<String>,
}

impl RegistrationPool {
    /// Loads exact, case-sensitive invitation codes from a JSON array of strings.
    pub fn load(path: &Path) -> Result<Self> {
        let json = fs_err::read_to_string(path)
            .map_err(|_| anyhow::anyhow!("failed to read registration codes file"))?;
        Self::from_json(&json)
    }

    fn from_json(json: &str) -> Result<Self> {
        let codes: Vec<String> = serde_json::from_str(json).map_err(|_| {
            anyhow::anyhow!("registration codes file must be a JSON array of strings")
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
            wallet_registered: false,
            pending_code: None,
        })
    }

    /// Registers both accounts, preserving their identities and any unresolved code on failure.
    ///
    /// Retrying an unresolved registration directly is safe even if its previous response was
    /// lost. A validity lookup would incorrectly discard a code consumed by that request.
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
        let counter_id = accounts.counter.id();
        if !self.wallet_registered {
            self.register_one(rpc, wallet_id).await?;
            self.wallet_registered = true;
        }
        self.register_one(rpc, counter_id).await?;
        self.wallet_registered = false;
        Ok(self.pending_accounts.take().expect("registered accounts exist"))
    }

    async fn register_one(
        &mut self,
        rpc: &mut impl RegistrationRpc,
        account: AccountId,
    ) -> Result<()> {
        loop {
            if self.pending_code.is_none() {
                let code = self
                    .codes
                    .front()
                    .ok_or_else(|| anyhow::anyhow!("registration code pool exhausted"))?;
                let valid = rpc.code_valid(code).await.map_err(|status| {
                    anyhow::anyhow!("registration code lookup failed ({})", status.code())
                })?;
                if !valid {
                    self.codes.pop_front();
                    continue;
                }
                self.pending_code = self.codes.pop_front();
            }
            let code = self.pending_code.as_ref().expect("registration code selected");
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
                    // Another client may have redeemed the code after the validity check.
                    self.pending_code = None;
                },
                Err(status) => {
                    // Server error messages can contain secrets; expose only the status code.
                    anyhow::bail!("account registration failed ({})", status.code());
                },
            }
        }
    }
}

impl RegistrationRpc for RpcClient {
    async fn code_valid(&mut self, code: &str) -> tonic::Result<bool> {
        Ok(self
            .is_invitation_code_valid(IsInvitationCodeValidRequest {
                invitation_code: code.to_owned(),
            })
            .await?
            .into_inner()
            .valid)
    }

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
        lose_counter_response: bool,
        raced_account: Option<AccountId>,
        fail_lookup: bool,
        requests: Vec<(String, AccountId)>,
    }

    impl Registry {
        fn with_codes(codes: &[&str]) -> Self {
            Self {
                codes: codes.iter().map(|code| ((*code).to_owned(), None)).collect(),
                ..Self::default()
            }
        }

        fn lookup(&mut self, code: &str) -> tonic::Result<bool> {
            if self.fail_lookup {
                self.fail_lookup = false;
                return Err(tonic::Status::unavailable("lookup failed"));
            }
            let valid = self.codes.get(code).is_some_and(Option::is_none);
            if code == "raced"
                && let Some(account) = self.raced_account.take()
            {
                self.codes.insert(code.to_owned(), Some(account));
            }
            Ok(valid)
        }

        fn redeem(&mut self, code: &str, account: AccountId) -> tonic::Result<()> {
            self.requests.push((code.to_owned(), account));
            let entry = self.codes.get_mut(code).ok_or(tonic::Status::not_found("unknown"))?;
            match entry {
                Some(existing) if *existing != account => {
                    return Err(tonic::Status::already_exists("consumed"));
                },
                _ => *entry = Some(account),
            }
            if self.lose_response || (self.lose_counter_response && code == "counter") {
                self.lose_response = false;
                self.lose_counter_response = false;
                return Err(tonic::Status::unavailable(format!("lost response for {code}")));
            }
            Ok(())
        }
    }

    impl RegistrationRpc for Registry {
        fn code_valid(&mut self, code: &str) -> impl Future<Output = tonic::Result<bool>> + Send {
            std::future::ready(self.lookup(code))
        }

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
        let json = r#"["used", "wallet", "counter"]"#;
        let mut registry = Registry::with_codes(&["used", "wallet", "counter"]);
        registry.codes.insert("used".into(), Some(pair().unwrap().wallet.id()));
        let accounts = RegistrationPool::from_json(json)
            .unwrap()
            .register_accounts(&mut registry, pair)
            .await
            .unwrap();
        assert_eq!(registry.codes["wallet"], Some(accounts.wallet.id()));
        assert_eq!(registry.codes["counter"], Some(accounts.counter.id()));
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
    async fn lost_response_retains_accounts_and_code_without_leaking_secrets() {
        let mut registry = Registry::with_codes(&["secret-wallet", "secret-counter"]);
        registry.lose_response = true;
        let mut pool =
            RegistrationPool::from_json(r#"["secret-wallet", "secret-counter"]"#).unwrap();
        let error = pool.register_accounts(&mut registry, pair).await.err().unwrap();
        assert!(!format!("{error:#}").contains("secret-wallet"));
        let accounts = pool
            .register_accounts(&mut registry, || panic!("accounts regenerated"))
            .await
            .unwrap();
        assert_eq!(registry.requests[0], registry.requests[1]);
        assert_eq!(registry.codes["secret-wallet"], Some(accounts.wallet.id()));
        assert_eq!(registry.codes["secret-counter"], Some(accounts.counter.id()));
        assert!(pool.register_accounts(&mut registry, pair).await.is_err());
    }

    /// Failed validity lookups must leave the code available for the next attempt.
    #[tokio::test]
    async fn transient_lookup_does_not_consume_a_code() {
        let mut registry = Registry::with_codes(&["a", "b"]);
        registry.fail_lookup = true;
        let mut pool = RegistrationPool::from_json(r#"["a", "b"]"#).unwrap();
        assert!(pool.register_accounts(&mut registry, pair).await.is_err());
        let accounts = pool
            .register_accounts(&mut registry, || panic!("accounts regenerated"))
            .await
            .unwrap();
        assert_eq!(registry.codes["a"], Some(accounts.wallet.id()));
        assert_eq!(registry.codes["b"], Some(accounts.counter.id()));
    }

    /// A counter registration failure must retain the already registered wallet without another
    /// redemption or account creation.
    #[tokio::test]
    async fn partial_pair_registration_resumes_at_the_counter() {
        let mut registry = Registry::with_codes(&["wallet", "counter"]);
        registry.lose_counter_response = true;
        let mut pool = RegistrationPool::from_json(r#"["wallet", "counter"]"#).unwrap();
        assert!(pool.register_accounts(&mut registry, pair).await.is_err());
        let accounts = pool
            .register_accounts(&mut registry, || panic!("accounts regenerated"))
            .await
            .unwrap();
        assert_eq!(
            registry.requests,
            vec![
                ("wallet".into(), accounts.wallet.id()),
                ("counter".into(), accounts.counter.id()),
                ("counter".into(), accounts.counter.id()),
            ]
        );
    }

    /// Another client redeeming a code between lookup and registration must not strand the pair.
    #[tokio::test]
    async fn code_race_advances_to_an_unused_code() {
        let mut registry = Registry::with_codes(&["raced", "wallet", "counter"]);
        let competitor = pair().unwrap().wallet.id();
        registry.raced_account = Some(competitor);
        let mut pool = RegistrationPool::from_json(r#"["raced", "wallet", "counter"]"#).unwrap();
        let accounts = pool.register_accounts(&mut registry, pair).await.unwrap();
        assert_eq!(registry.codes["raced"], Some(competitor));
        assert_eq!(registry.codes["wallet"], Some(accounts.wallet.id()));
        assert_eq!(registry.codes["counter"], Some(accounts.counter.id()));
    }

    /// Repeated deployments share one budget and preserve exact code text, including whitespace.
    #[tokio::test]
    async fn successive_pairs_share_the_budget() {
        let mut registry = Registry::with_codes(&[" Wallet ", "Counter", "wallet", "counter"]);
        let mut pool =
            RegistrationPool::from_json(r#"[" Wallet ", "Counter", "wallet", "counter"]"#).unwrap();
        let first = pool.register_accounts(&mut registry, pair).await.unwrap();
        let second = pool.register_accounts(&mut registry, pair).await.unwrap();
        assert_ne!(first.wallet.id(), second.wallet.id());
        assert_eq!(registry.codes[" Wallet "], Some(first.wallet.id()));
        assert_eq!(registry.codes["Counter"], Some(first.counter.id()));
        assert_eq!(registry.codes["wallet"], Some(second.wallet.id()));
        assert_eq!(registry.codes["counter"], Some(second.counter.id()));
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

    /// Invalid files must produce useful diagnostics without echoing secret input.
    #[test]
    fn rejects_empty_duplicate_and_malformed_codes() {
        for json in [r#"[""]"#, r#"["secret", "secret"]"#, r#"["secret", 3]"#, "secret"] {
            let error = RegistrationPool::from_json(json).err().unwrap();
            assert!(!format!("{error:#}").contains("secret"));
        }
    }
}
