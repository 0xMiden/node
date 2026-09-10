//! The status the service reports, and the task which keeps it current.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use miden_node_tracing::warn;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;

use crate::LOG_TARGET;
use crate::node::RpcNodeClient;

// STATUS SNAPSHOT
// ================================================================================================

/// The funding account's balance as of the last block the worker read.
///
/// The worker publishes the values, and the `Status` endpoint reads them. The two numbers are read
/// separately, so a concurrent update can pair a balance with the neighbouring block number. That
/// is acceptable for a status report and avoids taking a lock on the funding path.
#[derive(Clone)]
pub struct StatusSnapshot {
    account_id: AccountId,
    max_amount: u64,
    balance: Arc<AtomicU64>,
    chain_tip: Arc<AtomicU32>,
}

impl StatusSnapshot {
    /// Creates a snapshot for the given funding account.
    pub fn new(account_id: AccountId, max_amount: u64) -> Self {
        Self {
            account_id,
            max_amount,
            balance: Arc::new(AtomicU64::new(0)),
            chain_tip: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Publishes the balance the worker read at `chain_tip`.
    pub fn update(&self, balance: u64, chain_tip: BlockNumber) {
        self.balance.store(balance, Ordering::Relaxed);
        self.chain_tip.store(chain_tip.as_u32(), Ordering::Relaxed);
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn max_amount(&self) -> u64 {
        self.max_amount
    }

    pub fn balance(&self) -> u64 {
        self.balance.load(Ordering::Relaxed)
    }

    pub fn chain_tip(&self) -> BlockNumber {
        self.chain_tip.load(Ordering::Relaxed).into()
    }
}

// STATUS REFRESHER
// ================================================================================================

/// Reads the funding account on an interval so the reported balance stays current.
pub struct StatusRefresher {
    node: RpcNodeClient,
    account_id: AccountId,
    fee_faucet_id: AccountId,
    status: StatusSnapshot,
    interval: Duration,
}

impl StatusRefresher {
    pub fn new(
        node: RpcNodeClient,
        account_id: AccountId,
        fee_faucet_id: AccountId,
        status: StatusSnapshot,
        interval: Duration,
    ) -> Self {
        Self {
            node,
            account_id,
            fee_faucet_id,
            status,
            interval,
        }
    }

    /// Reads the funding account until the service shuts down.
    ///
    /// A failed read is not fatal: the node may be restarting, and the reported balance simply
    /// stays at the value of the last successful read.
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        loop {
            if let Err(err) = self.refresh().await {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "Failed to read the funding account"
                );
            }

            tokio::select! {
                () = tokio::time::sleep(self.interval) => {},
                () = shutdown.cancelled() => return Ok(()),
            }
        }
    }

    /// Reads the funding account at the chain tip and publishes its balance.
    async fn refresh(&self) -> Result<()> {
        let (vault, block_num) = self.node.public_account_vault(self.account_id).await?;

        let balance = vault
            .get_balance(AssetId::new_fungible(self.fee_faucet_id))
            .map_or(0, |amount| amount.as_u64());
        self.status.update(balance, block_num);

        Ok(())
    }
}
