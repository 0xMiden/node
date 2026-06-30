//! Network monitor status checker tasks.
//!
//! This module contains the logic for checking the status of network services.
//! Individual status checker tasks send updates via watch channels to the web server.
//!
//! Type definitions live in [`crate::service_status`] and are re-exported here for convenience.

use std::time::Duration;

use miden_node_proto::clients::RpcClient;
use tracing::debug;
use url::Url;

use crate::service::{Service, build_tls_client};
pub use crate::service_status::*;
use crate::{COMPONENT, LOG_TARGET};

// STALE CHAIN TIP TRACKER
// ================================================================================================

/// Tracks the chain tip and detects when it becomes stale.
///
/// This struct monitors the chain tip from RPC status responses and determines if the chain
/// has stopped making progress by comparing the time since the last chain tip change against
/// a configurable threshold.
#[derive(Debug)]
pub struct StaleChainTracker {
    /// The last observed chain tip from the store.
    last_chain_tip: Option<u32>,
    /// Unix timestamp when the chain tip was last observed to change.
    last_chain_tip_update: Option<u64>,
    /// Maximum time without a chain tip update before marking as stale.
    stale_threshold_secs: u64,
}

impl StaleChainTracker {
    /// Creates a new stale chain tracker with the given threshold.
    pub fn new(stale_threshold: Duration) -> Self {
        Self {
            last_chain_tip: None,
            last_chain_tip_update: None,
            stale_threshold_secs: stale_threshold.as_secs(),
        }
    }

    /// Updates the tracker with a new chain tip observation and returns whether the chain is
    /// stale.
    ///
    /// The chain is considered stale if the tip hasn't changed for longer than the configured
    /// threshold
    pub fn update(&mut self, chain_tip: u32, current_time: u64) -> Option<u64> {
        match self.last_chain_tip {
            Some(last_tip) if last_tip == chain_tip => {
                if let Some(last_update) = self.last_chain_tip_update {
                    let elapsed = current_time.saturating_sub(last_update);
                    if elapsed > self.stale_threshold_secs {
                        return Some(elapsed);
                    }
                }
            },
            _ => {
                self.last_chain_tip = Some(chain_tip);
                self.last_chain_tip_update = Some(current_time);
            },
        }
        None
    }
}

// RPC STATUS CHECKER
// ================================================================================================

pub struct RpcService {
    url: String,
    rpc: RpcClient,
    stale_tracker: StaleChainTracker,
    interval: Duration,
}

impl RpcService {
    pub fn new(
        rpc_url: Url,
        interval: Duration,
        request_timeout: Duration,
        stale_threshold: Duration,
    ) -> Self {
        let url = rpc_url.to_string();
        let rpc = build_tls_client::<RpcClient>(rpc_url, request_timeout);
        Self {
            url,
            rpc,
            stale_tracker: StaleChainTracker::new(stale_threshold),
            interval,
        }
    }
}

impl Service for RpcService {
    fn name(&self) -> &'static str {
        "RPC"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::RpcStatus(RpcStatusDetails {
                url: self.url.clone(),
                version: String::new(),
                genesis_commitment: None,
                chain_tip: 0,
                block_producer_status: None,
            }),
        )
    }

    #[miden_node_utils::tracing::miden_instrument(
        parent = None,
        target = COMPONENT,
        name = "network_monitor.status.check_rpc",
        skip_all,
        level = "info",
        ret(level = "debug")
    )]
    async fn check(&mut self) -> ServiceStatus {
        match self.rpc.status(()).await {
            Ok(response) => {
                let rpc_details =
                    RpcStatusDetails::from_rpc_status(response.into_inner(), self.url.clone());

                if let Some(stale_duration) =
                    self.stale_tracker.update(rpc_details.chain_tip, current_unix_timestamp_secs())
                {
                    debug!(
                        target: LOG_TARGET,
                        chain_tip = rpc_details.chain_tip,
                        stale_duration_secs = stale_duration,
                        "Chain tip is stale"
                    );
                    return ServiceStatus::unhealthy(
                        self.name(),
                        format!(
                            "Chain tip {} has not changed for {} seconds",
                            rpc_details.chain_tip, stale_duration
                        ),
                        ServiceDetails::RpcStatus(rpc_details),
                    );
                }

                ServiceStatus::healthy(self.name(), ServiceDetails::RpcStatus(rpc_details))
            },
            Err(e) => {
                debug!(target: LOG_TARGET, error = %e, "RPC status check failed");
                ServiceStatus::error(self.name(), e)
            },
        }
    }
}
