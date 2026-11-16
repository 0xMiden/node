//! `USDCx` bridge checker.
//!
//! Each check reads the circulating supply and pause flag of the `USDCx` faucet on Miden, the
//! collateral and pause flags of the xReserve contract that backs it, and the faucet's deposits and
//! withdrawals over the last 24 hours. The faucet is the chain's fee asset faucet, so its ID comes
//! from the protocol configuration of the latest block.
//!
//! The supply is read right before the collateral. A deposit raises the collateral before the
//! faucet mints it, and a withdrawal burns on Miden before the collateral is released, so the
//! supply exceeds the collateral only if a whole withdrawal completes between the two reads.

mod activity;
mod xreserve;

use std::time::Duration;

use alloy_primitives::Address;
use anyhow::{Context, Result};
use miden_node_proto::DecodeMessageExt;
use miden_node_proto::clients::{RpcClient, UsdcxFaucet};
use miden_node_proto::domain::protocol_config::ensure_protocol_config_is_present_and_matches_header;
use miden_node_proto::generated::miden::node::v1::GetBlockHeaderByNumberRequest;
use miden_node_tracing::instrument;
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountStorageHeader, StorageSlotName, StorageSlotType};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_standards::account::access::PausableStorage;
use miden_standards::account::faucets::FungibleFaucet;
use miden_usdcx::account::XReserveFaucetExtension;
use url::Url;

use self::activity::ActivityTracker;
use self::xreserve::XReserveClient;
use crate::service::{Service, build_tls_client};
use crate::status::{
    ServiceDetails,
    ServiceStatus,
    UsdcxActivityDetails,
    UsdcxBridgeDetails,
    UsdcxFaucetDetails,
    XReserveDetails,
};

/// Monitors the `USDCx` bridge between Miden and the xReserve chain.
pub struct UsdcxBridgeService {
    rpc: RpcClient,
    xreserve: XReserveClient,
    interval: Duration,
    /// Faucet state from the previous check, synced to the tip to avoid downloading its code again.
    faucet: Option<UsdcxFaucet>,
    /// Circle domain of the faucet, needed to read xReserve when the faucet read fails.
    circle_domain: Option<u32>,
    activity: ActivityTracker,
}

impl UsdcxBridgeService {
    pub fn new(
        rpc_url: Url,
        xreserve_rpc_url: Url,
        xreserve_address: Address,
        xreserve_local_token: Address,
        interval: Duration,
        request_timeout: Duration,
        max_decoding_message_size: usize,
    ) -> Self {
        Self {
            rpc: build_tls_client(rpc_url, request_timeout, max_decoding_message_size),
            xreserve: XReserveClient::new(
                xreserve_rpc_url,
                xreserve_address,
                xreserve_local_token,
                request_timeout,
            ),
            interval,
            faucet: None,
            circle_domain: None,
            activity: ActivityTracker::default(),
        }
    }

    /// Fetches the latest block header and the ID of the fee asset faucet it commits to.
    async fn fetch_tip(&mut self) -> Result<(BlockHeader, AccountId)> {
        let response = self
            .rpc
            .get_block_header_by_number(GetBlockHeaderByNumberRequest {
                block_num: None,
                include_mmr_proof: None,
                include_protocol_config: Some(true),
            })
            .await
            .context("failed to get the latest block header")?
            .into_inner();
        let header: BlockHeader = response
            .block_header
            .context("the block header response has no header")?
            .decode_and_build_unchecked()
            .context("failed to decode the latest block header")?;
        let protocol_config =
            ensure_protocol_config_is_present_and_matches_header(response.protocol_config, &header)
                .context("the node returned an invalid protocol configuration")?;
        Ok((header, protocol_config.fee_asset_id().faucet_id()))
    }

    /// Reads the faucet state at the tip.
    async fn read_faucet(
        &mut self,
        tip: &BlockHeader,
        faucet_id: AccountId,
    ) -> Result<UsdcxFaucetDetails> {
        let block = tip.block_num();
        if let Some(faucet) = self.faucet.as_mut().filter(|faucet| faucet.account_id() == faucet_id)
        {
            faucet
                .sync_to(&mut self.rpc, block)
                .await
                .context("failed to sync the USDCx faucet")?;
        } else {
            let faucet = UsdcxFaucet::load_at(&mut self.rpc, faucet_id, block)
                .await
                .context("failed to load the USDCx faucet")?;
            self.faucet = Some(faucet);
        }

        let faucet = self.faucet.as_ref().expect("the faucet was loaded above");
        let metadata = faucet.metadata().context("failed to read the USDCx faucet metadata")?;
        faucet_state(faucet_id, block, &metadata, faucet.storage_header())
    }
}

impl Service for UsdcxBridgeService {
    fn name(&self) -> &'static str {
        "USDCx Bridge"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::UsdcxBridge(UsdcxBridgeDetails {
                xreserve_address: self.xreserve.address().to_string(),
                ..Default::default()
            }),
        )
    }

    #[instrument(name = "check_status")]
    async fn check(&mut self) -> ServiceStatus {
        let tip = self.fetch_tip().await;
        let faucet = match &tip {
            Ok((header, faucet_id)) => self.read_faucet(header, *faucet_id).await,
            Err(err) => Err(anyhow::anyhow!("{err:#}")),
        };
        if let Ok(faucet) = &faucet {
            self.circle_domain = Some(faucet.circle_domain);
        }

        let xreserve = match self.circle_domain {
            Some(domain) => self.xreserve.read(domain).await,
            None => Err(anyhow::anyhow!("the Circle domain is unknown until the faucet is read")),
        };

        // A missing tip is already reported as a faucet error.
        let activity_error = match &tip {
            Ok((header, faucet_id)) => self
                .activity
                .sync(&mut self.rpc, *faucet_id, header, self.interval)
                .await
                .err()
                .map(|err| format!("{err:#}")),
            Err(_) => None,
        };

        bridge_status(
            self.name(),
            self.xreserve.address(),
            faucet.map_err(|err| format!("{err:#}")),
            xreserve.map_err(|err| format!("{err:#}")),
            self.activity.details(),
            activity_error,
        )
    }
}

/// Decodes the faucet state from its metadata and storage header.
fn faucet_state(
    faucet_id: AccountId,
    block: BlockNumber,
    metadata: &FungibleFaucet,
    storage: &AccountStorageHeader,
) -> Result<UsdcxFaucetDetails> {
    // Any non-zero pause word means paused.
    let paused = value_slot(storage, PausableStorage::is_paused_slot())? != Word::empty();
    let domain = value_slot(storage, XReserveFaucetExtension::domain_config_slot())?.as_elements()
        [0]
    .as_canonical_u64();
    let circle_domain = u32::try_from(domain)
        .with_context(|| format!("the faucet's Circle domain {domain} is not a valid domain"))?;

    Ok(UsdcxFaucetDetails {
        faucet_id: faucet_id.to_hex(),
        block_num: block.as_u32(),
        symbol: metadata.symbol().to_string(),
        decimals: metadata.decimals(),
        circulating_supply: metadata.token_supply().as_u64(),
        paused,
        circle_domain,
    })
}

/// Returns the value of the named value slot.
fn value_slot(storage: &AccountStorageHeader, name: &StorageSlotName) -> Result<Word> {
    let slot = storage.slots().find(|slot| slot.name() == name).with_context(|| {
        format!("the faucet has no `{name}` slot, so it is not an xReserve USDCx faucet")
    })?;
    anyhow::ensure!(
        slot.slot_type() == StorageSlotType::Value,
        "the faucet's `{name}` slot is not a value slot"
    );
    Ok(slot.value())
}

/// Builds the card status from the reads of one check.
///
/// The activity sync is informational and does not affect the status.
fn bridge_status(
    name: &str,
    xreserve_address: Address,
    faucet: Result<UsdcxFaucetDetails, String>,
    xreserve: Result<XReserveDetails, String>,
    activity: Option<UsdcxActivityDetails>,
    activity_error: Option<String>,
) -> ServiceStatus {
    let problems = bridge_problems(&faucet, &xreserve);
    let details = ServiceDetails::UsdcxBridge(UsdcxBridgeDetails {
        xreserve_address: xreserve_address.to_string(),
        faucet: faucet.ok(),
        xreserve: xreserve.ok(),
        activity,
        activity_error,
    });
    if problems.is_empty() {
        ServiceStatus::healthy(name, details)
    } else {
        ServiceStatus::unhealthy(name, problems.join("; "), details)
    }
}

/// Lists the reasons the bridge is unhealthy: a failed read, a pause on either side, or a supply
/// that the collateral does not cover.
fn bridge_problems(
    faucet: &Result<UsdcxFaucetDetails, String>,
    xreserve: &Result<XReserveDetails, String>,
) -> Vec<String> {
    let mut problems = Vec::new();
    match faucet {
        Err(err) => problems.push(format!("USDCx faucet: {err}")),
        Ok(faucet) if faucet.paused => problems.push("the USDCx faucet is paused".to_string()),
        Ok(_) => {},
    }
    match xreserve {
        Err(err) => problems.push(format!("xReserve: {err}")),
        Ok(xreserve) => {
            if xreserve.paused {
                problems.push("xReserve is paused".to_string());
            }
            if xreserve.deposits_paused {
                problems.push("xReserve deposits are paused".to_string());
            }
            if xreserve.withdrawals_paused {
                problems.push("xReserve withdrawals are paused".to_string());
            }
        },
    }
    if let (Ok(faucet), Ok(xreserve)) = (faucet, xreserve) {
        if faucet.decimals != xreserve.collateral_decimals {
            problems.push(format!(
                "the collateral token has {} decimals but USDCx has {}",
                xreserve.collateral_decimals, faucet.decimals
            ));
        } else if faucet.circulating_supply > xreserve.collateral {
            problems.push(format!(
                "the USDCx supply of {} base units exceeds the collateral of {} base units",
                faucet.circulating_supply, xreserve.collateral
            ));
        }
    }
    problems
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloy_primitives::address;
    use miden_protocol::account::{Account, AccountStorage, StorageSlot};
    use miden_protocol::asset::{AssetAmount, AssetId};
    use miden_protocol::block::FeeParameters;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };
    use miden_usdcx::account::xreserve::XReserveStablecoinBuilder;
    use miden_usdcx::xreserve::encoding::CircleDomain;

    use super::*;
    use crate::status::Status;

    const XRESERVE: Address = address!("0x008888878f94C0d87defdf0B07f46B93C1934442");

    /// Builds a `USDCx` faucet the way genesis does.
    fn usdcx_faucet(token_supply: u64) -> Account {
        let owner = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap();
        let fee_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
        XReserveStablecoinBuilder::builder()
            .token_supply(AssetAmount::new(token_supply).unwrap())
            .owner(owner)
            .attest_admin_holders(Vec::new())
            .pauser_holders(Vec::new())
            .unpauser_holders(Vec::new())
            .blocklist_manager_holders(Vec::new())
            .fee_parameters(FeeParameters::new(0))
            .fee_asset_id(AssetId::new_fungible(fee_faucet))
            .domain(CircleDomain::MIDEN)
            .build()
            .unwrap()
            .build_genesis_account([1; 32])
            .unwrap()
    }

    fn read(account: &Account, storage: &AccountStorageHeader) -> Result<UsdcxFaucetDetails> {
        let metadata = FungibleFaucet::try_from(account).unwrap();
        faucet_state(account.id(), BlockNumber::from(7), &metadata, storage)
    }

    /// Returns the account's storage header with the named value slot replaced or removed.
    fn header_with(
        account: &Account,
        name: &StorageSlotName,
        value: Option<Word>,
    ) -> AccountStorageHeader {
        let slots = account
            .storage()
            .to_header()
            .slots()
            .filter_map(|slot| {
                if slot.name() != name {
                    return Some(StorageSlot::with_value(slot.name().clone(), slot.value()));
                }
                value.map(|value| StorageSlot::with_value(name.clone(), value))
            })
            .collect();
        AccountStorage::new(slots).unwrap().to_header()
    }

    fn faucet_details(circulating_supply: u64) -> UsdcxFaucetDetails {
        UsdcxFaucetDetails {
            faucet_id: "0xfaucet".to_string(),
            block_num: 7,
            symbol: "USDCX".to_string(),
            decimals: 6,
            circulating_supply,
            paused: false,
            circle_domain: 10_007,
        }
    }

    fn xreserve_details(collateral: u64) -> XReserveDetails {
        XReserveDetails {
            chain_id: 5_042_002,
            collateral,
            collateral_decimals: 6,
            paused: false,
            deposits_paused: false,
            withdrawals_paused: false,
        }
    }

    fn status(
        faucet: Result<UsdcxFaucetDetails, String>,
        xreserve: Result<XReserveDetails, String>,
    ) -> ServiceStatus {
        bridge_status("USDCx Bridge", XRESERVE, faucet, xreserve, None, None)
    }

    #[test]
    fn genesis_faucet_reports_supply_and_domain() {
        let faucet = usdcx_faucet(100_000_000);

        let state = read(&faucet, &faucet.storage().to_header()).unwrap();

        assert_eq!(state.circulating_supply, 100_000_000);
        assert_eq!(state.decimals, 6);
        assert_eq!(state.symbol, "USDCX");
        assert!(!state.paused);
        assert_eq!(state.circle_domain, 10_007);
        assert_eq!(state.block_num, 7);
    }

    #[test]
    fn paused_faucet_is_reported() {
        let faucet = usdcx_faucet(1);
        let storage = header_with(
            &faucet,
            PausableStorage::is_paused_slot(),
            Some(Word::from([1u32, 0, 0, 0])),
        );

        assert!(read(&faucet, &storage).unwrap().paused);
    }

    #[test]
    fn faucet_without_a_circle_domain_is_rejected() {
        let faucet = usdcx_faucet(1);
        let storage = header_with(&faucet, XReserveFaucetExtension::domain_config_slot(), None);

        let err = read(&faucet, &storage).unwrap_err().to_string();

        assert!(err.contains("not an xReserve USDCx faucet"), "got: {err}");
    }

    #[test]
    fn covered_supply_is_healthy() {
        let status = status(Ok(faucet_details(1_000)), Ok(xreserve_details(1_000)));

        assert_eq!(status.status, Status::Healthy);
        assert_eq!(status.error, None);
    }

    #[test]
    fn pauses_and_deficits_are_unhealthy() {
        let paused_faucet = UsdcxFaucetDetails { paused: true, ..faucet_details(1) };
        let cases = [
            (paused_faucet, xreserve_details(1), "the USDCx faucet is paused"),
            (
                faucet_details(1),
                XReserveDetails { paused: true, ..xreserve_details(1) },
                "xReserve is paused",
            ),
            (
                faucet_details(1),
                XReserveDetails {
                    deposits_paused: true,
                    ..xreserve_details(1)
                },
                "deposits are paused",
            ),
            (
                faucet_details(1),
                XReserveDetails {
                    withdrawals_paused: true,
                    ..xreserve_details(1)
                },
                "withdrawals are paused",
            ),
            (faucet_details(1_001), xreserve_details(1_000), "exceeds the collateral"),
            (
                faucet_details(1),
                XReserveDetails {
                    collateral_decimals: 18,
                    ..xreserve_details(u64::MAX)
                },
                "18 decimals",
            ),
        ];
        for (faucet, xreserve, expected) in cases {
            let status = status(Ok(faucet), Ok(xreserve));

            assert_eq!(status.status, Status::Unhealthy);
            let error = status.error.unwrap();
            assert!(error.contains(expected), "expected {expected:?}, got: {error}");
        }
    }

    #[test]
    fn failed_reads_are_unhealthy_and_keep_the_other_side() {
        let status = status(Ok(faucet_details(1)), Err("connection refused".to_string()));

        assert_eq!(status.status, Status::Unhealthy);
        assert_eq!(status.error.as_deref(), Some("xReserve: connection refused"));
        let ServiceDetails::UsdcxBridge(details) = status.details else {
            panic!("expected USDCx bridge details");
        };
        assert_eq!(details.faucet, Some(faucet_details(1)));
        assert_eq!(details.xreserve, None);
    }

    #[test]
    fn activity_errors_do_not_change_the_status() {
        let status = bridge_status(
            "USDCx Bridge",
            XRESERVE,
            Ok(faucet_details(1)),
            Ok(xreserve_details(1)),
            None,
            Some("failed to sync the faucet transactions".to_string()),
        );

        assert_eq!(status.status, Status::Healthy);
    }
}
