// AGGLAYER STATUS CHECKER
// ================================================================================================

use std::time::Duration;

use anyhow::Context;
use miden_node_tracing::miden_instrument;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use crate::COMPONENT;
use crate::service::Service;
use crate::status::{
    AgglayerDirectionDetails,
    AgglayerStatusDetails,
    ServiceDetails,
    ServiceStatus,
    Status,
};

/// The only agglayer-monitor status schema version that this checker can read.
const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Polls the status endpoint of an agglayer-monitor instance.
pub struct AgglayerService {
    url: Url,
    client: Client,
    interval: Duration,
    request_timeout: Duration,
}

impl AgglayerService {
    pub fn new(url: Url, interval: Duration, request_timeout: Duration) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
            interval,
            request_timeout,
        }
    }

    /// Fetches the body of `GET /v1/status`. A response that is not successful is an error.
    async fn fetch_status(&self) -> anyhow::Result<String> {
        let url = self.url.join("v1/status")?;
        let response = self.client.get(url).timeout(self.request_timeout).send().await?;
        let status = response.status();
        let body = response.text().await?;
        anyhow::ensure!(status.is_success(), "HTTP {status}: {body}");
        Ok(body)
    }
}

impl Service for AgglayerService {
    fn name(&self) -> &'static str {
        "Agglayer Bridge"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.name(),
            ServiceDetails::AgglayerStatus(AgglayerStatusDetails {
                url: self.url.to_string(),
                ..Default::default()
            }),
        )
    }

    #[miden_instrument(
        target = COMPONENT,
        name = "check-status.agglayer",
    )]
    async fn check(&mut self) -> ServiceStatus {
        let body = match self.fetch_status().await {
            Ok(body) => body,
            Err(e) => return ServiceStatus::error(self.name(), format!("{e:#}")),
        };

        match parse_response(&body) {
            Ok(snapshot) => status_from_snapshot(self.name(), &self.url, &snapshot),
            Err(e) => ServiceStatus::error(self.name(), format!("{e:#}")),
        }
    }
}

/// Deserializes the `/v1/status` body.
fn parse_response(body: &str) -> anyhow::Result<StatusSnapshot> {
    let version: SchemaVersion =
        serde_json::from_str(body).context("failed to parse agglayer-monitor status")?;
    anyhow::ensure!(
        version.schema_version == SUPPORTED_SCHEMA_VERSION,
        "unsupported agglayer-monitor schema version {} (supported: {SUPPORTED_SCHEMA_VERSION})",
        version.schema_version,
    );

    let mut de = serde_json::Deserializer::from_str(body);
    serde_path_to_error::deserialize(&mut de).context("failed to parse agglayer-monitor status")
}

/// Maps the agglayer-monitor snapshot to the status of the card.
fn status_from_snapshot(name: &str, url: &Url, snapshot: &StatusSnapshot) -> ServiceStatus {
    let details = ServiceDetails::AgglayerStatus(AgglayerStatusDetails {
        url: url.to_string(),
        reason_code: snapshot.reason_code.clone(),
        runner_status: snapshot.runner.status.clone(),
        heartbeat_at: snapshot.runner.heartbeat_at,
        inbound: direction_details(&snapshot.directions.l1_to_miden),
        outbound: direction_details(&snapshot.directions.miden_to_l1),
    });

    match snapshot.overall_status {
        RemoteHealth::Healthy => ServiceStatus::healthy(name, details),
        RemoteHealth::Unhealthy => {
            ServiceStatus::unhealthy(name, unhealthy_message(snapshot), details)
        },
        RemoteHealth::Unknown => ServiceStatus::unknown(name, details),
    }
}

fn direction_details(direction: &DirectionStatus) -> AgglayerDirectionDetails {
    AgglayerDirectionDetails {
        status: direction.status.into(),
        reason_code: direction.reason_code.clone(),
        last_success_at: direction.last_success.as_ref().map(|run| run.completed_at),
        last_success_duration_ms: direction.last_success.as_ref().map(|run| run.test_duration_ms),
        last_failure_at: direction.last_failure.as_ref().map(|run| run.completed_at),
        last_failure_code: direction
            .last_failure
            .as_ref()
            .and_then(|run| run.error.as_ref())
            .map(|error| error.code.clone()),
        current_phase: direction.current_run.as_ref().map(|run| run.phase.clone()),
        success_count: direction.success_count,
        failure_count: direction.failure_count,
    }
}

/// Returns the error of the first unhealthy direction. If no unhealthy direction has an error,
/// returns the overall reason code.
fn unhealthy_message(snapshot: &StatusSnapshot) -> String {
    let directions = [
        ("L1 → Miden", &snapshot.directions.l1_to_miden),
        ("Miden → L1", &snapshot.directions.miden_to_l1),
    ];
    directions
        .into_iter()
        .filter(|(_, direction)| matches!(direction.status, RemoteHealth::Unhealthy))
        .find_map(|(label, direction)| {
            direction
                .error
                .as_ref()
                .map(|error| format!("{label}: {}: {}", error.code, error.message))
        })
        .or_else(|| snapshot.reason_code.clone())
        .unwrap_or_else(|| "agglayer-monitor reports the bridge as unhealthy".to_string())
}

// RESPONSE TYPES
// ================================================================================================

#[derive(Deserialize)]
struct SchemaVersion {
    schema_version: u32,
}

#[derive(Deserialize)]
struct StatusSnapshot {
    overall_status: RemoteHealth,
    reason_code: Option<String>,
    runner: Runner,
    directions: Directions,
}

#[derive(Deserialize)]
struct Runner {
    status: String,
    heartbeat_at: u64,
}

#[derive(Deserialize)]
struct Directions {
    l1_to_miden: DirectionStatus,
    miden_to_l1: DirectionStatus,
}

#[derive(Deserialize)]
struct DirectionStatus {
    status: RemoteHealth,
    reason_code: Option<String>,
    error: Option<Problem>,
    last_success: Option<RunSummary>,
    last_failure: Option<RunSummary>,
    current_run: Option<CurrentRun>,
    success_count: u64,
    failure_count: u64,
}

#[derive(Deserialize)]
struct RunSummary {
    completed_at: u64,
    test_duration_ms: u64,
    error: Option<Problem>,
}

#[derive(Deserialize)]
struct CurrentRun {
    phase: String,
}

#[derive(Deserialize)]
struct Problem {
    code: String,
    message: String,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum RemoteHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

impl From<RemoteHealth> for Status {
    fn from(value: RemoteHealth) -> Self {
        match value {
            RemoteHealth::Healthy => Status::Healthy,
            RemoteHealth::Unhealthy => Status::Unhealthy,
            RemoteHealth::Unknown => Status::Unknown,
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `GET /v1/status` response from the agglayer-monitor testnet run on 2026-09-23. The inbound
    /// test has one success, and the outbound test has not run.
    const TESTNET_STATUS: &str = r#"{
        "schema_version": 1,
        "generated_at": 1790178270,
        "profile": {
            "id": "sepolia-miden-testnet-86-eth",
            "revision": 1,
            "environment": "testnet",
            "l1_chain_id": 11155111,
            "l1_bridge_address": "0x1348947e282138d8f377b467f7d9c2eb0f335d1f",
            "agglayer_network_id": 86,
            "miden_genesis_commitment": "0xa78d1b0a40c9800d0b200587808fb3dd1762db6c5c7586f4675214b8a62d3491",
            "miden_bridge_account_id": "0x3b66e20b5088f25133b69216484652",
            "asset": {
                "origin_network": 0,
                "origin_token_address": "0x0000000000000000000000000000000000000000",
                "symbol": "ETH",
                "l1_decimals": 18,
                "miden_decimals": 8,
                "miden_faucet_id": "0x0b372f2735e33e91216d995bf29b91"
            }
        },
        "public_profile_verified": true,
        "overall_status": "unknown",
        "reason_code": "snapshot_stale",
        "runner": {
            "status": "unknown",
            "reason_code": "worker_stale",
            "heartbeat_at": 1790178270,
            "heartbeat_max_age_seconds": 90
        },
        "budget": {
            "utc_day": 20719,
            "reserved_capital_wei": "0",
            "reserved_l1_fee_wei": "0",
            "reserved_miden_fee_units": "0",
            "settled_l1_fee_wei_today": "200335914751464",
            "settled_miden_fee_units_today": "119"
        },
        "directions": {
            "l1_to_miden": {
                "status": "unknown",
                "reason_code": "snapshot_stale",
                "error": null,
                "observed_at": 1790178270,
                "claim_policy": "autoclaim_required",
                "completion_policy": "finalized_l1_deposit_and_consumed_p2id",
                "amount_source_base_units": "100000000000000",
                "amount_destination_base_units": "10000",
                "last_success": {
                    "run_id": "inbound-001",
                    "outcome": "succeeded",
                    "started_at": 1790177074,
                    "completed_at": 1790178270,
                    "test_duration_ms": 1190000,
                    "phase_durations_ms": {
                        "preparing_source": 6000,
                        "source_submitted": 0,
                        "waiting_autoclaim": 1076000,
                        "waiting_l1_inclusion": 34000,
                        "waiting_note_consumption": 80000
                    },
                    "valid_until": 1790184870,
                    "error": null
                },
                "last_failure": null,
                "last_terminal_run": {
                    "run_id": "inbound-001",
                    "outcome": "succeeded",
                    "started_at": 1790177074,
                    "completed_at": 1790178270,
                    "test_duration_ms": 1190000,
                    "phase_durations_ms": {
                        "preparing_source": 6000,
                        "source_submitted": 0,
                        "waiting_autoclaim": 1076000,
                        "waiting_l1_inclusion": 34000,
                        "waiting_note_consumption": 80000
                    },
                    "valid_until": 1790184870,
                    "error": null
                },
                "current_run": null,
                "next_scheduled_at": null,
                "skipped_ticks": 0,
                "success_count": 1,
                "failure_count": 0,
                "observation_failure_count": 0,
                "test_duration_ms": 1190000,
                "pending_runs": 0
            },
            "miden_to_l1": {
                "status": "unknown",
                "reason_code": "snapshot_stale",
                "error": null,
                "observed_at": null,
                "claim_policy": "autoclaim_required",
                "completion_policy": "finalized_l1_claim_and_recipient_delivery",
                "amount_source_base_units": "10000",
                "amount_destination_base_units": "100000000000000",
                "last_success": null,
                "last_failure": null,
                "last_terminal_run": null,
                "current_run": null,
                "next_scheduled_at": null,
                "skipped_ticks": 0,
                "success_count": 0,
                "failure_count": 0,
                "observation_failure_count": 0,
                "test_duration_ms": null,
                "pending_runs": 0
            }
        }
    }"#;

    fn url() -> Url {
        Url::parse("http://agglayer-monitor.example").unwrap()
    }

    fn agglayer_details(status: &ServiceStatus) -> &AgglayerStatusDetails {
        match &status.details {
            ServiceDetails::AgglayerStatus(details) => details,
            other => panic!("expected agglayer details, got {other:?}"),
        }
    }

    fn direction(status: RemoteHealth, error: Option<(&str, &str)>) -> DirectionStatus {
        DirectionStatus {
            status,
            reason_code: error.map(|(code, _)| code.to_string()),
            error: error.map(|(code, message)| Problem {
                code: code.to_string(),
                message: message.to_string(),
            }),
            last_success: None,
            last_failure: None,
            current_run: None,
            success_count: 0,
            failure_count: 0,
        }
    }

    fn snapshot(
        overall_status: RemoteHealth,
        reason_code: Option<&str>,
        inbound: DirectionStatus,
        outbound: DirectionStatus,
    ) -> StatusSnapshot {
        StatusSnapshot {
            overall_status,
            reason_code: reason_code.map(str::to_string),
            runner: Runner {
                status: "running".to_string(),
                heartbeat_at: 1_790_178_270,
            },
            directions: Directions {
                l1_to_miden: inbound,
                miden_to_l1: outbound,
            },
        }
    }

    #[test]
    fn testnet_status_maps_to_card_details() {
        let snapshot = parse_response(TESTNET_STATUS).unwrap();
        let status = status_from_snapshot("Agglayer Bridge", &url(), &snapshot);

        assert_eq!(status.status, Status::Unknown);
        let details = agglayer_details(&status);
        assert_eq!(details.reason_code.as_deref(), Some("snapshot_stale"));
        assert_eq!(details.runner_status, "unknown");
        assert_eq!(details.heartbeat_at, 1_790_178_270);

        assert_eq!(details.inbound.status, Status::Unknown);
        assert_eq!(details.inbound.last_success_at, Some(1_790_178_270));
        assert_eq!(details.inbound.last_success_duration_ms, Some(1_190_000));
        assert_eq!(details.inbound.last_failure_at, None);
        assert_eq!(details.inbound.success_count, 1);
        assert_eq!(details.inbound.failure_count, 0);

        assert_eq!(details.outbound.last_success_at, None);
        assert_eq!(details.outbound.last_failure_at, None);
        assert_eq!(details.outbound.current_phase, None);
        assert_eq!(details.outbound.success_count, 0);
    }

    #[test]
    fn overall_status_sets_card_status() {
        let cases = [
            (RemoteHealth::Healthy, Status::Healthy),
            (RemoteHealth::Unhealthy, Status::Unhealthy),
            (RemoteHealth::Unknown, Status::Unknown),
        ];
        for (remote, expected) in cases {
            let snapshot = snapshot(
                remote,
                None,
                direction(RemoteHealth::Healthy, None),
                direction(RemoteHealth::Healthy, None),
            );
            let status = status_from_snapshot("Agglayer Bridge", &url(), &snapshot);
            assert_eq!(status.status, expected);
        }
    }

    #[test]
    fn unhealthy_status_reports_the_failing_direction_error() {
        let snapshot = snapshot(
            RemoteHealth::Unhealthy,
            Some("e2e_failure"),
            direction(RemoteHealth::Healthy, None),
            direction(
                RemoteHealth::Unhealthy,
                Some(("deadline_exceeded", "The route did not finish before the deadline.")),
            ),
        );
        let status = status_from_snapshot("Agglayer Bridge", &url(), &snapshot);

        assert_eq!(status.status, Status::Unhealthy);
        assert_eq!(
            status.error.as_deref(),
            Some("Miden → L1: deadline_exceeded: The route did not finish before the deadline."),
        );
        assert_eq!(agglayer_details(&status).outbound.status, Status::Unhealthy);
    }

    #[test]
    fn unhealthy_status_without_direction_error_reports_the_reason_code() {
        let snapshot = snapshot(
            RemoteHealth::Unhealthy,
            Some("e2e_failure"),
            direction(RemoteHealth::Unhealthy, None),
            direction(RemoteHealth::Healthy, None),
        );
        let status = status_from_snapshot("Agglayer Bridge", &url(), &snapshot);

        assert_eq!(status.error.as_deref(), Some("e2e_failure"));
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let body = TESTNET_STATUS.replace("\"schema_version\": 1", "\"schema_version\": 2");
        let msg = format!("{:#}", parse_response(&body).err().unwrap());
        assert!(msg.contains("schema version 2"), "got: {msg}");
    }

    #[test]
    fn missing_direction_error_includes_path() {
        let body = TESTNET_STATUS.replace("\"miden_to_l1\"", "\"other_direction\"");
        let msg = format!("{:#}", parse_response(&body).err().unwrap());
        assert!(msg.contains("miden_to_l1"), "got: {msg}");
    }
}
