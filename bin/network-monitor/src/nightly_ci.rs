// NIGHTLY CI HEALTH CHECKER
// ================================================================================================

//! Polls the GitHub REST API for the latest scheduled run of a configured workflow on the
//! repo's `main` branch and surfaces it as a `ServiceStatus` card.
//!
//! ## Why scheduled-only
//!
//! Some repos run the same workflow on every push to `main` AND on a nightly schedule. The
//! per-network monitor only cares about the *nightly* signal — the wallet's e2e-blockchain
//! Chrome workflows are split per-network, so the devnet monitor pins to the devnet workflow
//! file and the testnet monitor pins to the testnet one. We filter by `event=schedule` to
//! lock onto the nightly cadence, ignoring whatever transient pushes may have run more
//! recently. If the schedule ever stops firing, the card surfaces a `Stale` warning via
//! `last_checked` drift exceeding 24h.
//!
//! ## Anonymous access
//!
//! GitHub's REST API is anonymous-readable for public repos at 60 requests/hour per IP.
//! At a 10-minute poll interval that's 6/hour — comfortably under the cap. No PAT needed.
//! We send a `User-Agent` header (required by GitHub) identifying the monitor.

use std::time::Duration;

use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use tracing::{instrument, warn};

use crate::COMPONENT;
use crate::service::Service;
use crate::service_status::{ServiceDetails, ServiceStatus, current_unix_timestamp_secs};

/// User-Agent header sent on every GitHub API request. GitHub requires a non-empty UA;
/// without it, all requests are 403'd. Includes the monitor version so log-side debugging
/// can correlate behavior to a specific build.
const USER_AGENT_VALUE: &str =
    concat!("miden-network-monitor/", env!("CARGO_PKG_VERSION"), " (+nightly-ci-card)");

/// GitHub API endpoint for listing workflow runs. Path expansion is `/repos/{owner}/{repo}/
/// actions/workflows/{workflow_path}/runs`. The `workflow_path` segment can be either a
/// numeric id or the workflow's filename (e.g. `e2e-blockchain-chrome-devnet.yml`); we use
/// the filename form because it's stable across repo renames and easier to configure.
const GITHUB_API_BASE: &str = "https://api.github.com";

// SERVICE
// ================================================================================================

/// Per-instance configuration for a nightly CI check. One service per workflow file.
#[derive(Debug, Clone)]
pub struct NightlyCiConfig {
    /// Display name shown on the dashboard card (e.g. "Wallet E2E (devnet)").
    pub name: String,
    /// Repo in `owner/repo` form (e.g. `0xMiden/wallet`).
    pub repo: String,
    /// Workflow filename (e.g. `e2e-blockchain-chrome-devnet.yml`).
    pub workflow_path: String,
    /// Branch the nightly is scheduled against. Almost always `main`.
    pub branch: String,
    /// How often to poll GitHub. 10 min is a comfortable default at the 60/hr anon limit.
    pub interval: Duration,
    /// Per-request HTTP timeout.
    pub request_timeout: Duration,
}

pub struct NightlyCiService {
    config: NightlyCiConfig,
    client: Client,
}

impl NightlyCiService {
    pub fn new(config: NightlyCiConfig) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        // GitHub recommends pinning the API version; v2022-11-28 is the current GA.
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("reqwest client builds with valid headers");

        Self { config, client }
    }

    /// Convenience: the public URL of the workflow file (used by the card to link out).
    fn workflow_html_url(&self) -> String {
        format!(
            "https://github.com/{}/actions/workflows/{}",
            self.config.repo, self.config.workflow_path
        )
    }

    /// Build the API URL for the latest scheduled run on `branch`.
    fn runs_endpoint(&self) -> String {
        format!(
            "{GITHUB_API_BASE}/repos/{}/actions/workflows/{}/runs?branch={}&event=schedule&per_page=1",
            self.config.repo, self.config.workflow_path, self.config.branch
        )
    }
}

impl Service for NightlyCiService {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn interval(&self) -> Duration {
        self.config.interval
    }

    fn initial_status(&self) -> ServiceStatus {
        ServiceStatus::unknown(
            self.config.name.clone(),
            ServiceDetails::NightlyCi(NightlyCiDetails {
                workflow_html_url: self.workflow_html_url(),
                ..NightlyCiDetails::default()
            }),
        )
    }

    #[instrument(target = COMPONENT, name = "check-status.nightly-ci", skip_all, ret(level = "debug"))]
    async fn check(&mut self) -> ServiceStatus {
        let endpoint = self.runs_endpoint();
        let resp = self
            .client
            .get(&endpoint)
            .timeout(self.config.request_timeout)
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                warn!(target: COMPONENT, error = %e, "nightly CI: request failed");
                return ServiceStatus::error(self.name(), e);
            },
        };

        // Surface 4xx/5xx with the body so a misconfigured workflow_path or an API change
        // shows up in the card error string instead of as a generic "request failed".
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let truncated: String = body.chars().take(200).collect();
            return ServiceStatus::error(
                self.name(),
                format!("GitHub API {status}: {truncated}"),
            );
        }

        let payload: GhRunsResponse = match resp.json().await {
            Ok(p) => p,
            Err(e) => return ServiceStatus::error(self.name(), e),
        };

        let Some(run) = payload.workflow_runs.into_iter().next() else {
            // Repo + workflow exist but there's no scheduled run yet (e.g. the cron hasn't
            // fired since the workflow was created). Surface as Unknown rather than
            // Unhealthy — there's nothing wrong, just no signal.
            return ServiceStatus::unknown(
                self.name(),
                ServiceDetails::NightlyCi(NightlyCiDetails {
                    workflow_html_url: self.workflow_html_url(),
                    ..NightlyCiDetails::default()
                }),
            );
        };

        let conclusion = NightlyConclusion::from_strs(
            run.status.as_deref(),
            run.conclusion.as_deref(),
        );

        let details = NightlyCiDetails {
            workflow_html_url: self.workflow_html_url(),
            run_id: Some(run.id),
            run_html_url: Some(run.html_url),
            run_started_at_unix: parse_iso8601_to_unix(run.run_started_at.as_deref()),
            run_conclusion: conclusion.clone(),
        };

        match conclusion {
            NightlyConclusion::Success => {
                ServiceStatus::healthy(self.name(), ServiceDetails::NightlyCi(details))
            },
            NightlyConclusion::Failure | NightlyConclusion::Cancelled | NightlyConclusion::TimedOut => {
                let msg = format!(
                    "last nightly run #{} concluded {}",
                    run.id, conclusion.as_str()
                );
                ServiceStatus::unhealthy(self.name(), msg, ServiceDetails::NightlyCi(details))
            },
            // In-flight, queued, or anything we don't recognise — we have a run, we just
            // don't have a verdict yet. The card shows "in progress / unknown" without
            // flipping the dot red.
            NightlyConclusion::InProgress | NightlyConclusion::Unknown => ServiceStatus {
                name: self.name().to_string(),
                status: crate::service_status::Status::Unknown,
                last_checked: current_unix_timestamp_secs(),
                error: None,
                details: ServiceDetails::NightlyCi(details),
            },
        }
    }
}

// DETAILS
// ================================================================================================

/// Card payload for the nightly CI service. One per monitored workflow.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NightlyCiDetails {
    /// Public URL of the workflow file on github.com (always populated, even before the
    /// first poll succeeds — useful for the card to link out before any data arrives).
    pub workflow_html_url: String,
    /// Most recent run id on the configured branch + event filter, if any.
    pub run_id: Option<u64>,
    /// Public URL of the most recent run (`actions/runs/{run_id}`).
    pub run_html_url: Option<String>,
    /// Unix timestamp the most recent run started, parsed from the API's ISO-8601 string.
    pub run_started_at_unix: Option<u64>,
    /// Run conclusion (or `Unknown` until populated / `InProgress` while running).
    pub run_conclusion: NightlyConclusion,
}

/// Discriminated outcome of the most recent run. Mirrors GitHub's `status` + `conclusion`
/// fields collapsed to a single value the card needs to render.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum NightlyConclusion {
    Success,
    Failure,
    Cancelled,
    TimedOut,
    InProgress,
    #[default]
    Unknown,
}

impl NightlyConclusion {
    /// Maps GitHub's `status` ∈ {`queued`, `in_progress`, `completed`, …} +
    /// `conclusion` ∈ {`success`, `failure`, `cancelled`, `timed_out`, `skipped`, …,
    /// `null`} to a single discriminant.
    pub fn from_strs(status: Option<&str>, conclusion: Option<&str>) -> Self {
        match (status, conclusion) {
            // status=completed → conclusion is the verdict
            (Some("completed"), Some("success")) => Self::Success,
            (Some("completed"), Some("failure")) => Self::Failure,
            (Some("completed"), Some("cancelled")) => Self::Cancelled,
            (Some("completed"), Some("timed_out")) => Self::TimedOut,
            // skipped / neutral / action_required / startup_failure → treat as Unknown
            // rather than Failure; "skipped" specifically means the run didn't actually
            // execute, so it's not a regression signal.
            (Some("completed"), _) => Self::Unknown,
            // status ∈ {queued, in_progress, pending, requested, waiting} → still cooking
            (Some(_), _) => Self::InProgress,
            (None, _) => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::InProgress => "in_progress",
            Self::Unknown => "unknown",
        }
    }
}

// GITHUB API SHAPES
// ================================================================================================

#[derive(Deserialize)]
struct GhRunsResponse {
    workflow_runs: Vec<GhRun>,
}

#[derive(Deserialize)]
struct GhRun {
    id: u64,
    /// `queued` | `in_progress` | `completed` | `pending` | `requested` | `waiting` | …
    status: Option<String>,
    /// `success` | `failure` | `cancelled` | `timed_out` | `skipped` | `neutral` |
    /// `action_required` | `startup_failure` | null while in_progress.
    conclusion: Option<String>,
    /// ISO-8601 string. Some runs report `run_started_at`; older endpoints only had
    /// `created_at`. We rely on `run_started_at` for accuracy; falls back to None.
    run_started_at: Option<String>,
    html_url: String,
}

// HELPERS
// ================================================================================================

/// Tiny ISO-8601 → unix-seconds parser scoped to GitHub's specific format
/// (`2026-05-04T04:00:12Z`). Pulling chrono just for this would be overkill; the format
/// is fixed, and we only need it for display/staleness math, not anything safety-critical.
fn parse_iso8601_to_unix(s: Option<&str>) -> Option<u64> {
    let s = s?;
    // Expected: YYYY-MM-DDTHH:MM:SSZ — exactly 20 chars.
    if s.len() != 20 || !s.ends_with('Z') {
        return None;
    }
    let bytes = s.as_bytes();
    let year: i64 = std::str::from_utf8(&bytes[0..4]).ok()?.parse().ok()?;
    let month: u32 = std::str::from_utf8(&bytes[5..7]).ok()?.parse().ok()?;
    let day: u32 = std::str::from_utf8(&bytes[8..10]).ok()?.parse().ok()?;
    let hour: u32 = std::str::from_utf8(&bytes[11..13]).ok()?.parse().ok()?;
    let minute: u32 = std::str::from_utf8(&bytes[14..16]).ok()?.parse().ok()?;
    let second: u32 = std::str::from_utf8(&bytes[17..19]).ok()?.parse().ok()?;

    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 60
    {
        return None;
    }

    // Days from 1970-01-01 to the start of `year`. Civil-from-days algorithm
    // by Howard Hinnant, but inverted: days-from-civil. Adapted to handle the
    // small year range we care about (≥ 1970).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64; // [0, 399]
    let m = u64::from(month);
    let d = u64::from(day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era * 146097 + doe as i64 - 719468;

    if days_since_epoch < 0 {
        return None;
    }
    let secs = (days_since_epoch as u64) * 86_400
        + u64::from(hour) * 3600
        + u64::from(minute) * 60
        + u64::from(second);
    Some(secs)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conclusion_from_strs_completed() {
        assert_eq!(
            NightlyConclusion::from_strs(Some("completed"), Some("success")),
            NightlyConclusion::Success
        );
        assert_eq!(
            NightlyConclusion::from_strs(Some("completed"), Some("failure")),
            NightlyConclusion::Failure
        );
        assert_eq!(
            NightlyConclusion::from_strs(Some("completed"), Some("cancelled")),
            NightlyConclusion::Cancelled
        );
        assert_eq!(
            NightlyConclusion::from_strs(Some("completed"), Some("timed_out")),
            NightlyConclusion::TimedOut
        );
        // skipped / neutral / action_required / startup_failure → Unknown, not Failure.
        assert_eq!(
            NightlyConclusion::from_strs(Some("completed"), Some("skipped")),
            NightlyConclusion::Unknown
        );
        assert_eq!(
            NightlyConclusion::from_strs(Some("completed"), Some("startup_failure")),
            NightlyConclusion::Unknown
        );
    }

    #[test]
    fn conclusion_from_strs_in_progress() {
        for status in ["queued", "in_progress", "pending", "requested", "waiting"] {
            assert_eq!(
                NightlyConclusion::from_strs(Some(status), None),
                NightlyConclusion::InProgress,
            );
        }
    }

    #[test]
    fn conclusion_from_strs_missing_status() {
        assert_eq!(
            NightlyConclusion::from_strs(None, None),
            NightlyConclusion::Unknown,
        );
    }

    #[test]
    fn iso8601_parse_known_value() {
        // 2026-05-04T04:00:12Z — exactly noon-equivalent unix calculation.
        // 2026-01-01T00:00:00Z = 1767225600
        // +123 days, 04:00:12 = 123*86400 + 4*3600 + 12 = 10627200 + 14412 = 10641612
        let epoch_2026 = parse_iso8601_to_unix(Some("2026-01-01T00:00:00Z")).unwrap();
        assert_eq!(epoch_2026, 1767225600);

        // Sanity-check the May value lands exactly where it should.
        let v = parse_iso8601_to_unix(Some("2026-05-04T04:00:12Z")).unwrap();
        // 2026 is not a leap year; jan(31) + feb(28) + mar(31) + apr(30) + 4 days = 124 days,
        // minus 1 because May 4 is the 124th day counting from Jan 1 inclusive but the
        // offset from Jan 1 00:00 is 123 full days.
        assert_eq!(v, epoch_2026 + 123 * 86_400 + 4 * 3600 + 12);
    }

    #[test]
    fn iso8601_parse_rejects_malformed() {
        assert!(parse_iso8601_to_unix(None).is_none());
        assert!(parse_iso8601_to_unix(Some("not-a-date")).is_none());
        assert!(parse_iso8601_to_unix(Some("2026-13-04T04:00:12Z")).is_none()); // bad month
        assert!(parse_iso8601_to_unix(Some("2026-05-04T25:00:12Z")).is_none()); // bad hour
        assert!(parse_iso8601_to_unix(Some("2026-05-04T04:00:12+0000")).is_none()); // no Z
    }
}
