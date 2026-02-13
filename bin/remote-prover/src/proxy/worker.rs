use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::Context;
use miden_node_utils::ErrorReport;
use miden_remote_prover::COMPONENT;
use miden_remote_prover::api::ProofType;
use miden_remote_prover::error::RemoteProverError;
use miden_remote_prover::generated::ProxyWorkerStatus;
use miden_remote_prover::generated::remote_prover::worker_status_api_client::WorkerStatusApiClient;
use pingora::lb::Backend;
use semver::{Version, VersionReq};
use serde::Serialize;
use tonic::transport::Channel;
use tracing::{error, info};

use super::metrics::WORKER_UNHEALTHY;

/// The maximum exponent for the backoff.
///
/// The maximum backoff is 2^[`MAX_BACKOFF_EXPONENT`] seconds.
const MAX_BACKOFF_EXPONENT: usize = 9;

/// The version of the proxy.
///
/// This is the version of the proxy that is used to check the version of the worker.
const MRP_PROXY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version requirement for the worker.
///
/// This is the version requirement for the worker that is used to check the version of the worker.
static WORKER_VERSION_REQUIREMENT: LazyLock<VersionReq> = LazyLock::new(|| {
    let current =
        Version::parse(MRP_PROXY_VERSION).expect("Proxy version should be valid at this point");
    VersionReq::parse(&format!("~{}.{}", current.major, current.minor))
        .expect("Version should be valid at this point")
});

// WORKER
// ================================================================================================

/// A worker used for processing of requests.
///
/// The worker is used to process requests.
/// It has a backend, a status client, a health status, and a version.
/// The backend is used to send requests to the worker.
/// The status client is used to check the status of the worker.
/// The health status is used to determine if the worker is healthy or unhealthy.
/// The version is used to check if the worker is compatible with the proxy.
/// The `is_available` is used to determine if the worker is available to process requests.
/// The `connection_timeout` is used to set the timeout for the connection to the worker.
/// The `total_timeout` is used to set the timeout for the total request.
#[derive(Debug, Clone)]
pub struct Worker {
    backend: Backend,
    status_client: Option<WorkerStatusApiClient<Channel>>,
    is_available: bool,
    health_status: WorkerHealthStatus,
    version: String,
    connection_timeout: Duration,
    total_timeout: Duration,
}

/// The health status of a worker.
///
/// A worker can be either healthy or unhealthy.
/// If the worker is unhealthy, it will have a number of failed attempts.
/// The number of failed attempts is incremented each time the worker is unhealthy.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum WorkerHealthStatus {
    /// The worker is healthy.
    Healthy,
    /// The worker is unhealthy.
    Unhealthy {
        /// The number of failed attempts.
        num_failed_attempts: usize,
        /// The timestamp of the first failure.
        #[serde(skip_serializing)]
        first_fail_timestamp: Instant,
        /// The reason for the failure.
        reason: String,
    },
    /// The worker status is unknown.
    Unknown,
}

impl Worker {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new worker and a gRPC status client for the given worker address.
    ///
    /// # Errors
    /// - Returns [`RemoteProverError::BackendCreationFailed`] if the worker address is invalid.
    pub async fn new(
        worker_addr: String,
        connection_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, RemoteProverError> {
        let backend =
            Backend::new(&worker_addr).map_err(RemoteProverError::BackendCreationFailed)?;

        let (status_client, health_status) =
            match create_status_client(&worker_addr, connection_timeout, total_timeout).await {
                Ok(client) => (Some(client), WorkerHealthStatus::Unknown),
                Err(err) => {
                    error!("Failed to create status client for worker {}: {}", worker_addr, err);
                    (
                        None,
                        WorkerHealthStatus::Unhealthy {
                            num_failed_attempts: 1,
                            first_fail_timestamp: Instant::now(),
                            reason: err.as_report_context("failed to create status client"),
                        },
                    )
                },
            };

        Ok(Self {
            backend,
            is_available: health_status == WorkerHealthStatus::Unknown,
            status_client,
            health_status,
            version: String::new(),
            connection_timeout,
            total_timeout,
        })
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Attempts to recreate the status client for this worker.
    ///
    /// This method will try to create a new gRPC status client using the worker's address
    /// and timeout configurations. If successful, it will update the worker's `status_client`
    /// field.
    ///
    /// # Returns
    /// - `Ok(())` if the client was successfully created
    /// - `Err(RemoteProverError)` if the client creation failed
    async fn recreate_status_client(&mut self) -> Result<(), RemoteProverError> {
        let name = self.name();
        match create_status_client(&name, self.connection_timeout, self.total_timeout).await {
            Ok(client) => {
                self.status_client = Some(client);
                Ok(())
            },
            Err(err) => {
                error!("Failed to recreate status client for worker {}: {}", name, err);
                Err(err)
            },
        }
    }

    /// Checks the current status of the worker and returns the result without updating worker
    /// state.
    ///
    /// Returns `Ok(())` if the worker is healthy and compatible, or `Err(reason)` if there's an
    /// issue. The caller should use `update_status` to apply the result to the worker's health
    /// status.
    #[tracing::instrument(target = COMPONENT, name = "worker.check_status")]
    pub async fn check_status(&mut self, supported_proof_type: ProofType) -> Result<(), String> {
        if !self.should_do_health_check() {
            return Ok(());
        }

        // If we don't have a status client, try to recreate it
        if self.status_client.is_none() {
            match self.recreate_status_client().await {
                Ok(()) => {
                    info!("Successfully recreated status client for worker {}", self.name());
                },
                Err(err) => {
                    return Err(err.as_report_context("failed to recreate status client"));
                },
            }
        }

        let worker_status = match self.status_client.as_mut().unwrap().status(()).await {
            Ok(response) => response.into_inner(),
            Err(e) => {
                error!("Failed to check worker status ({}): {}", self.name(), e);
                return Err(e.message().to_string());
            },
        };

        if worker_status.version.is_empty() {
            return Err("Worker version is empty".to_string());
        }

        if !is_valid_version(&WORKER_VERSION_REQUIREMENT, &worker_status.version).unwrap_or(false) {
            return Err(format!("Worker version is invalid ({})", worker_status.version));
        }

        self.version = worker_status.version;

        let worker_supported_proof_type = ProofType::try_from(worker_status.supported_proof_type)
            .inspect_err(|err| {
            error!(%err, name=%self.name(), "Failed to convert worker supported proof type");
        })?;

        if supported_proof_type != worker_supported_proof_type {
            return Err(format!("Unsupported proof type: {supported_proof_type}"));
        }

        Ok(())
    }

    /// Updates the worker's health status based on the result from `check_status`.
    ///
    /// If the result is `Ok(())`, the worker is marked as healthy.
    /// If the result is `Err(reason)`, the worker is marked as unhealthy with the failure reason.
    #[tracing::instrument(target = COMPONENT, name = "worker.update_status")]
    pub fn update_status(&mut self, check_result: Result<(), String>) {
        match check_result {
            Ok(()) => {
                self.set_health_status(WorkerHealthStatus::Healthy);
            },
            Err(reason) => {
                let failed_attempts = self.num_failures();
                self.set_health_status(WorkerHealthStatus::Unhealthy {
                    num_failed_attempts: failed_attempts + 1,
                    first_fail_timestamp: match &self.health_status {
                        WorkerHealthStatus::Unhealthy { first_fail_timestamp, .. } => {
                            *first_fail_timestamp
                        },
                        _ => Instant::now(),
                    },
                    reason,
                });
            },
        }
    }

    /// Sets the worker availability.
    pub fn set_availability(&mut self, is_available: bool) {
        self.is_available = is_available;
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of failures the worker has had.
    pub fn num_failures(&self) -> usize {
        match &self.health_status {
            WorkerHealthStatus::Healthy | WorkerHealthStatus::Unknown => 0,
            WorkerHealthStatus::Unhealthy {
                num_failed_attempts: failed_attempts,
                first_fail_timestamp: _,
                reason: _,
            } => *failed_attempts,
        }
    }

    /// Returns the health status of the worker.
    pub fn health_status(&self) -> &WorkerHealthStatus {
        &self.health_status
    }

    /// Returns the version of the worker.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the worker availability.
    ///
    /// A worker is available if it is healthy and ready to process requests.
    pub fn is_available(&self) -> bool {
        self.is_available
    }

    /// Returns the worker name.
    pub fn name(&self) -> String {
        self.backend.addr.to_string()
    }

    /// Returns whether the worker is healthy.
    ///
    /// This function will return `true` if the worker is healthy or the health status is unknown.
    /// Otherwise, it will return `false`.
    pub fn is_healthy(&self) -> bool {
        !matches!(self.health_status, WorkerHealthStatus::Unhealthy { .. })
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns whether the worker should do a health check.
    ///
    /// A worker should do a health check if it is healthy or if the time since the first failure
    /// is greater than the time since the first failure power of 2.
    ///
    /// The maximum exponent is [`MAX_BACKOFF_EXPONENT`], which corresponds to a backoff of
    /// 2^[`MAX_BACKOFF_EXPONENT`] seconds.
    fn should_do_health_check(&self) -> bool {
        match self.health_status {
            WorkerHealthStatus::Healthy | WorkerHealthStatus::Unknown => true,
            WorkerHealthStatus::Unhealthy {
                num_failed_attempts: failed_attempts,
                first_fail_timestamp,
                reason: _,
            } => {
                let time_since_first_failure = first_fail_timestamp.elapsed();
                time_since_first_failure
                    > Duration::from_secs(
                        2u64.pow(failed_attempts.min(MAX_BACKOFF_EXPONENT) as u32),
                    )
            },
        }
    }

    /// Sets the health status of the worker.
    ///
    /// This function will update the health status of the worker and update the worker availability
    /// based on the new health status.
    fn set_health_status(&mut self, health_status: WorkerHealthStatus) {
        let was_healthy = self.is_healthy();
        self.health_status = health_status;
        match &self.health_status {
            WorkerHealthStatus::Healthy | WorkerHealthStatus::Unknown => {
                if !was_healthy {
                    self.is_available = true;
                }
            },
            WorkerHealthStatus::Unhealthy { .. } => {
                WORKER_UNHEALTHY.with_label_values(&[&self.name()]).inc();
                self.is_available = false;
            },
        }
    }
}

// PARTIAL EQUALITY
// ================================================================================================

impl PartialEq for Worker {
    fn eq(&self, other: &Self) -> bool {
        self.backend == other.backend
    }
}

// CONVERSIONS
// ================================================================================================

/// Conversion from a Worker reference to a `WorkerStatus` proto message.
impl From<&Worker> for ProxyWorkerStatus {
    fn from(worker: &Worker) -> Self {
        use miden_remote_prover::generated::remote_prover::WorkerHealthStatus as ProtoWorkerHealthStatus;
        Self {
            name: worker.name(),
            version: worker.version().to_string(),
            status: match worker.health_status() {
                WorkerHealthStatus::Healthy => ProtoWorkerHealthStatus::Healthy,
                WorkerHealthStatus::Unhealthy { .. } => ProtoWorkerHealthStatus::Unhealthy,
                WorkerHealthStatus::Unknown => ProtoWorkerHealthStatus::Unknown,
            } as i32,
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Create a gRPC [`StatusApiClient`] for the given worker address.
///
/// # Errors
/// - [`RemoteProverError::InvalidURI`] if the worker address is invalid.
/// - [`RemoteProverError::ConnectionFailed`] if the connection to the worker fails.
async fn create_status_client(
    address: &str,
    connection_timeout: Duration,
    total_timeout: Duration,
) -> Result<WorkerStatusApiClient<Channel>, RemoteProverError> {
    let channel = Channel::from_shared(format!("http://{address}"))
        .map_err(|err| RemoteProverError::InvalidURI(err, address.to_string()))?
        .connect_timeout(connection_timeout)
        .timeout(total_timeout)
        .connect()
        .await
        .map_err(|err| RemoteProverError::ConnectionFailed(err, address.to_string()))?;

    Ok(WorkerStatusApiClient::new(channel))
}

/// Returns true if the version has major and minor versions match that of the required version.
/// Returns false otherwise.
///
/// # Errors
/// Returns an error if either of the versions is malformed.
fn is_valid_version(version_req: &VersionReq, version: &str) -> anyhow::Result<bool> {
    let received = Version::parse(version).context("Invalid worker version: {err}")?;

    Ok(version_req.matches(&received))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_version() {
        let version_req = VersionReq::parse("~1.0").unwrap();
        assert!(is_valid_version(&version_req, "1.0.0").unwrap());
        assert!(is_valid_version(&version_req, "1.0.1").unwrap());
        assert!(is_valid_version(&version_req, "1.0.12").unwrap());
        assert!(is_valid_version(&version_req, "1.0").is_err());
        assert!(!is_valid_version(&version_req, "2.0.0").unwrap());
        assert!(!is_valid_version(&version_req, "1.1.0").unwrap());
        assert!(!is_valid_version(&version_req, "0.9.0").unwrap());
        assert!(!is_valid_version(&version_req, "0.9.1").unwrap());
        assert!(!is_valid_version(&version_req, "0.10.0").unwrap());
        assert!(is_valid_version(&version_req, "miden").is_err());
        assert!(is_valid_version(&version_req, "1.miden.12").is_err());
    }
}
