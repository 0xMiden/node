//! Service trait shared by all network monitor checker tasks.
//!
//! Every service (RPC, explorer, faucet, provers, etc.) implements [`Service`]. The default
//! [`Service::run`] gives a standard interval-based check loop with shutdown detection.
//!
//! The [`Tasks::spawn_service`](crate::monitor::tasks::Tasks::spawn_service) helper takes any
//! service, seeds its `watch::channel` with [`Service::initial_status`], spawns the task, and
//! returns the receiver.

use std::time::Duration;

use miden_node_proto::clients::{Builder as ClientBuilder, GrpcClient};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::debug;
use url::Url;

use crate::LOG_TARGET;
use crate::service_status::ServiceStatus;

/// Build a lazily-connected gRPC client using the network monitor's standard settings (TLS enabled,
/// no metadata, no OTEL propagation).
pub fn build_tls_client<C: GrpcClient>(url: Url, timeout: Duration) -> C {
    ClientBuilder::new(url)
        .with_tls()
        .expect("TLS is enabled")
        .with_timeout(timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<C>()
}

/// A monitor checker that periodically produces [`ServiceStatus`] updates.
pub trait Service: Send + 'static {
    /// Human-readable service name.
    fn name(&self) -> &str;

    /// Interval between [`Self::check`] invocations.
    fn interval(&self) -> Duration;

    /// Value used to seed the `watch::channel` at spawn time.
    fn initial_status(&self) -> ServiceStatus;

    /// Runs a single check iteration.
    fn check(&mut self) -> impl std::future::Future<Output = ServiceStatus> + Send;

    /// Full service lifecycle. The default implementation loops on [`Self::interval`] ticks, calls
    /// [`Self::check`], and publishes the result. Returns when the channel has no receivers (clean
    /// shutdown). Services with custom scheduling override this.
    fn run(
        mut self,
        tx: watch::Sender<ServiceStatus>,
    ) -> impl std::future::Future<Output = ()> + Send
    where
        Self: Sized,
    {
        async move {
            let mut interval = tokio::time::interval(self.interval());
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let status = self.check().await;
                if tx.send(status).is_err() {
                    debug!(target: LOG_TARGET, "No receivers for {}, shutting down", self.name());
                    return;
                }
            }
        }
    }
}
