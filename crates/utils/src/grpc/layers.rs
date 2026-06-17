use std::net::{IpAddr, SocketAddr};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, ensure};
use governor::middleware::StateInformationMiddleware;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::{Layer, Service};
use tower_governor::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{KeyExtractor, SmartIpKeyExtractor};

use crate::clap::GrpcOptionsExternal;

/// Builds a global concurrency limit layer using the configured semaphore.
pub fn rate_limit_concurrent_connections(
    grpc_options: GrpcOptionsExternal,
) -> GlobalConcurrencyLimitLayer {
    tower::limit::GlobalConcurrencyLimitLayer::new(grpc_options.max_concurrent_connections as usize)
}

/// Creates a per-IP rate limit layer using the configured governor settings.
pub fn rate_limit_per_ip(
    grpc_options: GrpcOptionsExternal,
) -> anyhow::Result<
    tower_governor::GovernorLayer<GrpcIpExtractor, StateInformationMiddleware, tonic::body::Body>,
> {
    let nanos_per_replenish = Duration::from_secs(1)
        .as_nanos()
        .checked_div(u128::from(grpc_options.replenish_n_per_second_per_ip.get()))
        .unwrap_or_default();
    ensure!(
        nanos_per_replenish > 0,
        "grpc.replenish_n_per_second must be less than or equal to 1e9"
    );
    let replenish_period = Duration::from_nanos(
        u64::try_from(nanos_per_replenish).context("invalid gRPC rate limit configuration")?,
    );
    let config = GovernorConfigBuilder::default()
        .key_extractor(GrpcIpExtractor::default())
        .period(replenish_period)
        .burst_size(grpc_options.burst_size.into())
        .use_headers()
        .finish()
        .context("invalid gRPC rate limit configuration")?;
    let limiter = std::sync::Arc::clone(config.limiter());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            // avoid a DoS vector
            limiter.retain_recent();
        }
    });
    Ok(tower_governor::GovernorLayer::new(config))
}

/// The originating client IP, resolved by [`ResolveClientIpLayer`] and stored in a request's
/// extensions.
///
/// gRPC handlers can read this via `request.extensions().get::<ClientIp>()` to obtain the
/// load-balancer-aware client address without re-implementing IP extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    /// Returns the client IP resolved for `request` by [`ResolveClientIpLayer`], or `None` if it
    /// could not be determined.
    pub fn from_request<T>(request: &tonic::Request<T>) -> Option<IpAddr> {
        request.extensions().get::<Self>().map(|ip| ip.0)
    }
}

/// A [`tower::Layer`] that resolves the originating client IP and stores it in the request's
/// extensions as [`ClientIp`].
///
/// IP resolution reuses [`GrpcIpExtractor`], so clients behind a load balancer or reverse proxy are
/// identified by their forwarded IP (via `X-Forwarded-For` / `X-Real-Ip` / `Forwarded` headers),
/// falling back to the peer address. Resolving once at the transport layer keeps this consistent
/// with the per-IP rate limiter and lets handlers read the result instead of re-deriving it.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolveClientIpLayer;

impl<S> Layer<S> for ResolveClientIpLayer {
    type Service = ResolveClientIp<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResolveClientIp { inner }
    }
}

/// The service produced by [`ResolveClientIpLayer`].
#[derive(Debug, Clone, Copy)]
pub struct ResolveClientIp<S> {
    inner: S,
}

impl<S, B> Service<http::Request<B>> for ResolveClientIp<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        if let Ok(ip) = GrpcIpExtractor::default().extract(&request) {
            request.extensions_mut().insert(ClientIp(ip));
        }
        self.inner.call(request)
    }
}

/// Wraps [`SmartIpKeyExtractor`] by providing a fallback to the client IP address provided by the
/// gRPC transport.
///
/// [`SmartIpKeyExtractor`]'s own fallback of checking the peer IP directly fails because we are in
/// a gRPC transport and not the typical `SocketAddr` as it expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcIpExtractor(SmartIpKeyExtractor);

impl Default for GrpcIpExtractor {
    fn default() -> Self {
        Self(SmartIpKeyExtractor)
    }
}

impl GrpcIpExtractor {
    #[expect(clippy::result_large_err, reason = "this is a third party error type")]
    fn extract_tonic_address<T>(
        request: &http::Request<T>,
    ) -> Result<<Self as KeyExtractor>::Key, GovernorError> {
        request
            .extensions()
            .get::<tonic::transport::server::TcpConnectInfo>()
            .and_then(tonic::transport::server::TcpConnectInfo::remote_addr)
            .as_ref()
            .map(SocketAddr::ip)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

impl KeyExtractor for GrpcIpExtractor {
    type Key = IpAddr;

    fn extract<T>(
        &self,
        request: &http::Request<T>,
    ) -> Result<Self::Key, tower_governor::GovernorError> {
        self.0.extract(request).or_else(|_| Self::extract_tonic_address(request))
    }
}
